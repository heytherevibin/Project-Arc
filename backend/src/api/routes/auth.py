"""
Authentication Endpoints

JWT-based authentication with registration, login, and token refresh.
"""

from datetime import datetime, timedelta, timezone
from typing import Annotated
from uuid import uuid4

import bcrypt
from fastapi import APIRouter, Depends, status
from jose import jwt
from pydantic import BaseModel, EmailStr, Field

from core.config import get_settings
from core.exceptions import (
    AuthenticationError,
    InvalidCredentialsError,
    ResourceConflictError,
    ValidationError,
)
from api.dependencies import get_current_user
from core.logging import get_logger
from graph.client import get_neo4j_client
from graph.utils import node_to_dict


router = APIRouter()
logger = get_logger(__name__)


# =============================================================================
# Request/Response Models
# =============================================================================

class UserRegister(BaseModel):
    """Registration request."""
    
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=72, description="Bcrypt limit 72 bytes")
    name: str = Field(..., min_length=1, max_length=100)


class UserLogin(BaseModel):
    """Login request."""
    
    email: EmailStr
    password: str


class TokenRefresh(BaseModel):
    """Token refresh request."""
    
    refresh_token: str


class ChangePasswordRequest(BaseModel):
    """Change password request."""
    
    current_password: str
    new_password: str = Field(..., min_length=8, max_length=72)


class UserResponse(BaseModel):
    """User information response."""
    
    user_id: str
    email: str
    name: str
    roles: list[str]
    created_at: str


class TokenResponse(BaseModel):
    """Authentication token response."""
    
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int
    user: UserResponse


class MessageResponse(BaseModel):
    """Simple message response."""
    
    message: str


# =============================================================================
# Helper Functions
# =============================================================================

# Bcrypt limit (bcrypt rejects input > 72 bytes)
BCRYPT_MAX_PASSWORD_BYTES = 72


def _password_bytes(password: str) -> bytes:
    """Encode password to bytes, truncate to 72 bytes (UTF-8 safe)."""
    encoded = password.encode("utf-8")
    if len(encoded) <= BCRYPT_MAX_PASSWORD_BYTES:
        return encoded
    encoded = encoded[:BCRYPT_MAX_PASSWORD_BYTES]
    while len(encoded) > 0 and (encoded[-1] & 0x80) and not (encoded[-1] & 0x40):
        encoded = encoded[:-1]
    return encoded


def hash_password(password: str) -> str:
    """Hash a password using bcrypt (no passlib; avoids 72-byte init bug)."""
    pw_bytes = _password_bytes(password)
    return bcrypt.hashpw(pw_bytes, bcrypt.gensalt()).decode("ascii")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash."""
    try:
        return bcrypt.checkpw(
            _password_bytes(plain_password),
            hashed_password.encode("ascii"),
        )
    except Exception:
        return False


def create_access_token(user_id: str, email: str, roles: list[str]) -> tuple[str, int]:
    """
    Create a JWT access token.
    
    Returns:
        Tuple of (token, expires_in_seconds)
    """
    settings = get_settings()
    expire_minutes = settings.JWT_ACCESS_TOKEN_EXPIRE_MINUTES
    expires_at = datetime.now(timezone.utc) + timedelta(minutes=expire_minutes)
    
    payload = {
        "sub": user_id,
        "email": email,
        "roles": roles,
        "type": "access",
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
    }
    
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, expire_minutes * 60


def create_refresh_token(user_id: str) -> str:
    """Create a JWT refresh token."""
    settings = get_settings()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.JWT_REFRESH_TOKEN_EXPIRE_DAYS)
    
    payload = {
        "sub": user_id,
        "type": "refresh",
        "exp": expires_at,
        "iat": datetime.now(timezone.utc),
        "jti": str(uuid4()),  # Unique token ID for revocation
    }
    
    return jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


# =============================================================================
# Endpoints
# =============================================================================

@router.post(
    "/register",
    response_model=TokenResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register User",
)
async def register(data: UserRegister) -> TokenResponse:
    """
    Register a new user account.
    
    Creates a new user with hashed password and returns authentication tokens.
    """
    client = get_neo4j_client()
    
    # Check if email already exists
    existing = await client.execute_read(
        "MATCH (u:User {email: $email}) RETURN u",
        {"email": data.email.lower()},
    )
    
    if existing:
        raise ResourceConflictError(
            message="Email already registered",
            resource_type="User",
        )
    
    # Create user
    user_id = str(uuid4())
    now = datetime.now(timezone.utc).isoformat()
    hashed_pw = hash_password(data.password)
    
    await client.execute_write(
        """
        CREATE (u:User {
            user_id: $user_id,
            email: $email,
            name: $name,
            password_hash: $password_hash,
            roles: ['user'],
            created_at: $created_at,
            updated_at: null,
            is_active: true
        })
        """,
        {
            "user_id": user_id,
            "email": data.email.lower(),
            "name": data.name,
            "password_hash": hashed_pw,
            "created_at": now,
        },
    )
    
    logger.info("User registered", user_id=user_id, email=data.email)
    
    # Generate tokens
    access_token, expires_in = create_access_token(user_id, data.email, ["user"])
    refresh_token = create_refresh_token(user_id)
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        user=UserResponse(
            user_id=user_id,
            email=data.email.lower(),
            name=data.name,
            roles=["user"],
            created_at=now,
        ),
    )


@router.post(
    "/login",
    response_model=TokenResponse,
    summary="Login",
)
async def login(data: UserLogin) -> TokenResponse:
    """
    Authenticate user and return tokens.
    """
    client = get_neo4j_client()
    
    # Find user
    result = await client.execute_read(
        """
        MATCH (u:User {email: $email, is_active: true})
        RETURN u
        """,
        {"email": data.email.lower()},
    )
    
    if not result:
        logger.warning("Login failed - user not found", email=data.email)
        raise InvalidCredentialsError()
    
    user = node_to_dict(result[0].get("u"))
    if not user:
        raise InvalidCredentialsError()
    
    # Verify password
    if not verify_password(data.password, user["password_hash"]):
        logger.warning("Login failed - invalid password", email=data.email)
        raise InvalidCredentialsError()
    
    # Update last login
    await client.execute_write(
        """
        MATCH (u:User {user_id: $user_id})
        SET u.last_login_at = $now
        """,
        {"user_id": user["user_id"], "now": datetime.now(timezone.utc).isoformat()},
    )
    
    logger.info("User logged in", user_id=user["user_id"])
    
    # Generate tokens
    access_token, expires_in = create_access_token(
        user["user_id"],
        user["email"],
        user["roles"],
    )
    refresh_token = create_refresh_token(user["user_id"])
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in=expires_in,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            roles=user["roles"],
            created_at=user["created_at"],
        ),
    )


@router.post(
    "/refresh",
    response_model=TokenResponse,
    summary="Refresh Token",
)
async def refresh_token(data: TokenRefresh) -> TokenResponse:
    """
    Refresh an access token using a refresh token.
    """
    settings = get_settings()
    client = get_neo4j_client()
    
    try:
        payload = jwt.decode(
            data.refresh_token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        
        if payload.get("type") != "refresh":
            raise AuthenticationError("Invalid token type")
        
        user_id = payload.get("sub")
        if not user_id:
            raise AuthenticationError("Invalid token")
        
    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Refresh token expired")
    except jwt.JWTError:
        raise AuthenticationError("Invalid refresh token")
    
    # Get user
    result = await client.execute_read(
        "MATCH (u:User {user_id: $user_id, is_active: true}) RETURN u",
        {"user_id": user_id},
    )
    
    if not result:
        raise AuthenticationError("User not found")
    
    user = node_to_dict(result[0].get("u"))
    if not user:
        raise AuthenticationError("User not found")
    
    # Generate new tokens
    access_token, expires_in = create_access_token(
        user["user_id"],
        user["email"],
        user["roles"],
    )
    new_refresh_token = create_refresh_token(user["user_id"])
    
    return TokenResponse(
        access_token=access_token,
        refresh_token=new_refresh_token,
        expires_in=expires_in,
        user=UserResponse(
            user_id=user["user_id"],
            email=user["email"],
            name=user["name"],
            roles=user["roles"],
            created_at=user["created_at"],
        ),
    )


@router.post(
    "/change-password",
    response_model=MessageResponse,
    summary="Change Password",
)
async def change_password(
    data: ChangePasswordRequest,
    current_user: Annotated[dict, Depends(get_current_user)],
) -> MessageResponse:
    """
    Change the current user's password.
    Requires current password and new password.
    """
    client = get_neo4j_client()
    result = await client.execute_read(
        "MATCH (u:User {user_id: $user_id, is_active: true}) RETURN u",
        {"user_id": current_user["user_id"]},
    )
    if not result:
        raise InvalidCredentialsError()

    user = node_to_dict(result[0].get("u"))
    if not user:
        raise InvalidCredentialsError()
    password_hash = user.get("password_hash") or ""
    if not verify_password(data.current_password, password_hash):
        raise InvalidCredentialsError()

    new_hash = hash_password(data.new_password)
    now = datetime.now(timezone.utc).isoformat()
    await client.execute_write(
        """
        MATCH (u:User {user_id: $user_id})
        SET u.password_hash = $password_hash, u.updated_at = $updated_at
        """,
        {
            "user_id": current_user["user_id"],
            "password_hash": new_hash,
            "updated_at": now,
        },
    )
    logger.info("Password changed", user_id=current_user["user_id"])
    return MessageResponse(message="Password changed successfully")


@router.post(
    "/logout",
    response_model=MessageResponse,
    summary="Logout",
)
async def logout() -> MessageResponse:
    """
    Logout user (client should discard tokens).
    
    Note: For full security, implement token blacklisting with Redis.
    """
    return MessageResponse(message="Logged out successfully")
