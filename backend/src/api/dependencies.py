"""
Arc API Dependencies

FastAPI dependency injection functions for authentication,
database connections, and common utilities.
"""

from typing import Annotated

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt

from core.config import get_settings
from core.exceptions import (
    AuthenticationError,
    InvalidTokenError,
    ResourceNotFoundError,
    TokenExpiredError,
)
from core.logging import get_logger, set_user_context


logger = get_logger(__name__)
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
    x_api_key: Annotated[str | None, Header()] = None,
) -> dict:
    """
    Extract and validate the current user from JWT token or API key.
    
    Supports two authentication methods:
    1. Bearer token (JWT)
    2. X-API-Key header (for service-to-service communication)
    
    Args:
        credentials: HTTP Bearer credentials
        x_api_key: API key header
    
    Returns:
        User information dictionary
    
    Raises:
        AuthenticationError: If authentication fails
    """
    settings = get_settings()
    
    # Try Bearer token first
    if credentials:
        return await _validate_jwt_token(credentials.credentials, settings)
    
    # Try API key
    if x_api_key:
        return await _validate_api_key(x_api_key)
    
    # No authentication provided
    raise AuthenticationError("Authentication required")


async def get_optional_user(
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(security)],
) -> dict | None:
    """
    Optionally extract user from JWT token.
    
    Returns None if no token provided (for public endpoints).
    """
    if not credentials:
        return None
    
    settings = get_settings()
    
    try:
        return await _validate_jwt_token(credentials.credentials, settings)
    except AuthenticationError:
        return None


async def _validate_jwt_token(token: str, settings: any) -> dict:
    """Validate JWT token and extract user information."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET_KEY,
            algorithms=[settings.JWT_ALGORITHM],
        )
        
        user_id = payload.get("sub")
        if not user_id:
            raise InvalidTokenError()
        
        # Set user context for logging
        set_user_context(user_id, payload.get("project_id"))
        
        return {
            "user_id": user_id,
            "email": payload.get("email"),
            "roles": payload.get("roles", []),
            "project_id": payload.get("project_id"),
        }
    
    except jwt.ExpiredSignatureError as e:
        logger.warning("JWT token expired")
        raise TokenExpiredError() from e
    
    except JWTError as e:
        logger.warning("Invalid JWT token", error=str(e))
        raise InvalidTokenError() from e


async def _validate_api_key(api_key: str) -> dict:
    """
    Validate API key.
    
    Note: In production, this should validate against a database
    or secure key store.
    """
    # TODO: Implement API key validation against database
    # For now, reject all API keys until properly implemented
    raise AuthenticationError("API key authentication not yet implemented")


def require_roles(*roles: str):
    """
    Dependency factory that requires specific roles.
    
    Usage:
        @router.get("/admin", dependencies=[Depends(require_roles("admin"))])
        async def admin_endpoint(): ...
    """
    async def role_checker(
        current_user: Annotated[dict, Depends(get_current_user)],
    ) -> dict:
        user_roles = set(current_user.get("roles", []))
        required_roles = set(roles)
        
        if not required_roles.intersection(user_roles):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions",
            )
        
        return current_user
    
    return role_checker


class ProjectAccess:
    """
    Dependency that validates project access.
    
    Usage:
        @router.get("/projects/{project_id}/targets")
        async def get_targets(
            project: Annotated[dict, Depends(ProjectAccess())],
        ): ...
    """
    
    def __init__(self, require_write: bool = False):
        self.require_write = require_write
    
    async def __call__(
        self,
        project_id: str,
        current_user: Annotated[dict, Depends(get_current_user)],
    ) -> dict:
        """Validate user has access to the project."""
        from graph.client import get_neo4j_client
        from graph.utils import node_to_dict
        
        client = get_neo4j_client()
        
        query = """
        MATCH (p:Project {project_id: $project_id})
        WHERE p.owner_id = $user_id
        RETURN p
        """
        
        result = await client.execute_read(
            query,
            {"project_id": project_id, "user_id": current_user["user_id"]},
        )
        
        if not result:
            raise ResourceNotFoundError(
                "Project",
                project_id,
                details={"message": "Project not found or access denied"},
            )
        
        project = node_to_dict(result[0].get("p"))
        if not project:
            raise ResourceNotFoundError(
                "Project",
                project_id,
                details={"message": "Project not found or access denied"},
            )
        
        # Check write access if required
        if self.require_write and project.get("status") == "archived":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Cannot modify archived project",
            )
        
        # Set project context for logging
        set_user_context(current_user["user_id"], project_id)
        
        return {
            "project_id": project_id,
            "name": project["name"],
            "status": project["status"],
            "scope": project.get("scope", []),
            "out_of_scope": project.get("out_of_scope", []),
            "user": current_user,
        }
