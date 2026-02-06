"""
Arc Neo4j Client

Async Neo4j client with connection pooling and transaction management.
"""

from contextlib import asynccontextmanager
from functools import lru_cache
from typing import Any, AsyncIterator

from neo4j import AsyncDriver, AsyncGraphDatabase, AsyncSession
from neo4j.exceptions import (
    AuthError,
    ServiceUnavailable,
    SessionExpired,
)
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from core.config import get_settings
from core.exceptions import (
    Neo4jConnectionError,
    Neo4jQueryError,
)
from core.logging import get_logger


logger = get_logger(__name__)


class Neo4jClient:
    """
    Async Neo4j client with connection pooling and automatic retries.
    
    Provides a high-level interface for executing Cypher queries with
    proper transaction management and error handling.
    
    Example:
        async with Neo4jClient() as client:
            result = await client.execute_read(
                "MATCH (d:Domain {name: $name}) RETURN d",
                {"name": "example.com"}
            )
    """
    
    def __init__(
        self,
        uri: str | None = None,
        user: str | None = None,
        password: str | None = None,
        database: str | None = None,
        max_connection_pool_size: int | None = None,
    ) -> None:
        """
        Initialize Neo4j client.
        
        Args:
            uri: Neo4j connection URI (defaults to settings)
            user: Neo4j username (defaults to settings)
            password: Neo4j password (defaults to settings)
            database: Neo4j database name (defaults to settings)
            max_connection_pool_size: Maximum connection pool size
        """
        settings = get_settings()
        
        self._uri = uri or settings.NEO4J_URI
        self._user = user or settings.NEO4J_USER
        self._password = password or settings.NEO4J_PASSWORD
        self._database = database or settings.NEO4J_DATABASE
        self._max_pool_size = max_connection_pool_size or settings.NEO4J_MAX_CONNECTION_POOL_SIZE
        
        self._driver: AsyncDriver | None = None
    
    async def connect(self) -> None:
        """
        Establish connection to Neo4j.
        
        Raises:
            Neo4jConnectionError: If connection fails
        """
        if self._driver is not None:
            return
        
        try:
            self._driver = AsyncGraphDatabase.driver(
                self._uri,
                auth=(self._user, self._password),
                max_connection_pool_size=self._max_pool_size,
            )
            
            # Verify connection
            await self._driver.verify_connectivity()
            
            logger.info(
                "Connected to Neo4j",
                uri=self._uri,
                database=self._database,
            )
        
        except AuthError as e:
            logger.error("Neo4j authentication failed", error=str(e))
            raise Neo4jConnectionError(
                message="Neo4j authentication failed",
                details={"uri": self._uri},
            ) from e
        
        except ServiceUnavailable as e:
            logger.error("Neo4j service unavailable", error=str(e))
            raise Neo4jConnectionError(
                message="Neo4j service unavailable",
                details={"uri": self._uri},
            ) from e
        
        except Exception as e:
            logger.error("Failed to connect to Neo4j", error=str(e))
            raise Neo4jConnectionError(
                message=f"Failed to connect to Neo4j: {e}",
                details={"uri": self._uri},
            ) from e
    
    async def close(self) -> None:
        """Close the Neo4j connection."""
        if self._driver is not None:
            await self._driver.close()
            self._driver = None
            logger.info("Neo4j connection closed")
    
    async def __aenter__(self) -> "Neo4jClient":
        await self.connect()
        return self
    
    async def __aexit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        await self.close()
    
    @asynccontextmanager
    async def session(self) -> AsyncIterator[AsyncSession]:
        """
        Get a Neo4j session.
        
        Yields:
            AsyncSession: Neo4j session for executing queries
        
        Raises:
            Neo4jConnectionError: If not connected
        """
        if self._driver is None:
            raise Neo4jConnectionError(message="Not connected to Neo4j")
        
        session = self._driver.session(database=self._database)
        try:
            yield session
        finally:
            await session.close()
    
    @retry(
        retry=retry_if_exception_type((SessionExpired, ServiceUnavailable)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def execute_read(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a read-only Cypher query.
        
        Args:
            query: Cypher query string
            parameters: Query parameters
        
        Returns:
            List of result records as dictionaries
        
        Raises:
            Neo4jQueryError: If query execution fails
        """
        parameters = parameters or {}
        
        try:
            async with self.session() as session:
                result = await session.run(query, parameters)
                records = await result.data()
                
                logger.debug(
                    "Executed read query",
                    query=query[:100],
                    record_count=len(records),
                )
                
                return records
        
        except Exception as e:
            logger.error(
                "Read query failed",
                query=query[:200],
                error=str(e),
            )
            raise Neo4jQueryError(
                message=f"Read query failed: {e}",
                query=query,
            ) from e
    
    @retry(
        retry=retry_if_exception_type((SessionExpired, ServiceUnavailable)),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=1, max=10),
    )
    async def execute_write(
        self,
        query: str,
        parameters: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """
        Execute a write Cypher query.
        
        Args:
            query: Cypher query string
            parameters: Query parameters
        
        Returns:
            List of result records as dictionaries
        
        Raises:
            Neo4jQueryError: If query execution fails
        """
        parameters = parameters or {}
        
        try:
            async with self.session() as session:
                result = await session.run(query, parameters)
                records = await result.data()
                summary = await result.consume()
                
                logger.debug(
                    "Executed write query",
                    query=query[:100],
                    nodes_created=summary.counters.nodes_created,
                    relationships_created=summary.counters.relationships_created,
                )
                
                return records
        
        except Exception as e:
            logger.error(
                "Write query failed",
                query=query[:200],
                error=str(e),
            )
            raise Neo4jQueryError(
                message=f"Write query failed: {e}",
                query=query,
            ) from e
    
    async def execute_many(
        self,
        queries: list[tuple[str, dict[str, Any] | None]],
    ) -> list[list[dict[str, Any]]]:
        """
        Execute multiple queries in a single transaction.
        
        Args:
            queries: List of (query, parameters) tuples
        
        Returns:
            List of results for each query
        
        Raises:
            Neo4jQueryError: If any query fails (transaction rolled back)
        """
        results: list[list[dict[str, Any]]] = []
        
        try:
            async with self.session() as session:
                async with await session.begin_transaction() as tx:
                    for query, params in queries:
                        result = await tx.run(query, params or {})
                        records = await result.data()
                        results.append(records)
                    
                    await tx.commit()
            
            logger.debug(
                "Executed batch queries",
                query_count=len(queries),
            )
            
            return results
        
        except Exception as e:
            logger.error(
                "Batch query failed",
                query_count=len(queries),
                error=str(e),
            )
            raise Neo4jQueryError(
                message=f"Batch query failed: {e}",
            ) from e
    
    async def health_check(self) -> bool:
        """
        Check if Neo4j is healthy and responsive.
        
        Returns:
            True if healthy, False otherwise
        """
        try:
            if self._driver is None:
                return False
            
            await self._driver.verify_connectivity()
            return True
        
        except Exception:
            return False
    
    async def get_node_count(self, label: str, project_id: str | None = None) -> int:
        """
        Get count of nodes with a specific label.
        
        Args:
            label: Node label
            project_id: Optional project ID for filtering
        
        Returns:
            Node count
        """
        if project_id:
            query = f"MATCH (n:{label} {{project_id: $project_id}}) RETURN count(n) as count"
            params = {"project_id": project_id}
        else:
            query = f"MATCH (n:{label}) RETURN count(n) as count"
            params = {}
        
        result = await self.execute_read(query, params)
        return result[0]["count"] if result else 0


# Global client instance
_neo4j_client: Neo4jClient | None = None


@lru_cache
def get_neo4j_client() -> Neo4jClient:
    """
    Get the global Neo4j client instance.
    
    Returns:
        Neo4jClient: Singleton Neo4j client
    
    Note:
        Call `await client.connect()` before using.
    """
    global _neo4j_client
    if _neo4j_client is None:
        _neo4j_client = Neo4jClient()
    return _neo4j_client


async def init_neo4j() -> Neo4jClient:
    """
    Initialize and connect to Neo4j.
    
    Returns:
        Connected Neo4jClient instance
    """
    client = get_neo4j_client()
    await client.connect()
    return client


async def close_neo4j() -> None:
    """Close the global Neo4j client."""
    global _neo4j_client
    if _neo4j_client is not None:
        await _neo4j_client.close()
        _neo4j_client = None
