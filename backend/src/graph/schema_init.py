"""
Neo4j Schema Initialization

Applies the graph schema on application startup.
"""

import os
from pathlib import Path

from core.logging import get_logger
from graph.client import Neo4jClient


logger = get_logger(__name__)

# Path to schema files (applied in order)
SCHEMA_DIR = Path(__file__).parent / "schema"
SCHEMA_FILES = [
    SCHEMA_DIR / "core_schema.cypher",
    SCHEMA_DIR / "mitre_schema.cypher",
    SCHEMA_DIR / "identity_schema.cypher",
    SCHEMA_DIR / "attack_graph_schema.cypher",
    SCHEMA_DIR / "indexes.cypher",
]


def parse_cypher_statements(content: str) -> list[str]:
    """
    Parse Cypher file into individual statements.
    
    Handles:
    - Single-line comments (//)
    - Multi-statement files separated by semicolons
    - Empty lines
    
    Args:
        content: Raw Cypher file content
    
    Returns:
        List of individual Cypher statements
    """
    statements = []
    current_statement = []
    
    for line in content.split("\n"):
        # Skip empty lines and comments
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        
        current_statement.append(line)
        
        # Statement ends with semicolon
        if stripped.endswith(";"):
            statement = "\n".join(current_statement).strip()
            # Remove trailing semicolon for Neo4j driver
            statement = statement.rstrip(";").strip()
            if statement:
                statements.append(statement)
            current_statement = []
    
    # Handle statement without trailing semicolon
    if current_statement:
        statement = "\n".join(current_statement).strip()
        if statement:
            statements.append(statement)
    
    return statements


async def init_schema(client: Neo4jClient) -> None:
    """
    Initialize the Neo4j schema from the schema file.
    
    This function is idempotent - it can be run multiple times
    without causing errors (uses IF NOT EXISTS).
    
    Args:
        client: Connected Neo4jClient instance
    """
    # Collect all statements from all schema files
    all_statements: list[str] = []
    for schema_file in SCHEMA_FILES:
        if not schema_file.exists():
            logger.warning("Schema file not found, skipping", path=str(schema_file))
            continue
        content = schema_file.read_text(encoding="utf-8")
        stmts = parse_cypher_statements(content)
        all_statements.extend(stmts)
        logger.info("Loaded schema file", path=schema_file.name, statements=len(stmts))

    if not all_statements:
        logger.warning("No schema statements found in any schema file")
        return

    logger.info("Initializing Neo4j schema", total_files=len(SCHEMA_FILES))

    try:
        statements = all_statements
        
        logger.info(
            "Parsed schema statements",
            statement_count=len(statements),
        )
        
        # Execute each statement
        success_count = 0
        error_count = 0
        
        for i, statement in enumerate(statements, 1):
            try:
                # Extract statement type for logging
                statement_type = statement.split()[0:3]
                statement_preview = " ".join(statement_type)
                
                await client.execute_write(statement)
                success_count += 1
                
                logger.debug(
                    "Schema statement executed",
                    index=i,
                    statement=statement_preview,
                )
                
            except Exception as e:
                error_count += 1
                # Log but continue - some errors are expected
                # (e.g., constraint already exists in older Neo4j)
                logger.warning(
                    "Schema statement failed (may be expected)",
                    index=i,
                    error=str(e)[:200],
                )
        
        logger.info(
            "Schema initialization complete",
            success=success_count,
            errors=error_count,
            total=len(statements),
        )
        
    except Exception as e:
        logger.error(
            "Failed to initialize schema",
            error=str(e),
        )
        raise


async def verify_schema(client: Neo4jClient) -> dict:
    """
    Verify that the schema is properly initialized.
    
    Returns:
        Dictionary with schema verification results
    """
    try:
        # Check constraints
        constraints_result = await client.execute_read(
            "SHOW CONSTRAINTS YIELD name RETURN count(*) as count"
        )
        constraint_count = constraints_result[0]["count"] if constraints_result else 0
        
        # Check indexes
        indexes_result = await client.execute_read(
            "SHOW INDEXES YIELD name RETURN count(*) as count"
        )
        index_count = indexes_result[0]["count"] if indexes_result else 0
        
        return {
            "constraints": constraint_count,
            "indexes": index_count,
            "healthy": constraint_count > 0 and index_count > 0,
        }
        
    except Exception as e:
        logger.error("Schema verification failed", error=str(e))
        return {
            "constraints": 0,
            "indexes": 0,
            "healthy": False,
            "error": str(e),
        }
