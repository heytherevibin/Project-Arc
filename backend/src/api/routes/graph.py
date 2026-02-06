"""
Graph Visualization Endpoints

Provide graph data for attack surface visualization.
"""

from typing import Annotated

from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, Field

from api.dependencies import ProjectAccess
from graph.client import get_neo4j_client


router = APIRouter()


# =============================================================================
# Response Models
# =============================================================================

class GraphNode(BaseModel):
    """Node in the attack surface graph."""
    
    id: str
    label: str
    type: str
    properties: dict = Field(default_factory=dict)
    severity: str | None = None
    group: str | None = None


class GraphEdge(BaseModel):
    """Edge in the attack surface graph."""
    
    source: str
    target: str
    type: str
    properties: dict = Field(default_factory=dict)


class GraphResponse(BaseModel):
    """Complete graph response."""
    
    nodes: list[GraphNode]
    edges: list[GraphEdge]
    node_count: int
    edge_count: int


class GraphStats(BaseModel):
    """Graph statistics."""
    
    total_nodes: int
    total_edges: int
    node_types: dict[str, int]
    edge_types: dict[str, int]


# =============================================================================
# Endpoints
# =============================================================================

@router.get(
    "/data",
    response_model=GraphResponse,
    summary="Get Graph Data",
    description="Get the attack surface graph data for visualization.",
)
async def get_graph_data(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    limit: int = Query(500, ge=1, le=2000, description="Max nodes to return"),
    node_types: str | None = Query(None, description="Comma-separated node types to include"),
) -> GraphResponse:
    """
    Get graph data for attack surface visualization.
    
    Returns nodes and edges for the project's attack surface graph.
    """
    client = get_neo4j_client()
    
    # Build node type filter
    type_filter = ""
    if node_types:
        types = [t.strip() for t in node_types.split(",")]
        type_filter = f"WHERE any(label IN labels(n) WHERE label IN {types})"
    
    # Fetch nodes
    nodes_query = f"""
    MATCH (n)
    WHERE n.project_id = $project_id
    {type_filter}
    WITH n, labels(n) as node_labels
    RETURN 
        elementId(n) as id,
        node_labels[0] as type,
        properties(n) as props
    LIMIT $limit
    """
    
    nodes_result = await client.execute_read(
        nodes_query,
        {"project_id": project_id, "limit": limit},
    )
    
    # Process nodes
    nodes: list[GraphNode] = []
    node_ids = set()
    
    for r in nodes_result:
        node_id = r["id"]
        node_ids.add(node_id)
        
        node_type = r["type"]
        props = r["props"]
        
        # Determine label based on node type
        if node_type == "Domain":
            label = props.get("name", "Unknown Domain")
        elif node_type == "Subdomain":
            label = props.get("name", "Unknown Subdomain")
        elif node_type == "IP":
            label = props.get("address", "Unknown IP")
        elif node_type == "Port":
            label = f":{props.get('number', '?')}"
        elif node_type == "URL":
            label = props.get("url", "Unknown URL")[:50]
        elif node_type == "Service":
            label = props.get("name", "Unknown Service")
        elif node_type == "Technology":
            label = props.get("name", "Unknown Tech")
        elif node_type == "Vulnerability":
            label = props.get("name", props.get("template_id", "Unknown Vuln"))[:40]
        else:
            label = str(props.get("name", node_type))
        
        # Determine group for visualization
        group_map = {
            "Domain": "domain",
            "Subdomain": "subdomain",
            "IP": "network",
            "Port": "network",
            "Service": "service",
            "URL": "web",
            "Endpoint": "web",
            "Technology": "tech",
            "Vulnerability": "vuln",
            "CVE": "vuln",
        }
        
        nodes.append(GraphNode(
            id=node_id,
            label=label,
            type=node_type,
            properties=props,
            severity=props.get("severity"),
            group=group_map.get(node_type, "other"),
        ))
    
    # Fetch edges (only between nodes we have)
    if node_ids:
        edges_query = """
        MATCH (a)-[r]->(b)
        WHERE a.project_id = $project_id
        AND elementId(a) IN $node_ids
        AND elementId(b) IN $node_ids
        RETURN 
            elementId(a) as source,
            elementId(b) as target,
            type(r) as rel_type,
            properties(r) as props
        """
        
        edges_result = await client.execute_read(
            edges_query,
            {"project_id": project_id, "node_ids": list(node_ids)},
        )
        
        edges: list[GraphEdge] = [
            GraphEdge(
                source=r["source"],
                target=r["target"],
                type=r["rel_type"],
                properties=r["props"],
            )
            for r in edges_result
        ]
    else:
        edges = []
    
    return GraphResponse(
        nodes=nodes,
        edges=edges,
        node_count=len(nodes),
        edge_count=len(edges),
    )


@router.get(
    "/stats",
    response_model=GraphStats,
    summary="Get Graph Statistics",
    description="Get statistics about the attack surface graph.",
)
async def get_graph_stats(
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
) -> GraphStats:
    """Get statistics about the attack surface graph."""
    client = get_neo4j_client()
    
    # Count nodes by type
    nodes_query = """
    MATCH (n)
    WHERE n.project_id = $project_id
    WITH labels(n)[0] as label
    RETURN label, count(*) as count
    """
    
    nodes_result = await client.execute_read(nodes_query, {"project_id": project_id})
    
    node_types = {r["label"]: r["count"] for r in nodes_result}
    total_nodes = sum(node_types.values())
    
    # Count edges by type
    edges_query = """
    MATCH (a)-[r]->(b)
    WHERE a.project_id = $project_id
    WITH type(r) as rel_type
    RETURN rel_type, count(*) as count
    """
    
    edges_result = await client.execute_read(edges_query, {"project_id": project_id})
    
    edge_types = {r["rel_type"]: r["count"] for r in edges_result}
    total_edges = sum(edge_types.values())
    
    return GraphStats(
        total_nodes=total_nodes,
        total_edges=total_edges,
        node_types=node_types,
        edge_types=edge_types,
    )


@router.get(
    "/neighbors/{node_id}",
    response_model=GraphResponse,
    summary="Get Node Neighbors",
    description="Get a node and its immediate neighbors.",
)
async def get_node_neighbors(
    node_id: str,
    project_id: str = Query(..., description="Project ID"),
    project: Annotated[dict, Depends(ProjectAccess())] = None,
    depth: int = Query(1, ge=1, le=3, description="Traversal depth"),
) -> GraphResponse:
    """Get a node and its neighbors up to specified depth."""
    client = get_neo4j_client()
    
    # Fetch node and neighbors
    query = f"""
    MATCH path = (start)-[*1..{depth}]-(neighbor)
    WHERE elementId(start) = $node_id
    AND start.project_id = $project_id
    WITH nodes(path) as path_nodes, relationships(path) as path_rels
    UNWIND path_nodes as n
    WITH collect(DISTINCT n) as all_nodes, path_rels
    UNWIND all_nodes as n
    WITH n, labels(n) as node_labels, path_rels
    RETURN 
        collect(DISTINCT {{
            id: elementId(n), 
            type: node_labels[0], 
            props: properties(n)
        }}) as nodes,
        path_rels
    """
    
    result = await client.execute_read(
        query,
        {"node_id": node_id, "project_id": project_id},
    )
    
    if not result:
        return GraphResponse(nodes=[], edges=[], node_count=0, edge_count=0)
    
    # Process results
    nodes: list[GraphNode] = []
    node_ids = set()
    
    for r in result:
        for n in r["nodes"]:
            node_id_str = n["id"]
            if node_id_str not in node_ids:
                node_ids.add(node_id_str)
                
                node_type = n["type"]
                props = n["props"]
                
                label = props.get("name", props.get("address", props.get("url", node_type)))
                if isinstance(label, str) and len(label) > 50:
                    label = label[:50] + "..."
                
                nodes.append(GraphNode(
                    id=node_id_str,
                    label=str(label),
                    type=node_type,
                    properties=props,
                    severity=props.get("severity"),
                ))
    
    # Fetch edges between these nodes
    if node_ids:
        edges_query = """
        MATCH (a)-[r]->(b)
        WHERE elementId(a) IN $node_ids
        AND elementId(b) IN $node_ids
        RETURN 
            elementId(a) as source,
            elementId(b) as target,
            type(r) as rel_type
        """
        
        edges_result = await client.execute_read(
            edges_query,
            {"node_ids": list(node_ids)},
        )
        
        edges: list[GraphEdge] = [
            GraphEdge(
                source=r["source"],
                target=r["target"],
                type=r["rel_type"],
            )
            for r in edges_result
        ]
    else:
        edges = []
    
    return GraphResponse(
        nodes=nodes,
        edges=edges,
        node_count=len(nodes),
        edge_count=len(edges),
    )
