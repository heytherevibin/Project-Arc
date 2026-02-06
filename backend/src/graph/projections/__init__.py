"""Neo4j GDS graph projections for attack path analysis."""

from graph.projections.attack_surface import AttackSurfaceProjection
from graph.projections.identity_graph import IdentityGraphProjection

__all__ = ["AttackSurfaceProjection", "IdentityGraphProjection"]
