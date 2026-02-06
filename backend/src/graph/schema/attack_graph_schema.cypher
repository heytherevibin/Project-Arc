// =============================================================================
// Arc - Attack Graph Schema
// Weighted attack graph for GDS path discovery algorithms
// =============================================================================
// Constraints and indexes are in indexes.cypher (run after this file).
// =============================================================================

// =============================================================================
// RELATIONSHIP TYPE DESCRIPTIONS
// =============================================================================

// --- Attack Graph Edges (weighted for GDS) ---
// (AttackNode)-[:CAN_REACH {difficulty: float, stealth: float, cost: float}]->(AttackNode)
//   Properties:
//     difficulty: 0.0 (trivial) → 1.0 (extremely hard)
//     stealth:    0.0 (noisy)   → 1.0 (silent)
//     cost:       composite weight = difficulty * (1 - stealth) for GDS shortest path
//     technique:  MITRE ATT&CK technique ID used for this transition
//     tool:       tool required (e.g. "metasploit", "impacket")

// --- Virtual relationships derived from recon data ---
// These are created by the AttackGraphBuilder from actual recon findings:
//
// (Host|IP)-[:CAN_EXPLOIT {difficulty, vuln_id, cve}]->(Vulnerability)
//   A host has an exploitable vulnerability
//
// (Vulnerability)-[:LEADS_TO {difficulty}]->(Host|IP)
//   Exploiting a vulnerability gives access to a host
//
// (Host|IP)-[:HAS_ACCESS {permission_level}]->(Host|IP)
//   Network-level access between hosts (from port/service data)
//
// (ADUser)-[:CAN_COMPROMISE]->(ADComputer)
//   Derived from BloodHound-style identity paths
//
// (Credential)-[:GRANTS_ACCESS {permission_level}]->(Host|IP|ADComputer)
//   A credential provides access to a target

// --- Path results ---
// (AttackPath)-[:STARTS_AT]->(AttackNode)
// (AttackPath)-[:ENDS_AT]->(AttackNode)
// (AttackPath)-[:TRAVERSES {order: int}]->(AttackNode)

// =============================================================================
// GDS PROJECTION DOCUMENTATION
// =============================================================================
//
// The following GDS projections are created at runtime by the AttackPathFinder:
//
// 1. attack_surface_{project_id}
//    Nodes: Host, IP, ADUser, ADComputer, ADGroup, Credential, Vulnerability
//    Relationships: CAN_REACH, CAN_EXPLOIT, LEADS_TO, HAS_ACCESS,
//                   MEMBER_OF, ADMIN_TO, CAN_RDPINTO, ALLOWED_TO_DELEGATE
//    Weight property: "cost" (composite of difficulty and stealth)
//
// 2. identity_graph_{project_id}
//    Nodes: ADUser, ADGroup, ADComputer, ADGPO, ADOU
//    Relationships: MEMBER_OF, ADMIN_TO, CAN_RDPINTO, CAN_PSREMOTE,
//                   GENERIC_ALL, GENERIC_WRITE, WRITE_DACL, FORCE_CHANGE_PASSWORD,
//                   HAS_SPN_TO, ALLOWED_TO_DELEGATE, HAS_SESSION
//    Weight property: "cost"
//
// Algorithms used:
//   - gds.shortestPath.dijkstra: Shortest attack path (weighted)
//   - gds.shortestPath.yens:     K-shortest paths
//   - gds.betweenness:           Choke point detection (centrality)
//   - gds.bfs:                   Blast radius calculation
//   - gds.louvain:               Community detection (network segmentation)
//   - gds.pageRank:              High-value node identification
