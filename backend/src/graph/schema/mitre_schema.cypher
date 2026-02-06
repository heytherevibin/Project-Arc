// =============================================================================
// Arc - MITRE ATT&CK Schema
// Maps attack activities to the ATT&CK framework for adversary emulation
// =============================================================================
// Constraints and indexes are in indexes.cypher (run after this file).
// =============================================================================

// =============================================================================
// RELATIONSHIP TYPE DESCRIPTIONS
// =============================================================================

// Tactic → Technique hierarchy:
// (MITRETactic)-[:INCLUDES_TECHNIQUE]->(MITRETechnique)
// (MITRETechnique)-[:HAS_SUBTECHNIQUE]->(MITRESubTechnique)

// Threat intelligence:
// (MITREGroup)-[:USES_TECHNIQUE]->(MITRETechnique)
// (MITREGroup)-[:USES_SOFTWARE]->(MITRESoftware)
// (MITRESoftware)-[:IMPLEMENTS_TECHNIQUE]->(MITRETechnique)

// Defensive mapping:
// (MITREMitigation)-[:MITIGATES]->(MITRETechnique)
// (MITREDataSource)-[:DETECTS]->(MITRETechnique)

// Execution trace → ATT&CK mapping:
// (ExecutionStep)-[:MAPS_TO_TECHNIQUE]->(MITRETechnique)
// (ExecutionStep)-[:MAPS_TO_TACTIC]->(MITRETactic)
// (Scan)-[:HAS_STEP]->(ExecutionStep)

// Vulnerability → ATT&CK mapping:
// (Vulnerability)-[:EXPLOITS_TECHNIQUE]->(MITRETechnique)
// (CVE)-[:ASSOCIATED_TECHNIQUE]->(MITRETechnique)
