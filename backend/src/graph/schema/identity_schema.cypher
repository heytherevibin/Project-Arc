// =============================================================================
// Arc - Identity & Active Directory Attack Path Schema
// BloodHound-style identity relationship modeling for AD/Azure environments
// =============================================================================
// Constraints and indexes are in indexes.cypher (run after this file).
// =============================================================================

// =============================================================================
// RELATIONSHIP TYPE DESCRIPTIONS (BloodHound-compatible)
// =============================================================================

// --- Group Membership ---
// (ADUser)-[:MEMBER_OF]->(ADGroup)
// (ADGroup)-[:MEMBER_OF]->(ADGroup)          // nested groups
// (ADComputer)-[:MEMBER_OF]->(ADGroup)

// --- Admin Relationships ---
// (ADUser)-[:ADMIN_TO]->(ADComputer)          // local admin
// (ADGroup)-[:ADMIN_TO]->(ADComputer)
// (ADUser)-[:CAN_RDPINTO]->(ADComputer)       // RDP access
// (ADUser)-[:CAN_PSREMOTE]->(ADComputer)      // PS remote
// (ADUser)-[:EXECUTE_DCOM]->(ADComputer)      // DCOM exec

// --- ACL-based Abuse ---
// (ADUser|ADGroup)-[:GENERIC_ALL]->(ADUser|ADGroup|ADComputer)
// (ADUser|ADGroup)-[:GENERIC_WRITE]->(ADUser|ADGroup|ADComputer)
// (ADUser|ADGroup)-[:WRITE_DACL]->(ADUser|ADGroup|ADComputer)
// (ADUser|ADGroup)-[:WRITE_OWNER]->(ADUser|ADGroup|ADComputer)
// (ADUser|ADGroup)-[:FORCE_CHANGE_PASSWORD]->(ADUser)
// (ADUser|ADGroup)-[:ADD_MEMBER]->(ADGroup)
// (ADUser|ADGroup)-[:OWNS]->(ADUser|ADGroup|ADComputer)

// --- Kerberos ---
// (ADUser)-[:HAS_SPN_TO]->(ADComputer)        // kerberoastable SPN
// (ADUser)-[:ALLOWED_TO_DELEGATE]->(ADComputer)
// (ADComputer)-[:ALLOWED_TO_DELEGATE]->(ADComputer)
// (ADUser)-[:ALLOWED_TO_ACT]->(ADComputer)    // RBCD

// --- Credential Flow ---
// (ADUser)-[:HAS_SESSION]->(ADComputer)       // logged-in session
// (ADComputer)-[:HAS_SESSION]->(ADUser)       // reverse: who is on machine
// (Credential)-[:BELONGS_TO]->(ADUser)
// (Credential)-[:BELONGS_TO]->(ADComputer)
// (Credential)-[:VALID_FOR]->(ADComputer)     // credential works on host

// --- GPO ---
// (ADGPO)-[:APPLIES_TO]->(ADOU)
// (ADGPO)-[:APPLIES_TO]->(ADDomain)
// (ADUser|ADGroup)-[:GPO_EDIT]->(ADGPO)

// --- OU hierarchy ---
// (ADDomain)-[:CONTAINS]->(ADOU)
// (ADOU)-[:CONTAINS]->(ADOU)
// (ADOU)-[:CONTAINS]->(ADUser|ADGroup|ADComputer)

// --- ADCS (Certificate Services) ---
// (ADCertTemplate)-[:PUBLISHED_BY]->(ADCA)
// (ADUser|ADGroup)-[:CAN_ENROLL]->(ADCertTemplate)
// (ADCertTemplate)-[:ENABLES_AUTH_AS]->(ADUser)  // ESC1/ESC6/ESC9 etc.

// --- Domain Trust ---
// (ADDomain)-[:TRUSTS]->(ADDomain)
// (ADDomain)-[:TRUSTED_BY]->(ADDomain)

// --- Azure AD ---
// (AzureUser)-[:MEMBER_OF]->(AzureGroup)
// (AzureUser)-[:HAS_ROLE]->(AzureRole)
// (AzureServicePrincipal)-[:HAS_ROLE]->(AzureRole)
// (AzureApp)-[:HAS_SERVICE_PRINCIPAL]->(AzureServicePrincipal)
// (AzureUser)-[:OWNS]->(AzureApp)
// (AzureUser)-[:APP_ADMIN]->(AzureApp)

// --- Cross-domain: tie AD identity to recon hosts ---
// (ADComputer)-[:MAPS_TO_HOST]->(Host)        // links AD computer to recon IP/Host
// (ADUser)-[:MAPS_TO_TARGET]->(Subdomain|IP)
