// =============================================================================
// Arc - Neo4j Index and Constraint Definitions
// Run after schema files. All CREATE INDEX/CONSTRAINT/FULLTEXT in one place.
// =============================================================================

// =============================================================================
// CORE SCHEMA - Constraints
// =============================================================================
CREATE CONSTRAINT domain_unique IF NOT EXISTS
FOR (d:Domain) REQUIRE (d.name, d.project_id) IS UNIQUE;

CREATE CONSTRAINT subdomain_unique IF NOT EXISTS
FOR (s:Subdomain) REQUIRE (s.name, s.project_id) IS UNIQUE;

CREATE CONSTRAINT ip_unique IF NOT EXISTS
FOR (i:IP) REQUIRE (i.address, i.project_id) IS UNIQUE;

CREATE CONSTRAINT url_unique IF NOT EXISTS
FOR (u:URL) REQUIRE (u.url, u.project_id) IS UNIQUE;

CREATE CONSTRAINT vulnerability_unique IF NOT EXISTS
FOR (v:Vulnerability) REQUIRE (v.template_id, v.matched_at, v.project_id) IS UNIQUE;

CREATE CONSTRAINT cve_unique IF NOT EXISTS
FOR (c:CVE) REQUIRE (c.cve_id, c.project_id) IS UNIQUE;

CREATE CONSTRAINT scan_unique IF NOT EXISTS
FOR (s:Scan) REQUIRE s.scan_id IS UNIQUE;

CREATE CONSTRAINT project_unique IF NOT EXISTS
FOR (p:Project) REQUIRE p.project_id IS UNIQUE;

CREATE CONSTRAINT user_unique IF NOT EXISTS
FOR (u:User) REQUIRE u.user_id IS UNIQUE;

CREATE CONSTRAINT user_email_unique IF NOT EXISTS
FOR (u:User) REQUIRE u.email IS UNIQUE;

CREATE CONSTRAINT whoisdata_unique IF NOT EXISTS
FOR (w:WhoisData) REQUIRE (w.domain_name, w.project_id) IS UNIQUE;

CREATE CONSTRAINT shodandata_unique IF NOT EXISTS
FOR (s:ShodanData) REQUIRE (s.ip, s.project_id) IS UNIQUE;

CREATE CONSTRAINT apiendpoint_unique IF NOT EXISTS
FOR (a:ApiEndpoint) REQUIRE (a.base_url, a.path, a.method, a.project_id) IS UNIQUE;

CREATE CONSTRAINT githubrepo_unique IF NOT EXISTS
FOR (g:GitHubRepo) REQUIRE (g.full_name, g.project_id) IS UNIQUE;

CREATE CONSTRAINT githubfinding_unique IF NOT EXISTS
FOR (f:GitHubFinding) REQUIRE (f.repo_full_name, f.path, f.project_id) IS UNIQUE;

// =============================================================================
// CORE SCHEMA - Indexes
// =============================================================================
CREATE INDEX idx_user_email IF NOT EXISTS
FOR (u:User) ON (u.email);

CREATE INDEX idx_user_active IF NOT EXISTS
FOR (u:User) ON (u.is_active);

CREATE INDEX idx_domain_project IF NOT EXISTS
FOR (d:Domain) ON (d.project_id);

CREATE INDEX idx_subdomain_project IF NOT EXISTS
FOR (s:Subdomain) ON (s.project_id);

CREATE INDEX idx_ip_project IF NOT EXISTS
FOR (i:IP) ON (i.project_id);

CREATE INDEX idx_port_project IF NOT EXISTS
FOR (p:Port) ON (p.project_id);

CREATE INDEX idx_service_project IF NOT EXISTS
FOR (svc:Service) ON (svc.project_id);

CREATE INDEX idx_url_project IF NOT EXISTS
FOR (u:URL) ON (u.project_id);

CREATE INDEX idx_endpoint_project IF NOT EXISTS
FOR (e:Endpoint) ON (e.project_id);

CREATE INDEX idx_parameter_project IF NOT EXISTS
FOR (p:Parameter) ON (p.project_id);

CREATE INDEX idx_technology_project IF NOT EXISTS
FOR (t:Technology) ON (t.project_id);

CREATE INDEX idx_vulnerability_project IF NOT EXISTS
FOR (v:Vulnerability) ON (v.project_id);

CREATE INDEX idx_cve_project IF NOT EXISTS
FOR (c:CVE) ON (c.project_id);

CREATE INDEX idx_scan_project IF NOT EXISTS
FOR (s:Scan) ON (s.project_id);

CREATE INDEX idx_domain_name IF NOT EXISTS
FOR (d:Domain) ON (d.name);

CREATE INDEX idx_subdomain_name IF NOT EXISTS
FOR (s:Subdomain) ON (s.name);

CREATE INDEX idx_ip_address IF NOT EXISTS
FOR (i:IP) ON (i.address);

CREATE INDEX idx_ip_cdn IF NOT EXISTS
FOR (i:IP) ON (i.is_cdn);

CREATE INDEX idx_port_number IF NOT EXISTS
FOR (p:Port) ON (p.number);

CREATE INDEX idx_port_state IF NOT EXISTS
FOR (p:Port) ON (p.state);

CREATE INDEX idx_service_name IF NOT EXISTS
FOR (svc:Service) ON (svc.name);

CREATE INDEX idx_service_product IF NOT EXISTS
FOR (svc:Service) ON (svc.product);

CREATE INDEX idx_url_status IF NOT EXISTS
FOR (u:URL) ON (u.status_code);

CREATE INDEX idx_url_live IF NOT EXISTS
FOR (u:URL) ON (u.is_live);

CREATE INDEX idx_technology_name IF NOT EXISTS
FOR (t:Technology) ON (t.name);

CREATE INDEX idx_technology_version IF NOT EXISTS
FOR (t:Technology) ON (t.name, t.version);

CREATE INDEX idx_vulnerability_severity IF NOT EXISTS
FOR (v:Vulnerability) ON (v.severity);

CREATE INDEX idx_vulnerability_template IF NOT EXISTS
FOR (v:Vulnerability) ON (v.template_id);

CREATE INDEX idx_vulnerability_id IF NOT EXISTS
FOR (v:Vulnerability) ON (v.vulnerability_id);

CREATE INDEX idx_vulnerability_cve IF NOT EXISTS
FOR (v:Vulnerability) ON (v.cve_id);

CREATE INDEX idx_cve_id IF NOT EXISTS
FOR (c:CVE) ON (c.cve_id);

CREATE INDEX idx_cve_severity IF NOT EXISTS
FOR (c:CVE) ON (c.severity);

CREATE INDEX idx_cve_cvss IF NOT EXISTS
FOR (c:CVE) ON (c.cvss_score);

CREATE INDEX idx_scan_status IF NOT EXISTS
FOR (s:Scan) ON (s.status);

CREATE INDEX idx_scan_type IF NOT EXISTS
FOR (s:Scan) ON (s.scan_type);

CREATE INDEX idx_scan_target IF NOT EXISTS
FOR (s:Scan) ON (s.target);

CREATE INDEX idx_parameter_injectable IF NOT EXISTS
FOR (p:Parameter) ON (p.is_injectable);

CREATE INDEX idx_domain_created IF NOT EXISTS
FOR (d:Domain) ON (d.created_at);

CREATE INDEX idx_vulnerability_created IF NOT EXISTS
FOR (v:Vulnerability) ON (v.created_at);

CREATE INDEX idx_scan_started IF NOT EXISTS
FOR (s:Scan) ON (s.started_at);

CREATE INDEX idx_whoisdata_project IF NOT EXISTS
FOR (w:WhoisData) ON (w.project_id);

CREATE INDEX idx_whoisdata_domain IF NOT EXISTS
FOR (w:WhoisData) ON (w.domain_name);

CREATE INDEX idx_shodandata_project IF NOT EXISTS
FOR (s:ShodanData) ON (s.project_id);

CREATE INDEX idx_shodandata_ip IF NOT EXISTS
FOR (s:ShodanData) ON (s.ip);

CREATE INDEX idx_apiendpoint_project IF NOT EXISTS
FOR (a:ApiEndpoint) ON (a.project_id);

CREATE INDEX idx_githubrepo_project IF NOT EXISTS
FOR (g:GitHubRepo) ON (g.project_id);

CREATE INDEX idx_githubfinding_project IF NOT EXISTS
FOR (f:GitHubFinding) ON (f.project_id);

// =============================================================================
// CORE SCHEMA - Full-text indexes
// =============================================================================
CREATE FULLTEXT INDEX vuln_fulltext IF NOT EXISTS
FOR (v:Vulnerability) ON EACH [v.name, v.description];

CREATE FULLTEXT INDEX tech_fulltext IF NOT EXISTS
FOR (t:Technology) ON EACH [t.name, t.categories];

// =============================================================================
// IDENTITY SCHEMA - Constraints
// =============================================================================
CREATE CONSTRAINT ad_user_unique IF NOT EXISTS
FOR (u:ADUser) REQUIRE (u.object_id, u.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_group_unique IF NOT EXISTS
FOR (g:ADGroup) REQUIRE (g.object_id, g.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_computer_unique IF NOT EXISTS
FOR (c:ADComputer) REQUIRE (c.object_id, c.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_domain_unique IF NOT EXISTS
FOR (d:ADDomain) REQUIRE (d.domain_sid, d.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_ou_unique IF NOT EXISTS
FOR (o:ADOU) REQUIRE (o.ou_guid, o.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_gpo_unique IF NOT EXISTS
FOR (g:ADGPO) REQUIRE (g.gpo_guid, g.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_cert_template_unique IF NOT EXISTS
FOR (t:ADCertTemplate) REQUIRE (t.template_name, t.project_id) IS UNIQUE;

CREATE CONSTRAINT ad_ca_unique IF NOT EXISTS
FOR (ca:ADCA) REQUIRE (ca.ca_name, ca.project_id) IS UNIQUE;

CREATE CONSTRAINT azure_user_unique IF NOT EXISTS
FOR (u:AzureUser) REQUIRE (u.object_id, u.project_id) IS UNIQUE;

CREATE CONSTRAINT azure_group_unique IF NOT EXISTS
FOR (g:AzureGroup) REQUIRE (g.object_id, g.project_id) IS UNIQUE;

CREATE CONSTRAINT azure_app_unique IF NOT EXISTS
FOR (a:AzureApp) REQUIRE (a.app_id, a.project_id) IS UNIQUE;

CREATE CONSTRAINT azure_sp_unique IF NOT EXISTS
FOR (sp:AzureServicePrincipal) REQUIRE (sp.sp_id, sp.project_id) IS UNIQUE;

CREATE CONSTRAINT azure_role_unique IF NOT EXISTS
FOR (r:AzureRole) REQUIRE (r.role_id, r.project_id) IS UNIQUE;

CREATE CONSTRAINT credential_unique IF NOT EXISTS
FOR (c:Credential) REQUIRE (c.credential_id, c.project_id) IS UNIQUE;

CREATE CONSTRAINT session_unique IF NOT EXISTS
FOR (s:Session) REQUIRE (s.session_id, s.project_id) IS UNIQUE;

// =============================================================================
// IDENTITY SCHEMA - Indexes
// =============================================================================
CREATE INDEX idx_ad_user_project IF NOT EXISTS
FOR (u:ADUser) ON (u.project_id);

CREATE INDEX idx_ad_user_sam IF NOT EXISTS
FOR (u:ADUser) ON (u.sam_account_name);

CREATE INDEX idx_ad_user_upn IF NOT EXISTS
FOR (u:ADUser) ON (u.user_principal_name);

CREATE INDEX idx_ad_user_enabled IF NOT EXISTS
FOR (u:ADUser) ON (u.enabled);

CREATE INDEX idx_ad_user_admin IF NOT EXISTS
FOR (u:ADUser) ON (u.admin_count);

CREATE INDEX idx_ad_user_spn IF NOT EXISTS
FOR (u:ADUser) ON (u.has_spn);

CREATE INDEX idx_ad_user_unconstrained IF NOT EXISTS
FOR (u:ADUser) ON (u.unconstrained_delegation);

CREATE INDEX idx_ad_group_project IF NOT EXISTS
FOR (g:ADGroup) ON (g.project_id);

CREATE INDEX idx_ad_group_name IF NOT EXISTS
FOR (g:ADGroup) ON (g.name);

CREATE INDEX idx_ad_group_highvalue IF NOT EXISTS
FOR (g:ADGroup) ON (g.high_value);

CREATE INDEX idx_ad_computer_project IF NOT EXISTS
FOR (c:ADComputer) ON (c.project_id);

CREATE INDEX idx_ad_computer_name IF NOT EXISTS
FOR (c:ADComputer) ON (c.name);

CREATE INDEX idx_ad_computer_os IF NOT EXISTS
FOR (c:ADComputer) ON (c.operating_system);

CREATE INDEX idx_ad_computer_dc IF NOT EXISTS
FOR (c:ADComputer) ON (c.is_dc);

CREATE INDEX idx_ad_computer_unconstrained IF NOT EXISTS
FOR (c:ADComputer) ON (c.unconstrained_delegation);

CREATE INDEX idx_ad_domain_project IF NOT EXISTS
FOR (d:ADDomain) ON (d.project_id);

CREATE INDEX idx_ad_domain_name IF NOT EXISTS
FOR (d:ADDomain) ON (d.name);

CREATE INDEX idx_credential_project IF NOT EXISTS
FOR (c:Credential) ON (c.project_id);

CREATE INDEX idx_credential_type IF NOT EXISTS
FOR (c:Credential) ON (c.credential_type);

CREATE INDEX idx_credential_valid IF NOT EXISTS
FOR (c:Credential) ON (c.is_valid);

CREATE INDEX idx_session_project IF NOT EXISTS
FOR (s:Session) ON (s.project_id);

CREATE INDEX idx_session_active IF NOT EXISTS
FOR (s:Session) ON (s.is_active);

CREATE INDEX idx_azure_user_project IF NOT EXISTS
FOR (u:AzureUser) ON (u.project_id);

CREATE INDEX idx_azure_group_project IF NOT EXISTS
FOR (g:AzureGroup) ON (g.project_id);

CREATE INDEX idx_azure_app_project IF NOT EXISTS
FOR (a:AzureApp) ON (a.project_id);

CREATE INDEX idx_azure_sp_project IF NOT EXISTS
FOR (sp:AzureServicePrincipal) ON (sp.project_id);

// =============================================================================
// IDENTITY SCHEMA - Full-text indexes
// =============================================================================
CREATE FULLTEXT INDEX ad_user_fulltext IF NOT EXISTS
FOR (u:ADUser) ON EACH [u.sam_account_name, u.display_name, u.description];

CREATE FULLTEXT INDEX ad_computer_fulltext IF NOT EXISTS
FOR (c:ADComputer) ON EACH [c.name, c.operating_system, c.description];

CREATE FULLTEXT INDEX ad_group_fulltext IF NOT EXISTS
FOR (g:ADGroup) ON EACH [g.name, g.description];

// =============================================================================
// ATTACK GRAPH SCHEMA - Constraints
// =============================================================================
CREATE CONSTRAINT attack_node_unique IF NOT EXISTS
FOR (a:AttackNode) REQUIRE (a.node_id, a.project_id) IS UNIQUE;

CREATE CONSTRAINT attack_edge_unique IF NOT EXISTS
FOR (e:AttackEdge) REQUIRE (e.edge_id, e.project_id) IS UNIQUE;

CREATE CONSTRAINT attack_path_unique IF NOT EXISTS
FOR (p:AttackPath) REQUIRE (p.path_id, p.project_id) IS UNIQUE;

CREATE CONSTRAINT choke_point_unique IF NOT EXISTS
FOR (cp:ChokePoint) REQUIRE (cp.node_id, cp.project_id) IS UNIQUE;

// =============================================================================
// ATTACK GRAPH SCHEMA - Indexes
// =============================================================================
CREATE INDEX idx_attack_node_project IF NOT EXISTS
FOR (a:AttackNode) ON (a.project_id);

CREATE INDEX idx_attack_node_type IF NOT EXISTS
FOR (a:AttackNode) ON (a.node_type);

CREATE INDEX idx_attack_node_compromised IF NOT EXISTS
FOR (a:AttackNode) ON (a.compromised);

CREATE INDEX idx_attack_node_criticality IF NOT EXISTS
FOR (a:AttackNode) ON (a.criticality);

CREATE INDEX idx_attack_path_project IF NOT EXISTS
FOR (p:AttackPath) ON (p.project_id);

CREATE INDEX idx_attack_path_cost IF NOT EXISTS
FOR (p:AttackPath) ON (p.total_cost);

CREATE INDEX idx_choke_point_project IF NOT EXISTS
FOR (cp:ChokePoint) ON (cp.project_id);

CREATE INDEX idx_choke_point_score IF NOT EXISTS
FOR (cp:ChokePoint) ON (cp.centrality_score);

// =============================================================================
// MITRE SCHEMA - Constraints
// =============================================================================
CREATE CONSTRAINT mitre_tactic_unique IF NOT EXISTS
FOR (t:MITRETactic) REQUIRE t.tactic_id IS UNIQUE;

CREATE CONSTRAINT mitre_technique_unique IF NOT EXISTS
FOR (t:MITRETechnique) REQUIRE t.technique_id IS UNIQUE;

CREATE CONSTRAINT mitre_subtechnique_unique IF NOT EXISTS
FOR (s:MITRESubTechnique) REQUIRE s.technique_id IS UNIQUE;

CREATE CONSTRAINT mitre_group_unique IF NOT EXISTS
FOR (g:MITREGroup) REQUIRE g.group_id IS UNIQUE;

CREATE CONSTRAINT mitre_software_unique IF NOT EXISTS
FOR (s:MITRESoftware) REQUIRE s.software_id IS UNIQUE;

CREATE CONSTRAINT mitre_mitigation_unique IF NOT EXISTS
FOR (m:MITREMitigation) REQUIRE m.mitigation_id IS UNIQUE;

CREATE CONSTRAINT mitre_datasource_unique IF NOT EXISTS
FOR (d:MITREDataSource) REQUIRE d.datasource_id IS UNIQUE;

CREATE CONSTRAINT execution_step_unique IF NOT EXISTS
FOR (e:ExecutionStep) REQUIRE (e.step_id, e.project_id) IS UNIQUE;

// =============================================================================
// MITRE SCHEMA - Indexes
// =============================================================================
CREATE INDEX idx_mitre_tactic_name IF NOT EXISTS
FOR (t:MITRETactic) ON (t.name);

CREATE INDEX idx_mitre_tactic_shortname IF NOT EXISTS
FOR (t:MITRETactic) ON (t.short_name);

CREATE INDEX idx_mitre_technique_name IF NOT EXISTS
FOR (t:MITRETechnique) ON (t.name);

CREATE INDEX idx_mitre_technique_platform IF NOT EXISTS
FOR (t:MITRETechnique) ON (t.platforms);

CREATE INDEX idx_mitre_subtechnique_name IF NOT EXISTS
FOR (s:MITRESubTechnique) ON (s.name);

CREATE INDEX idx_mitre_subtechnique_parent IF NOT EXISTS
FOR (s:MITRESubTechnique) ON (s.parent_technique_id);

CREATE INDEX idx_mitre_group_name IF NOT EXISTS
FOR (g:MITREGroup) ON (g.name);

CREATE INDEX idx_mitre_software_name IF NOT EXISTS
FOR (s:MITRESoftware) ON (s.name);

CREATE INDEX idx_mitre_software_type IF NOT EXISTS
FOR (s:MITRESoftware) ON (s.software_type);

CREATE INDEX idx_execution_step_project IF NOT EXISTS
FOR (e:ExecutionStep) ON (e.project_id);

CREATE INDEX idx_execution_step_scan IF NOT EXISTS
FOR (e:ExecutionStep) ON (e.scan_id);

CREATE INDEX idx_execution_step_tool IF NOT EXISTS
FOR (e:ExecutionStep) ON (e.tool_name);

CREATE INDEX idx_execution_step_timestamp IF NOT EXISTS
FOR (e:ExecutionStep) ON (e.executed_at);

// =============================================================================
// MITRE SCHEMA - Full-text indexes
// =============================================================================
CREATE FULLTEXT INDEX mitre_technique_fulltext IF NOT EXISTS
FOR (t:MITRETechnique) ON EACH [t.name, t.description];

CREATE FULLTEXT INDEX mitre_group_fulltext IF NOT EXISTS
FOR (g:MITREGroup) ON EACH [g.name, g.description];
