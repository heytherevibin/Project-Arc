/**
 * Arc Mission Control - Type Definitions
 */

// =============================================================================
// Project Types
// =============================================================================

export interface Project {
  project_id: string;
  name: string;
  description: string | null;
  status: 'active' | 'paused' | 'completed' | 'archived';
  scope: string[];
  out_of_scope: string[];
  tags: string[];
  created_at: string;
  updated_at: string | null;
  owner_id: string;
  stats?: ProjectStats;
}

export interface ProjectStats {
  domains: number;
  subdomains: number;
  ips: number;
  ports: number;
  urls: number;
  vulnerabilities: number;
  critical_vulns: number;
  high_vulns: number;
  scans_completed: number;
}

export interface ProjectCreate {
  name: string;
  description?: string;
  scope: string[];
  out_of_scope?: string[];
  tags?: string[];
}

// =============================================================================
// Target Types
// =============================================================================

export type TargetType = 'domain' | 'ip' | 'url' | 'cidr';

export interface Target {
  target_id: string;
  value: string;
  target_type: TargetType;
  description: string | null;
  tags: string[];
  status: string;
  created_at: string;
  last_scanned_at: string | null;
  findings_count: number;
}

export interface TargetDetails extends Target {
  subdomains_count: number;
  ips_count: number;
  ports_count: number;
  urls_count: number;
  vulnerabilities_count: number;
  technologies: string[];
}

// =============================================================================
// Scan Types
// =============================================================================

export type ScanType = 
  | 'subdomain_discovery'
  | 'port_scan'
  | 'dns_resolution'
  | 'http_probe'
  | 'service_fingerprint'
  | 'web_crawl'
  | 'api_discovery'
  | 'vulnerability_scan'
  | 'technology_detection'
  | 'full_recon';

export type ScanStatus = 
  | 'pending'
  | 'queued'
  | 'running'
  | 'paused'
  | 'completed'
  | 'failed'
  | 'cancelled'
  | 'timeout';

export interface Scan {
  scan_id: string;
  target: string;
  scan_type: ScanType;
  status: ScanStatus;
  progress: number;
  phase: string | null;
  started_at: string | null;
  completed_at: string | null;
  duration_seconds: number | null;
  findings_count: number;
  error_message: string | null;
  created_at: string;
}

export interface ScanProgress {
  scan_id: string;
  status: ScanStatus;
  progress: number;
  phase: string | null;
  current_tool: string | null;
  items_discovered: number;
  vulnerabilities_found: number;
  elapsed_seconds: number;
}

export interface WhoisEntry {
  domain_name: string;
  raw?: string | null;
}

export interface ShodanEntry {
  ip: string;
  data_json?: string | null;
}

export interface ScanResults {
  scan_id: string;
  target: string;
  scan_type: ScanType;
  status: ScanStatus;
  summary: {
    subdomains_count: number;
    ips_count: number;
    ports_count: number;
    urls_count: number;
    technologies_count: number;
    vulnerabilities_count: number;
    whois_count?: number;
    shodan_count?: number;
    api_endpoints_count?: number;
    github_repos_count?: number;
    github_findings_count?: number;
    critical_count: number;
    high_count: number;
    medium_count: number;
    low_count: number;
  };
  subdomains: Subdomain[];
  ips: IPAddress[];
  ports: Port[];
  urls: URL[];
  technologies: Technology[];
  vulnerabilities: Vulnerability[];
  whois_data?: WhoisEntry[];
  shodan_data?: ShodanEntry[];
  api_endpoints?: ApiEndpoint[];
  github_repos?: GitHubRepo[];
  github_findings?: GitHubFinding[];
  /** Per-phase tool errors (e.g. MCP unreachable). Shown when recon tools failed. */
  tool_errors?: string[] | null;
}

export interface ApiEndpoint {
  base_url: string;
  path: string;
  method: string;
}

export interface GitHubRepo {
  full_name: string;
  html_url?: string | null;
  description?: string | null;
  updated_at?: string | null;
}

export interface GitHubFinding {
  repo_full_name: string;
  path: string;
  html_url?: string | null;
}

// =============================================================================
// Asset Types
// =============================================================================

export interface Subdomain {
  name: string;
  has_dns_records: boolean;
  is_wildcard: boolean;
  discovery_source: string | null;
  created_at: string;
}

export interface IPAddress {
  address: string;
  version: number;
  is_internal: boolean;
  is_cdn: boolean;
  cdn_name: string | null;
  asn: string | null;
  asn_org: string | null;
  country: string | null;
}

export interface Port {
  number: number;
  protocol: 'tcp' | 'udp';
  state: string;
  ip: string;
}

export interface URL {
  url: string;
  status_code: number | null;
  title: string | null;
  content_type: string | null;
  content_length: number | null;
  server: string | null;
  is_live: boolean;
  technologies?: string[];
}

export interface Technology {
  name: string;
  version: string | null;
  categories: string[];
  confidence: number;
}

// =============================================================================
// Vulnerability Types
// =============================================================================

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export interface Vulnerability {
  template_id: string;
  name: string;
  description: string | null;
  severity: Severity;
  cvss_score: number | null;
  cve_id: string | null;
  cwe_id: string | null;
  matched_at: string;
  evidence: string | null;
  remediation: string | null;
  references: string[];
  created_at: string;
}

// =============================================================================
// Graph Types (for visualization)
// =============================================================================

export interface GraphNode {
  id: string;
  label: string;
  type: 'domain' | 'subdomain' | 'ip' | 'port' | 'url' | 'technology' | 'vulnerability';
  properties: Record<string, unknown>;
}

export interface GraphLink {
  source: string;
  target: string;
  type: string;
}

export interface GraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

// =============================================================================
// WebSocket Types
// =============================================================================

export type WSEventType =
  | 'connected'
  | 'disconnected'
  | 'error'
  | 'scan_started'
  | 'scan_progress'
  | 'scan_phase_changed'
  | 'scan_completed'
  | 'scan_failed'
  | 'asset_discovered'
  | 'vulnerability_found'
  | 'technology_detected'
  | 'system_notification';

export interface WSMessage {
  event: WSEventType;
  data: unknown;
  timestamp: string;
}

// =============================================================================
// Attack Path Types
// =============================================================================

export interface AttackPathNode {
  id: string;
  label: string;
  type: string;
  risk_score: number;
  properties: Record<string, unknown>;
}

export interface AttackPathEdge {
  source: string;
  target: string;
  type: string;
  cost: number;
  technique?: string;
  description?: string;
}

export interface AttackPath {
  path_id: string;
  name: string;
  source: AttackPathNode;
  target: AttackPathNode;
  nodes: AttackPathNode[];
  edges: AttackPathEdge[];
  total_cost: number;
  risk_level: 'critical' | 'high' | 'medium' | 'low';
  mitre_techniques: string[];
}

export interface ChokePoint {
  node_id: string;
  label: string;
  type: string;
  betweenness_score: number;
  paths_through: number;
}

// =============================================================================
// Identity Graph Types (BloodHound-style)
// =============================================================================

export type IdentityNodeType =
  | 'ADUser'
  | 'ADGroup'
  | 'ADComputer'
  | 'ADDomain'
  | 'ADOU'
  | 'ADGPO'
  | 'ADCertTemplate'
  | 'AzureUser'
  | 'AzureGroup'
  | 'AzureApp'
  | 'AzureRole'
  | 'AzureServicePrincipal';

export interface IdentityNode {
  id: string;
  label: string;
  type: IdentityNodeType;
  properties: Record<string, unknown>;
  is_high_value?: boolean;
  is_owned?: boolean;
  is_admin?: boolean;
}

export interface IdentityEdge {
  source: string;
  target: string;
  type: string;
}

export interface IdentityGraphData {
  nodes: IdentityNode[];
  edges: IdentityEdge[];
  domain_stats: DomainStats;
}

export interface DomainStats {
  users: number;
  groups: number;
  computers: number;
  domains: number;
  domain_admins: number;
  kerberoastable: number;
  asrep_roastable: number;
  unconstrained_delegation: number;
}

// =============================================================================
// Approval Queue Types (Human-in-the-Loop)
// =============================================================================

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low';
export type ApprovalStatus = 'pending' | 'approved' | 'denied' | 'expired';

export interface ApprovalRequest {
  approval_id: string;
  agent_id: string;
  agent_name: string;
  action: string;
  tool_name: string;
  tool_args: Record<string, unknown>;
  risk_level: RiskLevel;
  reason: string;
  status: ApprovalStatus;
  mitre_technique?: string;
  target_info?: string;
  created_at: string;
  expires_at: string;
  reviewed_by?: string;
  reviewed_at?: string;
}

// =============================================================================
// Mission Types
// =============================================================================

export type MissionStatus = 'created' | 'planning' | 'running' | 'paused' | 'completed' | 'failed' | 'cancelled';

export interface Mission {
  mission_id: string;
  project_id: string;
  name: string;
  objective: string;
  target: string;
  status: MissionStatus;
  current_phase: string;
  created_at: string;
  updated_at: string;
  started_at: string | null;
  completed_at: string | null;
  discovered_hosts_count: number;
  discovered_vulns_count: number;
  active_sessions_count: number;
  compromised_hosts_count: number;
}

export interface MissionPlan {
  plan_id: string;
  strategy: string;
  steps: MissionPlanStep[];
  estimated_time_minutes: number;
  risk_assessment: string;
}

export interface MissionPlanStep {
  step_id: string;
  description: string;
  tool_name: string;
  phase: string;
  risk_level: string;
  requires_approval: boolean;
}

export interface MissionCreateResponse {
  mission: Mission;
  plan: MissionPlan;
}

export interface MissionStepResponse {
  mission_id: string;
  phase: string | null;
  next_agent: string | null;
  discovered_hosts: number;
  discovered_vulns: number;
  active_sessions: number;
  pending_approvals: Record<string, unknown>[];
  status: string;
  error?: string;
}

export interface MissionEvent {
  event_id: string;
  mission_id: string;
  event_type: string;
  timestamp: string;
  agent_id: string;
  phase: string;
  summary: string;
  details: Record<string, unknown>;
}

// =============================================================================
// Agent / Chat Types
// =============================================================================

export interface AgentInfo {
  agent_id: string;
  agent_name: string;
  supported_phases: string[];
  available_tools: string[];
  status: string;
}

export interface ChatMessage {
  id: string;
  role: 'user' | 'assistant';
  content: string;
  timestamp: string;
  agent_id?: string;
  suggestions?: string[];
}

export interface ChatResponse {
  response: string;
  agent_id: string;
  suggestions: string[];
  actions_taken: Record<string, unknown>[];
}

// =============================================================================
// API Types
// =============================================================================

export interface APIError {
  code: string;
  message: string;
  details: Record<string, unknown>;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}

export interface HealthResponse {
  status: 'healthy' | 'unhealthy' | 'degraded';
  version: string;
  environment: string;
  timestamp: string;
  components: ComponentHealth[];
}

export interface ComponentHealth {
  name: string;
  status: 'healthy' | 'unhealthy' | 'degraded';
  latency_ms: number | null;
  message: string | null;
}
