export interface ThreatIntelOverview {
  total_cves: number
  kev_count: number
  avg_epss: number
  exposure_count: number
  severity_distribution: {
    critical: number
    high: number
    medium: number
    low: number
    informational: number
  }
}

export interface VulnFinding {
  finding_uid: string
  finding_title: string
  severity_id: number
  status: string
  provider: string
  vuln_uid: string
  vuln_title: string
  vuln_severity: string
  cvss_score: number
  epss_score: number
  is_exploited: boolean
}

export interface TechniqueCoverage {
  uid: string
  name: string
  finding_count: number
}

export interface TacticCoverage {
  uid: string
  name: string
  finding_count: number
  techniques: TechniqueCoverage[]
}

export interface AttackCoverage {
  tactics: TacticCoverage[]
  count: number
}

export interface CVEEntry {
  cve_id: string
  cvss_score: number
  epss_score: number
  is_exploited: boolean
  severity: string
  title: string
  affected_count: number
}

export interface ExposedResource {
  resource_uid: string
  resource_type: string
  resource_name: string
  provider: string
  endpoint: string
  protocol: string
  port: number
  is_public: boolean
}
