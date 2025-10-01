#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pydantic model definitions for ReconAgent framework.
Defines type-safe, validated output schemas for each reconnaissance phase ensuring consistent result processing.
"""

from typing import List, Optional, Literal, Dict, Any, Union
from pydantic import BaseModel, Field


class UE_Format(BaseModel):
    line_no: int = Field(description="Line number in source data")
    url: str = Field(description="Target URL with potential vulnerability")
    category: Literal[
        "open_redirect", "idor_potential", "info_disclosure", "auth_bypass",
        "api_exposure", "admin_access", "file_exposure", "debug_mode",
        "config_leak", "ssrf_potential", "parameter_pollution", "misc"
    ] = Field(description="Vulnerability category classification")
    evidence: str = Field(description="Detailed vulnerability description")
    payload_example: str = Field(description="Concrete exploitation payload")
    exploitation_notes: str = Field(description="Step-by-step testing methodology")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    params: List[str] = Field(description="URL parameters involved", default_factory=list)
    endpoint_type: Literal["admin", "api", "auth", "file", "debug", "public", "unknown"] = Field(description="Endpoint classification")

class GD_SearchResult(BaseModel):
    google_dork: str = Field(description="Google Dork query used")
    website_url: str = Field(description="Search result URL")
    search_result: str = Field(description="Full search result content")
    title: str = Field(description="Search result title")
    snippet: str = Field(description="Matching snippet from search")
    position: int = Field(description="Position of the result in the search")
    triage: Literal["url", "file"] = Field(description="Result type classification: webpage or file")

class GD_URLAnalysis(BaseModel):
    google_dork: str = Field(description="Google Dork query used")
    website_url: str = Field(description="Analyzed page URL")
    category: Literal["XSS", "SQLi", "Open Redirect", "LFI", "RFI", "SSRF", "IDOR", "Information Disclosure", "Information", "Misc", "null"] = Field(description="Vulnerability category")
    evidence: str = Field(description="Evidence")
    endpoints: Optional[List[str]] = Field(default=None, description="Discovered endpoints")
    parameters: Optional[List[str]] = Field(default=None, description="URL parameters discovered")
    payload_example: Optional[str] = Field(default=None, description="Example exploitation payload")
    exploitation_notes: str = Field(description="Exploitation methodology")
    severity: Literal["critical", "high", "medium", "low", "informational"] = Field(description="Severity level")

class GH_SearchResult(BaseModel):
    file_name: str = Field(description="File name from GitHub")
    file_path: str = Field(description="Full file path in repository")
    file_type: str = Field(description="File extension")
    html_url: str = Field(description="GitHub web URL to view file")
    repository: str = Field(description="Full repository name (owner/repo)")
    repository_url: str = Field(description="Repository homepage URL")
    owner_type: str = Field(description="Owner type: User or Organization")
    score: float = Field(description="GitHub search relevance score")

class GH_Format(BaseModel):
    file_name: str = Field(description="File name from search result")
    file_path: str = Field(description="File path in repository")
    html_url: str = Field(description="GitHub web URL to file")
    repository: str = Field(description="Repository name (owner/repo)")
    category: Literal[
        "credential_exposure", "api_key_leak", "private_key", "database_config",
        "cloud_config", "environment_file", "recovery_codes", "webhook_url",
        "system_config", "development_artifact"
    ] = Field(description="Credential exposure category")
    evidence: str = Field(description="Detailed vulnerability description with masked sensitive content")
    payload_example: str = Field(description="Concrete exploitation approach or verification method")
    exploitation_notes: str = Field(description="Step-by-step verification methodology")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    verification_status: Literal["content_verified", "access_denied", "scraping_failed"] = Field(description="Content verification status: whether file content was successfully accessed for analysis")
    sensitive_data_type: Literal["credentials", "api_keys", "private_keys", "database_config", "cloud_config", "recovery_codes", "system_config", "webhook_urls", "other"] = Field(description="Specific type of sensitive data identified")

class JA_Format(BaseModel):
    file: str = Field(description="JavaScript filename")
    category: Literal["hardcoded_secret", "api_endpoint", "sensitive_info", "auth_logic", "error_exposure"] = Field(description="Type of security issue found")
    line_number: int = Field(description="Line number in the file")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    evidence: str = Field(description="Code snippet showing the vulnerability")
    description: str = Field(description="Detailed explanation of the finding")
    exploitation_potential: Literal["direct_access", "credential_theft", "information_disclosure", "authentication_bypass"] = Field(description="Potential exploitation impact")
    payload_example: str = Field(description="Concrete exploitation payload")
    exploitation_notes: str = Field(description="Step-by-step testing methodology")


class SecurityIncident(BaseModel):
    title: str = Field(description="Title of the security incident")
    source: str = Field(description="Source URL or site where incident was reported")
    source_language: Literal["english", "korean", "japanese", "chinese", "german", "french", "other"] = Field(description="Language of the source")
    date: Optional[str] = Field(default=None, description="Date of the incident")
    summary: str = Field(description="Brief summary of the incident")
    incident_type: Literal["data_breach", "system_compromise", "service_disruption", "credential_leak"] = Field(description="Type of security incident")
    affected_data: str = Field(description="Description of compromised data")
    impact_scope: str = Field(description="Number of affected users or scale of impact")

class Vulnerability(BaseModel):
    title: str = Field(description="Title of the vulnerability")
    source: str = Field(description="Source URL or site")
    source_language: Literal["english", "korean", "japanese", "chinese", "german", "french", "other"] = Field(description="Language of the source")
    date: Optional[str] = Field(default=None, description="Date of vulnerability disclosure")
    summary: str = Field(description="Brief summary of the vulnerability")
    severity: Literal["critical", "high", "medium", "low"] = Field(description="Severity level of the vulnerability")
    vulnerability_type: Literal["sqli", "xss", "rce", "idor", "ssrf", "authentication_bypass", "other"] = Field(description="Type of vulnerability")
    cve_id: Optional[str] = Field(default=None, description="CVE identifier if available")
    bounty_amount: Optional[str] = Field(default=None, description="Bug bounty amount if disclosed")
    researcher: Optional[str] = Field(default=None, description="Security researcher who discovered it")
    patch_status: Literal["patched", "unpatched", "unknown"] = Field(description="Current patch status")

class NewFeature(BaseModel):
    title: str = Field(description="Title of the new feature")
    description: str = Field(description="Brief summary of the feature")
    date: str = Field(description="Release date in YYYY-MM-DD format")
    source: str = Field(description="Source URL")
    source_language: Literal["english", "korean", "japanese", "chinese", "german", "french", "other"] = Field(description="Language of the source")
    feature_type: Literal["new_endpoint", "ui_change", "api_update", "security_feature", "infrastructure_change"] = Field(description="Type of feature")
    attack_surface_change: Literal["increased", "decreased", "unchanged"] = Field(description="Change in attack surface")
    attack_vectors: List[str] = Field(description="List of potential attack methods")

class TI_Incident_Format(BaseModel):
    """Output format for TI_incident task"""
    incidents: List[SecurityIncident] = Field(default_factory=list, description="List of security incidents")

class TI_Vulnerability_Format(BaseModel):
    """Output format for TI_known_vuln task"""
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="List of known vulnerabilities")

class TI_NewFeature_Format(BaseModel):
    """Output format for TI_new_feature task"""
    new_features: List[NewFeature] = Field(default_factory=list, description="List of new features")

class TI_Format(BaseModel):
    """Aggregated threat intelligence from all Phase 5 tasks"""
    incidents: List[SecurityIncident] = Field(default_factory=list, description="Security incidents from TI_incident task")
    vulnerabilities: List[Vulnerability] = Field(default_factory=list, description="Known vulnerabilities from TI_known_vuln task")
    new_features: List[NewFeature] = Field(default_factory=list, description="Recent features from TI_new_feature task")
    overall_risk_score: Optional[Literal["critical", "high", "medium", "low"]] = Field(default=None, description="Overall risk assessment based on all findings")
    priority_findings: List[str] = Field(default_factory=list, description="Top priority findings requiring immediate attention")
    recommended_actions: List[str] = Field(default_factory=list, description="Recommended security actions based on threat intelligence")

class SSLCertificateDetail(BaseModel):
    subject: Dict[str, str] = Field(description="Certificate subject information")
    issuer: Dict[str, str] = Field(description="Certificate issuer information")
    valid_from: str = Field(description="Certificate valid from date")
    valid_to: str = Field(description="Certificate valid to date")
    fingerprint: str = Field(description="SHA1 fingerprint")
    fingerprint256: str = Field(description="SHA256 fingerprint")
    subjectaltname: str = Field(description="Subject Alternative Names")
    bits: int = Field(description="Key size in bits")
    ext_key_usage: List[str] = Field(description="Extended key usage", default_factory=list)

class DNSRecordDetail(BaseModel):
    A: Optional[Dict[str, Any]] = Field(default=None, description="A record information")
    AAAA: List[str] = Field(description="AAAA records", default_factory=list)
    MX: List[str] = Field(description="MX records", default_factory=list)
    TXT: List[str] = Field(description="TXT records", default_factory=list)
    NS: List[str] = Field(description="NS records", default_factory=list)
    CNAME: List[str] = Field(description="CNAME records", default_factory=list)
    SOA: List[str] = Field(description="SOA records", default_factory=list)
    SRV: List[str] = Field(description="SRV records", default_factory=list)
    PTR: List[str] = Field(description="PTR records", default_factory=list)

class DNSSECDetail(BaseModel):
    dnskey_found: bool = Field(description="DNSKEY record found")
    ds_found: bool = Field(description="DS record found")
    rrsig_found: bool = Field(description="RRSIG record found")
    validation_status: Literal["signed", "unsigned", "error"] = Field(description="DNSSEC validation status")

class ThreatIntelDetail(BaseModel):
    phish_tank_status: Literal["clean", "malicious", "unknown", "error"] = Field(description="PhishTank verification status")
    blocklist_checks: Dict[str, bool] = Field(description="Blocklist verification results", default_factory=dict)
    url_haus_status: Literal["clean", "malicious", "unknown", "error"] = Field(description="URLHaus verification status")

class ArchiveHistoryDetail(BaseModel):
    first_scan: str = Field(description="First archive scan date")
    last_scan: str = Field(description="Last archive scan date")
    total_scans: int = Field(description="Total number of scans")
    change_count: int = Field(description="Number of changes detected")
    average_page_size: int = Field(description="Average page size in KB")
    scan_frequency: Dict[str, float] = Field(description="Scanning frequency statistics", default_factory=dict)

class SocialMetaDetail(BaseModel):
    title: Optional[str] = Field(default=None, description="Page title")
    description: Optional[str] = Field(default=None, description="Page description")
    og_title: Optional[str] = Field(default=None, description="OpenGraph title")
    og_description: Optional[str] = Field(default=None, description="OpenGraph description")
    og_image: Optional[str] = Field(default=None, description="OpenGraph image URL")
    og_url: Optional[str] = Field(default=None, description="OpenGraph URL")
    twitter_card: Optional[str] = Field(default=None, description="Twitter card type")

class GeneralSecurityFinding(BaseModel):
    finding_type: Literal["security_misconfiguration", "missing_security_control", "ssl_issue", "hsts_issue"] = Field(description="Type of security finding")
    component: Literal["http_security", "hsts", "ssl", "tls_cipher_suites", "tls_security_config", "firewall"] = Field(description="Security component")
    title: str = Field(description="Concise title of the security finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the security issue")
    evidence: str = Field(description="Specific evidence from webcheck data")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Potential attack vectors enabled")
    compliance_impact: str = Field(description="Security compliance implications")
    ssl_details: Optional[SSLCertificateDetail] = Field(default=None, description="SSL certificate details if applicable")

class WC_Finding(BaseModel):
    """Base class for discriminated union of all finding types"""
    title: str = Field(description="Concise title of the finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the issue")
    evidence: str = Field(description="Specific evidence from webcheck data")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Potential attack vectors enabled")
    compliance_impact: str = Field(description="Security compliance implications")

class DNSFinding(WC_Finding):
    finding_category: Literal["dns_domain"] = Field(default="dns_domain", description="DNS/Domain finding category")
    finding_type: Literal["dns_misconfiguration", "missing_dnssec", "dns_exposure"] = Field(description="Type of DNS finding")
    component: Literal["dns", "dnssec", "dns_server", "whois", "txt_records"] = Field(description="DNS component")
    title: str = Field(description="Concise title of the DNS finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the DNS issue")
    evidence: str = Field(description="Specific evidence from DNS analysis")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="DNS-related attack vectors")
    compliance_impact: str = Field(description="DNS security compliance impact")
    dns_details: Optional[DNSRecordDetail] = Field(default=None, description="DNS record details if applicable")
    dnssec_details: Optional[DNSSECDetail] = Field(default=None, description="DNSSEC details if applicable")

class InfrastructureFinding(WC_Finding):
    finding_category: Literal["infrastructure"] = Field(default="infrastructure", description="Infrastructure finding category")
    finding_type: Literal["infrastructure_exposure", "service_enumeration", "tech_stack_disclosure"] = Field(description="Type of infrastructure finding")
    component: Literal["headers", "ports", "tech_stack", "server_info", "location"] = Field(description="Infrastructure component")
    title: str = Field(description="Concise title of the infrastructure finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the infrastructure issue")
    evidence: str = Field(description="Specific evidence from infrastructure analysis")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Infrastructure-related attack vectors")
    compliance_impact: str = Field(description="Infrastructure compliance impact")
    open_ports: Optional[List[int]] = Field(default=None, description="List of open ports if applicable")
    server_headers: Optional[Dict[str, str]] = Field(default=None, description="Server headers if applicable")

class ContentFinding(WC_Finding):
    finding_category: Literal["content_discovery"] = Field(default="content_discovery", description="Content discovery finding category")
    finding_type: Literal["content_disclosure", "missing_security_policy", "information_leakage"] = Field(description="Type of content finding")
    component: Literal["robots_txt", "sitemap", "security_txt", "linked_pages", "social_tags"] = Field(description="Content component")
    title: str = Field(description="Concise title of the content finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the content issue")
    evidence: str = Field(description="Specific evidence from content analysis")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Content-related attack vectors")
    compliance_impact: str = Field(description="Content security compliance impact")
    social_meta: Optional[SocialMetaDetail] = Field(default=None, description="Social media metadata if applicable")

class ThreatFinding(WC_Finding):
    finding_category: Literal["threat_intel"] = Field(default="threat_intel", description="Threat intelligence finding category")
    finding_type: Literal["threat_reputation", "blocklist_status", "historical_analysis"] = Field(description="Type of threat finding")
    component: Literal["cookies", "threats", "block_lists", "archives"] = Field(description="Threat component")
    title: str = Field(description="Concise title of the threat finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the threat assessment")
    evidence: str = Field(description="Specific evidence from threat analysis")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Threat-related attack vectors")
    compliance_impact: str = Field(description="Threat compliance impact")
    threat_intel: Optional[ThreatIntelDetail] = Field(default=None, description="Threat intelligence details if applicable")
    archive_history: Optional[ArchiveHistoryDetail] = Field(default=None, description="Historical archive data if applicable")

class SecurityFinding(WC_Finding):
    finding_category: Literal["security"] = Field(default="security", description="Security finding category")
    finding_type: Literal["security_misconfiguration", "missing_security_control", "ssl_issue", "hsts_issue"] = Field(description="Type of security finding")
    component: Literal["http_security", "hsts", "ssl", "tls_cipher_suites", "tls_security_config", "firewall"] = Field(description="Security component")
    title: str = Field(description="Concise title of the security finding")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the security issue")
    evidence: str = Field(description="Specific evidence from webcheck data")
    remediation: str = Field(description="Recommended remediation steps")
    webcheck_source: str = Field(description="Source endpoint from webcheck")
    attack_vector: str = Field(description="Potential attack vectors enabled")
    compliance_impact: str = Field(description="Security compliance implications")
    ssl_details: Optional[SSLCertificateDetail] = Field(default=None, description="SSL certificate details if applicable")

class WC_Format(BaseModel):
    findings: List[Union[SecurityFinding, DNSFinding, InfrastructureFinding, ContentFinding, ThreatFinding]] = Field(
        description="List of categorized security findings from webcheck analysis"
    )

class OT_Format(BaseModel):
    platform: Literal["zoomeye", "urlscan", "fofa"] = Field(description="OSINT platform source of the finding")
    asset_type: Literal["subdomain", "ip_address", "service", "certificate", "vulnerability", "infrastructure", "network_info", "threat_indicator"] = Field(description="Type of asset or finding discovered")
    title: str = Field(description="Concise title of the OSINT finding")
    target: str = Field(description="Specific target (IP, domain, service) identified")
    severity: Literal["critical", "high", "medium", "low", "info"] = Field(description="Risk severity level")
    description: str = Field(description="Detailed description of the OSINT finding")
    evidence: str = Field(description="Specific evidence from platform data")
    exploitation_potential: Literal["immediate_access", "reconnaissance_value", "attack_surface_expansion", "threat_intelligence"] = Field(description="Exploitation or intelligence value")
    attack_vectors: str = Field(description="Potential attack vectors enabled by this finding")
    remediation_priority: Literal["immediate", "high", "medium", "low"] = Field(description="Recommended remediation priority")
    cross_platform_correlation: str = Field(description="Correlation with findings from other OSINT platforms")