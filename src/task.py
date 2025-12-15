#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Task definitions for ReconAgent framework.
Defines sequential pipeline of 20+ CrewAI tasks across 8 phases for OSINT reconnaissance and vulnerability assessment.
"""

import os
from datetime import datetime, timedelta, timezone

import tldextract
from crewai import Task
from crewai_tools import DirectoryReadTool, FileReadTool, SerperDevTool, ScrapeWebsiteTool, FileWriterTool

from custom_tools.url_enum.fetcher_tool import URLFetcherTool
from custom_tools.url_enum.distiller_tool import URLDistillerTool
from custom_tools.url_enum.validator_tool import URLValidatorTool
from custom_tools.google_dork.file_fetch_tool import FileFetchTool
from custom_tools.github_dork.github_tool import GitHubDorkingTool
from custom_tools.js_analysis.js_collector_tool import JavaScriptCollectorTool
from custom_tools.js_analysis.nuclei_scanner_tool import NucleiScannerTool
from custom_tools.js_analysis.noir_scanner_tool import NoirScannerTool
from custom_tools.infra.webcheck_tool import WebCheckTool
from custom_tools.osint.zoomeye_tool import ZoomEyeOSINTTool
from custom_tools.osint.urlscan_tool import URLScanTool
from custom_tools.osint.fofa_tool import FOFASearchTool

from src.agent import phase1_url_analyst, phase2_dorking_specialist, phase3_github_researcher, phase4_javascript_auditor, phase5_threat_researcher, phase6_infrastructure_analyst, phase7_osint_integrator

today = datetime.now(timezone.utc)

DATE_30D_AGO = (today - timedelta(days=30)).strftime("%Y-%m-%d")
TARGET = os.getenv("TARGET")
extracted = tldextract.extract(TARGET)
ROOT_TARGET = f"{extracted.domain}.{extracted.suffix}"

RESULT_DIR = os.getenv("RESULT_DIR") or f"results/{TARGET}"

from src.models import UE_Format, GD_SearchResult, GD_URLAnalysis, GH_SearchResult, GH_Format, JA_Format, TI_Format, TI_Incident_Format, TI_Vulnerability_Format, TI_NewFeature_Format, WC_Format, OT_Format

UE_fetch_urls = Task(
    name="fetch_urls",
    agent=phase1_url_analyst,
    description=f"[1-1] Fetch URLs for {TARGET} using URLFetcherTool",
    expected_output="URL collection success status",
    tools=[URLFetcherTool()],
)

UE_distill_urls = Task(
    name="classify_urls",
    agent=phase1_url_analyst,
    description=f"[1-2] Classify fetched URLs for {TARGET} using URLDistillerTool",
    expected_output="URL classification success status",
    tools=[URLDistillerTool()],
    context=[UE_fetch_urls]
)

# Optional: URL validation task (can be skipped with --skip-validation)
UE_validate_urls = Task(
    name="validate_urls",
    agent=phase1_url_analyst,
    description=f"""[1-3] Validate collected URLs for {TARGET} using URLValidatorTool.

        This task checks which URLs are currently alive by sending HTTP requests.
        Only URLs with 2xx/3xx status codes will be included in alive_urls.txt.

        Output files:
        • alive_urls.txt - URLs that responded with success status
        • validated_urls.json - Detailed validation results with status codes
    """,
    expected_output="URL validation statistics (total, alive, dead counts)",
    tools=[URLValidatorTool()],
    context=[UE_distill_urls]
)

UE_analysis = Task(
    name="scan_urls",
    agent=phase1_url_analyst,
    description=f"""[1-4] Analyze collected URLs and identify ALL potential attack vectors.

        Analysis items:
        • ADMINISTRATIVE & DEBUG ENDPOINTS: Admin interfaces, Debug endpoints, Monitoring, Documentation
        • API & SERVICE ENDPOINTS: REST APIs, GraphQL, Webhooks, Versioned APIs
        • AUTHENTICATION & AUTHORIZATION: Auth bypasses, Login endpoints, User context, Session handling
        • SENSITIVE PARAMETERS: IDOR potential, Open redirects, File operations, SSRF vectors
        • INFORMATION DISCLOSURE: Error pages, Backup files, Config files, Log files
        • WELL-KNOWN & DISCOVERY: Security info, OpenID, Metadata
        • FILE EXTENSIONS & TECHNOLOGY: Database, Config, Source code, Archives

        Use FileReadTool to analyze the alive URLs:
        {{
            "file_path": "results/{TARGET}/phase1/url/alive_urls.txt",
            "start_line": 1,
            "line_count": null
        }}

        Additionally, read parameter vulnerability hints for prioritized analysis:
        {{
            "file_path": "results/{TARGET}/phase1/pattern/param_hints.json"
        }}

        Use param_hints.json to identify high-risk parameters:
        • open_redirect: Parameters that may allow URL redirection attacks
        • ssrf: Parameters that may enable server-side request forgery
        • lfi: Parameters that may allow local file inclusion
        • sqli: Parameters that may be vulnerable to SQL injection
        • idor: Parameters that may enable insecure direct object references
        • xss: Parameters that may allow cross-site scripting
        • auth: Parameters related to authentication/authorization

    """,
    expected_output="A JSON object with 'findings' array containing objects with 'line_no', 'url', 'category' (array of vulnerability types), 'evidence', 'payload_example', 'exploitation_notes', 'severity', 'params', and 'endpoint_type' fields.",
    tools=[FileReadTool(file_path=f"{RESULT_DIR}/phase1/url/alive_urls.txt"), FileReadTool(file_path=f"{RESULT_DIR}/phase1/pattern/param_hints.json")],
    context=[UE_validate_urls],
    output_json=UE_Format,
)

UE_result = Task(
    name="save_attack_vectors",
    agent=phase1_url_analyst,
    description=f"""[1-5] Save URL Enumeration analysis results for {TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p1_attack_vector.json"
          "directory": "{RESULT_DIR}/phase1"
        }}

        """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[UE_analysis]
)

GD_dorking = Task(
    name="google_dorking",
    agent=phase2_dorking_specialist,
    description=f"""[2-1] Execute comprehensive Google Dorking for {TARGET} and classify results.

        Query sequence (execute all 15 queries):
        1. site:{TARGET} (intitle:"index of /" | intitle:"docker-compose.yml" | intitle:".env" | intitle:"config.yml" | intitle:".git" | intitle:"package.json" | intitle:"requirements.txt" | intitle:".gitignore" | intitle:"IIS Windows Server")
        2. site:{TARGET} (ext:pdf | ext:doc | ext:docx | ext:xls | ext:xlsx | ext:csv | ext:ppt | ext:pptx | ext:txt | ext:rtf | ext:odt) ("INTERNAL USE ONLY" | "INTERNAL ONLY" | "TRADE SECRET" | "NOT FOR DISTRIBUTION" | "NOT FOR PUBLIC RELEASE" | "EMPLOYEE ONLY")
        3. site:{TARGET} (ext:csv | ext:txt | ext:json | ext:xlsx | ext:xls | ext:sql | ext:log) (intext:"id" | intext:"uid" | intext:"uuid" | intext:"username" | intext:"password" | intext:"userid" | intext:"email" | intext:"ssn" | intext:"phone" | intext:"date of birth" | intext:"Social Security Number" | intext:"credit card" | intext:"CCV" | intext:"CVV" | intext:"card number")
        4. site:{TARGET} (inurl:action | inurl:page | inurl:pid | inurl:uid | inurl:id | inurl:search | inurl:cid | inurl:idx | inurl:no | inurl:/graphql | inurl:/swagger)
        5. site:{TARGET} (ext:yaml | ext:yml | ext:ini | ext:conf | ext:config | ext:log | ext:pdf) (intext:"token" | intext:"access_token" | intext:"api_key" | intext:"private_key" | intext:"secret")
        6. site:{TARGET} (inurl:/download.jsp | inurl:/downloads.jsp | inurl:/upload.jsp) | inurl:/uploads.jsp | inurl:/download.php | inurl:/downloads.php | inurl:/upload.php) | inurl:/uploads.php)
        7. site:{TARGET} (inurl:index.php?page | inurl:file | inurl:inc | inurl:layout | inurl:template | inurl:content | inurl:module | inurl:admin | inurl:administrator | inurl:wp-login)
        8. site:{TARGET} (ext:pdf | ext:doc | ext:docx | ext:ppt | ext:pptx) (intext:"join.slack" | intext:"t.me" | intext:"trello.com/invite" | intext:"notion.so" | intext:"atlassian.net" | intext:"asana.com" | intext:"teams.microsoft.com" | intext:"zoom.us/j" | intext:"bit.ly")
        9. site:{TARGET} (inurl:url= | inurl:continue= | inurl:redirect | inurl:return | inurl:target | inurl:site= | inurl:view= | inurl:path | inurl:returl= | inurl:next= | inurl:fallback= | inurl:u= | inurl:goto= | inurl:link=)
        10. (site:*.s3.amazonaws.com | site:*.s3-external-1.amazonaws.com | site:*.s3.dualstack.us-east-1.amazonaws.com | site:*.s3.ap-south-1.amazonaws.com) "{TARGET}"
        11. site:{TARGET} inurl:eyJ (inurl:token | inurl:jwt | inurl:access | inurl:auth | inurl:authorization | inurl:secret)
        12. site:{TARGET} inurl:api (inurl:/v1/ | inurl:/v2/ | inurl:/v3/ | inurl:/v4/ | inurl:/v5/ | inurl:/rest)
        13. site:{TARGET} inurl:"error" | intitle:"exception" | intitle:"failure" | intitle:"server at" | inurl:exception | "database error" | "SQL syntax" | "undefined index" | "unhandled exception" | "stack trace"
        14. site:openbugbounty.org inurl:reports intext:"{TARGET}"
        15. (site:groups.google.com | site:googleapis.com | site:drive.google.com | site:dropbox.com | site:box.com | site:onedrive.live.com | site:firebaseio.com) "{TARGET}"

        triage classification:
        • url: Web pages, APIs, endpoints
        • file: Downloadable documents (pdf, docx, xlsx, csv, txt, sql, log, etc.)
        
        """,
    expected_output="Google Dorking results ('title', 'link', 'snippet', 'position', 'triage')",
    tools=[SerperDevTool()],
    output_json=GD_SearchResult
)

GD_url_analysis = Task(
    name="analyze_search_results",
    agent=phase2_dorking_specialist,
    description=f"""[2-2] Analyze only results with triage=url from Google Dorking results.

        Extract critical security information from each URL:
        • Discovered endpoints and API paths
        • Form elements and input fields for injection testing
        • URL parameters and query strings
        • Directory listings and exposed paths
        • Error messages and debug information

        Analyze technical stack and configuration:
        • Detect technologies (frameworks, libraries, servers)
        • Check security headers (X-Frame-Options, CSP, CORS)
        • Identify authentication/session mechanisms
        • Find JavaScript files and external resources
        • Detect client-side routing patterns

        Look for sensitive information:
        • Hardcoded credentials or API keys
        • Internal network information
        • Development/staging URLs
        • Comments with sensitive data
        • Exposed configuration files

    """,
    expected_output="A JSON object with 'google_dork', 'website_url', 'category', 'evidence', 'endpoints', 'parameters', 'payload_example', 'exploitation_notes', 'severity' fields.",
    tools=[ScrapeWebsiteTool()],
    context=[GD_dorking],
    output_json=GD_URLAnalysis,
)

GD_file_download = Task(
    name="download_files",
    agent=phase2_dorking_specialist,
    description=f"""[2-3] Download files identified from Google dorking results.

        Use FileFetchTool to download files:
        • Input: URLs from dorking results with triage=file
        • Output: results/{TARGET}/phase2/files/<extracted_filename>
        • Attempt download for all file URLs

    """,
    expected_output="File download status and relative paths",
    tools=[FileFetchTool()],
    context=[GD_dorking],
)

GD_file_analysis = Task(
    name="analyze_files",
    agent=phase2_dorking_specialist,
    description=f"""[2-4] Analyze downloaded files for sensitive information.

        File type analysis strategy:
        1. Text files (.txt, .csv, .json, .log, .sql, .xml, .conf, .ini, .yaml):
           Use FileReadTool to analyze the attack vectors:
            {{
                "file_path": "results/{TARGET}/phase2/files/<extracted_filename>",
                "start_line": 1,
                "line_count": null
            }}    

        2. Binary files (.xlsx, .xlsm, .xls, .pdf, .doc, .docx, .ppt, .pptx):
           Use DirectoryReadTool to analyze only filenames and metadata

        Analysis items:
        • Metadata (author, creation date, software...) - extracted from filename
        • Exposed credentials or API keys
        • Internal network information
        • Employee names and contact details
        • System configuration details
        • Database connection strings
        • Hardcoded secrets or passwords
        • PII (emails, phone numbers, SSNs)
        • Comments with sensitive data
        • Other sensitive information as needed

    """,
    expected_output="A JSON object with 'google_dork', 'website_url', 'filename', 'category', 'evidence', 'metadata', 'exploitation_notes', 'potential_impact', 'severity')",
    tools=[FileReadTool(), DirectoryReadTool(directory=f"{RESULT_DIR}/phase2/files/")],
    context=[GD_file_download],
)

GD_result = Task(
    name="integrate_dorking_analysis",
    agent=phase2_dorking_specialist,
    description=f"""[2-5] Save Google Dorking analysis results for {TARGET} as structured attack vectors in JSON

        Combine results from both analysis tasks (url, file) into unified output.

        Use FileWriterTool to save:
        {{
          "filename": "p2_attack_vector.json"
          "directory": "{RESULT_DIR}/phase2"
        }}

    """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[GD_url_analysis, GD_file_analysis],
)

GH_dorking = Task(
    name="github_dorking_credentials",
    agent=phase3_github_researcher,
    description=f"""[3-1] Execute GitHub Dork queries for {TARGET} using GitHubDorkingTool.""",
    expected_output=f"""JSON object containing search results with repository metadata and file information""",
    tools=[GitHubDorkingTool()],
    output_json=GH_SearchResult,
)

GH_analysis = Task(
    name="github_results_analysis",
    agent=phase3_github_researcher,
    description=f"""[3-2] Analyze Github Dorking results for {TARGET} reconnaissance.

        Analysis items:
        • API key exposures: Live service API keys, OAuth tokens, JWT secrets
        • Database credentials: Connection strings, passwords, database URLs
        • Cloud access keys: AWS, Azure, GCP credentials with active permissions
        • Private keys: SSH keys, TLS certificates, signing keys
        • Infrastructure secrets: CI/CD tokens, webhook URLs, service credentials
        • Environment files: .env, configuration files, deployment configs
        • Recovery mechanisms: 2FA backup codes, recovery keys, reset tokens
        • System configuration: Database settings, service endpoints, internal URLs
        • Development tools: IDE configs, deployment scripts, internal tools

    """,
    expected_output="A JSON object with 'file_name', 'file_path', 'html_url', 'repository', 'category', 'evidence', 'payload_example', 'exploitation_notes', 'severity', 'verification_status', 'sensitive_data_type' fields.",
    tools=[ScrapeWebsiteTool()],
    context=[GH_dorking],
    output_json=GH_Format,
)

GH_result = Task(
    name="save_github_intelligence",
    agent=phase3_github_researcher,
    description=f"""[3-3] Save Github Dorking analysis results for {TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p3_attack_vector.json"
          "directory": "{RESULT_DIR}/phase3"
        }}

    """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[GH_analysis]
)

JA_collect = Task(
    name="collect_javascript",
    agent=phase4_javascript_auditor,
    description=f"""[4-1] Collect and download JavaScript files from {TARGET} using JavaScriptCollectorTool.""",
    expected_output="JSON with collection statistics (Phase1 URLs, Playwright URLs, downloaded files count)",
    tools=[JavaScriptCollectorTool()],
)

JA_nuclei_scan = Task(
    name="scan_javascript_with_nuclei",
    agent=phase4_javascript_auditor,
    description=f"""[4-2] Scan JavaScript URLs with Nuclei regex-based pattern matching using NucleiScannerTool.""",
    expected_output="JSON with Nuclei scan results",
    tools=[NucleiScannerTool()],
    context=[JA_collect]
)

JA_noir_scan = Task(
    name="scan_javascript_with_noir",
    agent=phase4_javascript_auditor,
    description=f"""[4-3] Scan JavaScript files with OWASP NOIR AST-based analysis using NoirScannerTool.""",
    expected_output="JSON with NOIR scan results",
    tools=[NoirScannerTool()],
    context=[JA_collect]
)

JA_analysis = Task(
    name="analyze_and_validate_findings",
    agent=phase4_javascript_auditor,
    description=f"""[4-4] Analyze and validate findings from Nuclei and NOIR scans for {TARGET}.

    Use FileReadTool to read scan results:
    {{
        "file_path": "{RESULT_DIR}/phase4/js_nuclei.json"
    }}
    {{
        "file_path": "{RESULT_DIR}/phase4/js_noir.json"
    }}

    For each finding:
    1. Read the specific file and line number mentioned in the scan result
    2. Examine surrounding context (10 lines before/after)
    3. Validate if it's a true positive or false positive
    4. Extract evidence and assess severity
    5. Generate exploitation notes and payload examples

    Analysis criteria:
    • Verify hardcoded secrets are actual credentials, not examples/placeholders
    • Confirm API endpoints are production, not test/mock endpoints
    • Assess exploitability and business impact
    • Filter out common false positives

    """,
    expected_output="A JSON object with 'file', 'category', 'line_number', 'severity', 'evidence', 'description', 'exploitation_potential', 'payload_example', and 'exploitation_notes' fields.",
    tools=[FileReadTool()],
    context=[JA_nuclei_scan, JA_noir_scan],
    output_json=JA_Format,
)

JA_result = Task(
    name="save_javascript_analysis",
    agent=phase4_javascript_auditor,
    description=f"""[4-5] Save Javascript Analysis results for {TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p4_attack_vector.json"
          "directory": "{RESULT_DIR}/phase4"
        }}

        """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[JA_analysis]
)

TI_incident = Task(
    name="search_security_incidents",
    agent=phase5_threat_researcher,
    description=f"""[5-1] Search for security incidents where {ROOT_TARGET} is specifically the victim or affected party.

        METHODOLOGY:

        Step 1: Domain localization analysis
        • Analyze {ROOT_TARGET} domain to determine primary operating countries and languages
        • Consider domain TLD (.kr=Korean, .jp=Japanese, .cn=Chinese, .de=German, .fr=French, etc.)
        • Consider company origin, primary markets, and regional news coverage
        • Generate appropriate localized keywords for security incidents

        Step 2: Multi-language incident search
        • Execute searches in both English and identified local languages

        Step 3: Result aggregation and validation
        • Combine results from English and localized searches
        • Cross-reference incidents found in multiple language sources

    """,
    expected_output="A JSON object with 'incidents' field containing a list of security incidents.",
    tools=[SerperDevTool()],
    output_json=TI_Incident_Format,
)

TI_known_vuln = Task(
    name="search_vulnerability_intelligence",
    agent=phase5_threat_researcher,
    description=f"""[5-2] Search for CVEs and vulnerabilities where {ROOT_TARGET} is explicitly the affected vendor/product.

        METHODOLOGY:

        Step 1: Domain localization analysis
        • Analyze {ROOT_TARGET} domain to determine primary operating countries and languages
        • Consider domain TLD (.kr=Korean, .jp=Japanese, .cn=Chinese, .de=German, .fr=French, etc.)
        • Consider company origin, primary markets, and regional vulnerability disclosure practices
        • Generate appropriate localized keywords for vulnerabilities and security research terms

        Step 2: Multi-language vulnerability search
        • Execute searches in both English and identified local languages

        Step 3: Result aggregation and validation
        • Combine results from English and localized searches
        • Cross-reference vulnerabilities found in multiple language sources

        CVE VALIDATION REQUIREMENTS:
        • CVE must explicitly list {ROOT_TARGET} as the vendor or affected product
        • Extract ACTUAL vulnerability description from CVE database
        • Include CVSS score and affected components
        • Verify CVE ID is valid (not future dated or malformed)
        • If no valid CVEs found: return {{"vulnerabilities": []}}

    """,
    expected_output="A JSON object with 'vulnerabilities' field containing a list of known vulnerabilities.",
    tools=[SerperDevTool()],
    output_json=TI_Vulnerability_Format,
)

TI_new_feature = Task(
    name="search_recent_features",
    agent=phase5_threat_researcher,
    description=f"""[5-3] Search for features released in 2025 from {ROOT_TARGET}, focusing on security impacts and attack vectors.

        METHODOLOGY:

        Step 1: Domain localization analysis
        • Analyze {ROOT_TARGET} domain to determine primary operating countries and languages
        • Consider domain TLD (.kr=Korean, .jp=Japanese, .cn=Chinese, .de=German, .fr=French, etc.)
        • Consider company origin, primary markets, and service regions
        • Generate appropriate localized keywords for "new feature", "security", "announcement", "beta", "API" etc.

        Step 2: Multi-language search execution
        • Execute searches in both English and identified local languages

        Step 3: Result aggregation and analysis
        • Combine results from English and localized searches
        • Cross-reference features found in multiple language sources

        ATTACK VECTOR ANALYSIS REQUIREMENTS:
        • Identify NEW attack surfaces introduced by features
        • Assess API endpoints, authentication changes, file upload capabilities
        • Evaluate permission model changes and access control modifications
        • Analyze client-side features for XSS, CSRF, or data exposure risks
        • Check for new third-party integrations or external dependencies

        DATE VALIDATION REQUIREMENTS:
        • Features must be from 2025 or have verifiable recent dates
        • EXCLUDE any features older than current year unless still in active development
        • If date is unclear or missing, EXCLUDE the feature
        • If no recent features found: return {{"new_features": []}}

    """,
    expected_output="A JSON object with 'new_features' field containing a list of new features.",
    tools=[SerperDevTool()],
    output_json=TI_NewFeature_Format,
)

TI_analysis = Task(
    name="aggregate_threat_intelligence",
    agent=phase5_threat_researcher,
    description=f"""[5-4] Aggregate and synthesize all threat intelligence findings for {ROOT_TARGET}.
    
        Analysis items:
        • Security incidents and breaches from TI_incident task
        • Known vulnerabilities and CVEs from TI_known_vuln task  
        • Recent features and changes from TI_new_feature task

    """,
    expected_output="A JSON object with 'incidents', 'vulnerabilities', 'new_features', 'overall_risk_score', 'priority_findings', and 'recommended_actions' fields.",
    context=[TI_incident, TI_known_vuln, TI_new_feature],
    output_json=TI_Format,
)

TI_result = Task(
    name="save_threat_intelligence",
    agent=phase5_threat_researcher,
    description=f"""[5-5] Save Threat Intelligence analysis results for {ROOT_TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p5_attack_vector.json"
          "directory": "{RESULT_DIR}/phase5"
        }}
    
    """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[TI_analysis]
)

WC_fingerprint = Task(
    name="fingerprint_infrastructure",
    agent=phase6_infrastructure_analyst,
    description=f"[6-1] Comprehensive infrastructure fingerprinting for {TARGET} using WebCheckTool.",
    expected_output="Infrastructure fingerprinting results including technology stack and configuration details",
    tools=[WebCheckTool()],
)

WC_analysis = Task(
    name="review_infrastructure_security",
    agent=phase6_infrastructure_analyst,
    description=f"""[6-2] Analyze comprehensive 25-endpoint webcheck results for categorized security findings using the new structured model.

        Use FileReadTool to analyze the attack vectors:
        {{
            "file_path": "{RESULT_DIR}/phase6/webcheck.json",
            "start_line": 1,
            "line_count": null
        }}   

    """,
    expected_output="A JSON object with 'findings' field containing a list of categorized security findings.",
    tools=[FileReadTool()],
    context=[WC_fingerprint],
    output_json=WC_Format,
)

WC_result = Task(
    name="save_infrastructure_analysis",
    agent=phase6_infrastructure_analyst,
    description=f"""[6-3] Save Infrastructure Analysis results for {TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p6_attack_vector.json"
          "directory": "{RESULT_DIR}/phase6"
        }}

    """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[WC_analysis]
)

OT_zoomeye = Task(
    name="conduct_zoomeye_reconnaissance",
    agent=phase7_osint_integrator,
    description=f"[7-1] Comprehensive asset discovery for {TARGET} using ZoomEye OSINT platform.",
    expected_output="ZoomEye reconnaissance results with discovered assets, services, and infrastructure details",
    tools=[ZoomEyeOSINTTool()],
)

OT_urlscan = Task(
    name="analyze_urlscan_security",
    agent=phase7_osint_integrator,
    description=f"""[7-2] Execute URLScan.io analysis for {TARGET} to identify security vulnerabilities and web technologies.""",
    expected_output="URLScan.io analysis results with security findings and technology stack information",
    tools=[URLScanTool()],
)

OT_fofa = Task(
    name="discover_fofa_assets",
    agent=phase7_osint_integrator,
    description=f"[7-3] Cyberspace asset mapping and discovery for {TARGET} using FOFA search engine.",
    expected_output="FOFA asset discovery results with network infrastructure and service enumeration",
    tools=[FOFASearchTool()],
)

OT_analysis = Task(
    name="analyze_osint_platforms",
    agent=phase7_osint_integrator,
    description=f"""[7-4] Analyze and correlate OSINT findings from ZoomEye, urlscan and FOFA platforms for {TARGET}.""",
    expected_output="A JSON object with 'platform', 'asset_type', 'title', 'target', 'severity', 'description', 'evidence', 'exploitation_potential', 'attack_vectors', 'remediation_priority', 'cross_platform_correlation' fields.",
    context=[OT_zoomeye, OT_urlscan, OT_fofa],
    output_json=OT_Format,
)

OT_result = Task(
    name="save_osint_analysis",
    agent=phase7_osint_integrator,
    description=f"""[7-5] Save Extended OSINT Tools analysis results for {TARGET} as structured attack vectors in JSON

        Use FileWriterTool to save the attack vectors:
        {{
          "filename": "p7_attack_vector.json"
          "directory": "{RESULT_DIR}/phase7"
        }}

    """,
    expected_output="Attack vectors saved successfully",
    tools=[FileWriterTool()],
    context=[OT_analysis]
)