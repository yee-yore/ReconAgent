# ReconAgent - Automated Security Recon Framework

<p align="center">
  <img src="https://img.shields.io/badge/Version-0.1.1--alpha-blue.svg" alt="Version">
  <img src="https://img.shields.io/badge/Python-3.11%2B-green.svg" alt="Python">
  <img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="License">
  <img src="https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker" alt="Docker">
</p>

**ReconAgent** is an LLM-powered automated recon framework for pentesting and bug bounty hunting, built with CrewAI. It follows a "slow but strong" philosophy.

### Features
ReconAgent is in **early development stage** and aims to automate the following reconnaissance techniques (more may be added).

- URL Enumeration
- Google Dorking
- GitHub Dorking
- Javascript Analysis
- Threat Intelligence
- Infrastructure Analysis
- Extended OSINT
- Report Generation

## Quick Start

### Setup
```bash
# Clone repository
git clone https://github.com/yee-yore/ReconAgent.git
cd ReconAgent

# Configure and edit .env with your API keys
cp .env.example .env
```

### Docker (Recommended)
```bash
# Build image
docker-compose build reconagent
```
```bash
# Run all phases
docker-compose run --rm reconagent --target target.com --all
```
```bash
# Run specific phase
docker-compose run --rm reconagent --target target.com --phase google-dork
```
```bash
# Generate report after running phases
docker-compose run --rm reconagent --target target.com --report
```

### Manual Installation
```bash
# Install dependencies
pip install -r requirements.txt
pip install waymore uddup && pipx install uro
playwright install chromium
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
brew install noir
```

```bash
# Single phase
python reconagent.py --target target.com --phase url-enum

# Multiple phases
python reconagent.py --target target.com --phase url-enum,google-dork,github-dork

# Generate report
python reconagent.py --target target.com --report

# Generate report using standalone script
python generate_report.py --target target.com --output custom_report.html
```

## Features

#### Phase 1: URL Enumeration
- **Description**: Archives and crawls historical URLs to map attack surface
- **Process**: URL fetching → URL classification → Security analysis → Result aggregation
- **Output**: Categorized URLs with vulnerability indicators and exploitation notes
```json
{
  "line_no": 42,
  "url": "/ajax/download.jsp?dirId=value&docId=value",
  "category": "idor_potential",
  "evidence": "Parameter manipulation for file access with dirId and docId controlling resource retrieval",
  "payload_example": "/ajax/download.jsp?dirId=../../../etc&docId=passwd",
  "exploitation_notes": "1. Test parameter manipulation 2. Try directory traversal 3. Enumerate accessible files",
  "severity": "high",
  "params": ["dirId", "docId"],
  "endpoint_type": "file"
}
```

#### Phase 2: Google Dorking
- **Description**: Automated Google dorking with 15 specialized queries
- **Process**: Google Dorking → URL analysis → File download → File content analysis → Result aggregation
- **Output**: Information disclosure findings, exposed files, configuration leaks
```json
{
  "google_dork": "site:target.com inurl:callback",
  "website_url": "https://target.com/api/endpoint?callback=processData",
  "category": "XSS",
  "evidence": "Callback parameter reflects user input in response without sanitization",
  "endpoints": ["/api/endpoint", "/graphql", "/api/v2/search"],
  "parameters": ["callback", "id", "search", "query"],
  "payload_example": "?callback=<script>alert(document.domain)</script>",
  "exploitation_notes": "Test reflected XSS: 1. Inject basic payload 2. Bypass filters if present 3. Escalate to stored XSS if applicable",
  "severity": "high"
}
```

#### Phase 3: GitHub Intelligence
- **Description**: GitHub credential and sensitive data discovery
- **Process**: GitHub Dorking → Content verification & analysis → Result aggregation
- **Output**: Exposed credentials, API keys, database configs, private keys
```json
{
  "file_name": ".env.production",
  "file_path": "backend/config/.env.production",
  "html_url": "https://github.com/target-org/webapp/blob/main/backend/config/.env.production",
  "repository": "target-org/webapp",
  "category": "credential_exposure",
  "evidence": "Production environment file with AWS keys: AWS_ACCESS_KEY_ID=AKIA****************, AWS_SECRET=****, DB_PASSWORD=****",
  "payload_example": "aws sts get-caller-identity --profile hijacked",
  "exploitation_notes": "1. Extract credentials 2. Configure AWS CLI 3. Test access: aws s3 ls 4. Enumerate permissions 5. Pivot to other services",
  "severity": "critical",
  "verification_status": "content_verified",
  "sensitive_data_type": "cloud_config"
}
```

#### Phase 4: JavaScript Analysis
- **Description**: Client-side security vulnerability scanning with nuclei + noir
- **Process**: JS collection → Nuclei scanning → Noir scanning → Finding validation → Result aggregation
- **Output**: API endpoints, hardcoded secrets, auth logic vulnerabilities
```json
{
  "file": "app.bundle.min.js",
  "category": "hardcoded_secret",
  "line_number": 1842,
  "severity": "critical",
  "evidence": "const STRIPE_SECRET='sk_live_51HqJ...';const AWS_KEY='AKIAIOSFODNN7EXAMPLE';",
  "description": "Multiple production secrets hardcoded in minified JavaScript: Stripe secret key and AWS access key",
  "exploitation_potential": "credential_theft",
  "payload_example": "stripe.customers.list({api_key: 'sk_live_51HqJ...', limit: 100})",
  "exploitation_notes": "1. Extract Stripe secret key 2. Test API access: curl https://api.stripe.com/v1/customers -u sk_live_xxx: 3. Enumerate customer data 4. Test AWS key for S3/EC2 access"
}
```

#### Phase 5: Threat Intelligence
- **Description**: CVE research, security incidents, and new feature analysis
- **Process**: Security incident search → CVE/vulnerability research → New feature discovery → Risk correlation → Result aggregation
- **Output**: Known vulnerabilities, security incidents, recent feature changes
```json
{
  "vulnerabilities": [{
    "title": "Authentication Bypass via JWT Manipulation",
    "source": "https://hackerone.com/reports/1234567",
    "source_language": "english",
    "date": "2024-08-15",
    "summary": "Weak JWT signature validation allows attackers to forge admin tokens",
    "severity": "critical",
    "vulnerability_type": "authentication_bypass",
    "cve_id": "CVE-2024-45678",
    "bounty_amount": "$15,000",
    "researcher": "security_researcher",
    "patch_status": "patched"
  }],
  "incidents": [{
    "title": "Credential Stuffing Attack on User Accounts",
    "source": "https://status.target.com/incidents/2024-09-01",
    "source_language": "english",
    "date": "2024-09-01",
    "summary": "Automated credential stuffing attack compromised 5,000 user accounts",
    "incident_type": "credential_leak",
    "affected_data": "Account credentials, session tokens",
    "impact_scope": "5,000 accounts compromised"
  }],
  "new_features": [{
    "title": "New GraphQL API Endpoint",
    "description": "Introduced GraphQL endpoint for mobile app integration",
    "date": "2024-09-15",
    "source": "https://blog.target.com/new-api-release",
    "source_language": "english",
    "feature_type": "api_update",
    "attack_surface_change": "increased",
    "attack_vectors": ["GraphQL introspection", "Query depth attacks", "Batching abuse"]
  }],
  "overall_risk_score": "critical",
  "priority_findings": ["Recent JWT bypass vulnerability with active exploitation", "GraphQL endpoint increases attack surface significantly"],
  "recommended_actions": ["Verify JWT signature patch deployment", "Implement GraphQL query depth limiting", "Enable MFA for all admin accounts"]
}
```

#### Phase 6: Infrastructure Fingerprinting
- **Description**: Technology stack and security configuration analysis via web-check
- **Process**: Fingerprinting → Multi-category analysis → Result aggregation
- **Output**: Security misconfigurations, DNS issues, SSL problems, tech stack exposure
```json
{
  "findings": [{
    "finding_category": "security",
    "finding_type": "missing_security_control",
    "component": "http_security",
    "title": "Missing Critical Security Headers",
    "severity": "high",
    "description": "Essential security headers not implemented: CSP, HSTS, X-Frame-Options, X-Content-Type-Options",
    "evidence": "Headers: Server: nginx/1.21.6, X-Powered-By: PHP/8.1.0. Missing: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options",
    "remediation": "Add headers: Content-Security-Policy: default-src 'self'; Strict-Transport-Security: max-age=31536000; includeSubDomains; X-Frame-Options: DENY",
    "webcheck_source": "/api/headers",
    "attack_vector": "Clickjacking, MIME-sniffing attacks, mixed content, session hijacking over HTTP",
    "compliance_impact": "OWASP A05:2021 Security Misconfiguration, fails PCI-DSS 6.5.10",
    "ssl_details": null
  }]
}
```

#### Phase 7: Extended OSINT
- **Description**: Multi-platform reconnaissance (ZoomEye, URLScan.io, FOFA)
- **Process**: ZoomEye asset discovery → URLScan.io analysis → FOFA enumeration → Cross-platform correlation → Result aggregation
- **Output**: Exposed services, subdomains, certificates, network infrastructure
```json
{
  "platform": "zoomeye",
  "asset_type": "service",
  "title": "Unauthenticated Redis Instance Exposed to Internet",
  "target": "203.0.113.45:6379",
  "severity": "critical",
  "description": "Redis 6.2.7 exposed without authentication on public IP, allowing unrestricted access to cached sensitive data",
  "evidence": "Port 6379/tcp open, banner: 'Redis version=6.2.7', AUTH not required, 2,847 keys enumerated including session tokens and API keys",
  "exploitation_potential": "immediate_access",
  "attack_vectors": "1. Connect: redis-cli -h 203.0.113.45 2. Enumerate: KEYS * 3. Extract data: GET <key> 4. RCE attempt: MODULE LOAD /tmp/evil.so 5. Persistence: CONFIG SET dir /var/www/html",
  "remediation_priority": "immediate",
  "cross_platform_correlation": "URLScan.io: subdomain cache.target.com → 203.0.113.45 | FOFA: 4 more Redis instances on 203.0.113.0/24 subnet, all unauthenticated"
}
```

#### Report Generation
**Note**: Report generation is not a phase, but a separate utility for aggregating results.

- **Description**: Comprehensive HTML reporting
- **Output**: Executive summary with severity statistics, detailed technical findings by phase, interactive filtering and search (see the `sample_report.html`)

## Contributing

Contributions, bug reports, and feature requests are always welcome! If you have ideas for improving ReconAgent or encounter any issues, please feel free to:

- Open an issue for bug reports or feature suggestions
- Submit a pull request with improvements or fixes
- Share your reconnaissance workflows and use cases

## Acknowledgments

ReconAgent is powered by excellent open-source tools and frameworks:
- **Apache-2.0**: **[uro](https://github.com/s0md3v/uro)**, **[playwright](https://github.com/microsoft/playwright)**
- **MIT**: **[CrewAI](https://github.com/crewAIInc/crewAI)**, **[waymore](https://github.com/xnl-h4ck3r/waymore)**, **[uddup](https://github.com/rotemreiss/uddup)**, **[nuclei](https://github.com/projectdiscovery/nuclei)**, **[OWASP Noir](https://github.com/owasp-noir/noir)**, **[web-check](https://github.com/Lissy93/web-check)** 

---