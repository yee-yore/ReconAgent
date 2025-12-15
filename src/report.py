#!/usr/bin/env python3
"""
Minimal Grayscale Security Report Generator
Generates clean, professional HTML reports from ReconAgent JSON outputs
"""

import json, os, sys, argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Optional
from collections import defaultdict

class SecurityReportGenerator:
    def __init__(self, results_dir: str):
        self.results_dir = Path(results_dir)
        self.target = self.results_dir.name
        self.findings = []
        self.findings_by_phase = defaultdict(list)
        self.stats = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0,
            'total': 0
        }
        self.phase_order = [
            'URL Enumeration',
            'Google Dorking',
            'GitHub Intelligence',
            'JavaScript Analysis',
            'Threat Intelligence',
            'Infrastructure Analysis',
            'Extended OSINT'
        ]

    def load_phase_data(self):
        phase_files = [
            ('phase1', 'p1_attack_vector.json', self.parse_phase1),
            ('phase2', 'p2_attack_vector.json', self.parse_phase2),
            ('phase3', 'p3_attack_vector.json', self.parse_phase3),
            ('phase4', 'p4_attack_vector.json', self.parse_phase4),
            ('phase5', 'p5_attack_vector.json', self.parse_phase5),
            ('phase6', 'p6_attack_vector.json', self.parse_phase6),
            ('phase7', 'p7_attack_vector.json', self.parse_phase7),
        ]

        for phase_dir, filename, parser in phase_files:
            file_path = self.results_dir / phase_dir / filename
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read().strip()

                    if not content:
                        pass
                        continue

                    data = json.loads(content)
                    if data:
                        parser(data, phase_dir, filename)
                    else:
                        pass
                except json.JSONDecodeError as e:
                    pass
                except Exception as e:
                    pass

    def parse_phase1(self, data: Any, phase: str, filename: str):
        if isinstance(data, list):
            for finding in data:
                reference = f"{phase}/{filename}"
                if finding.get('line_no'):
                    reference += f" (line {finding['line_no']})"

                finding_data = dict(finding)

                finding_data.update({
                    'phase': 'URL Enumeration',
                    'phase_num': 1,
                    'title': finding.get('category', 'URL Finding'),
                    'severity': finding.get('severity', 'low').lower(),
                    'reference': reference
                })

                self.add_finding(finding_data)

    def parse_phase2(self, data: Any, phase: str, filename: str):
        findings = data
        if isinstance(data, dict):
            if 'attack_vectors' in data:
                findings = data['attack_vectors']
            elif 'website_url' in data or 'category' in data:
                findings = [data]
            else:
                for key, value in data.items():
                    if isinstance(value, list):
                        findings = value
                        break

        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    finding_data = dict(finding)

                    if 'website_url' in finding:
                        finding_data['url'] = finding['website_url']

                    finding_data.update({
                        'phase': 'Google Dorking',
                        'phase_num': 2,
                        'title': finding.get('title', finding.get('category', 'Google Dork Finding')),
                        'severity': finding.get('severity', 'low').lower(),
                        'reference': f"{phase}/{filename}"
                    })

                    self.add_finding(finding_data)

    def parse_phase3(self, data: Any, phase: str, filename: str):
        findings = data
        if isinstance(data, dict) and not any(k in data for k in ['repository_url', 'file_path', 'category']):
            for key, value in data.items():
                if isinstance(value, list):
                    findings = value
                    break
        elif isinstance(data, dict):
            findings = [data]

        if isinstance(findings, list):
            for finding in findings:
                if isinstance(finding, dict):
                    finding_data = dict(finding)

                    if 'repository_url' in finding:
                        finding_data['url'] = finding['repository_url']

                    if not finding_data.get('title'):
                        if finding.get('category'):
                            finding_data['title'] = finding['category'].replace('_', ' ').title()
                        elif finding.get('file_path'):
                            finding_data['title'] = f"Exposure in {finding['file_path']}"
                        else:
                            finding_data['title'] = 'GitHub Finding'

                    finding_data.update({
                        'phase': 'GitHub Intelligence',
                        'phase_num': 3,
                        'severity': finding.get('severity', 'low').lower(),
                        'reference': f"{phase}/{filename}"
                    })

                    self.add_finding(finding_data)

    def parse_phase4(self, data: Any, phase: str, filename: str):
        if isinstance(data, dict):
            findings = data.get('findings', [])
            if isinstance(findings, list):
                for finding in findings:
                    reference = f"{phase}/{filename}"
                    if finding.get('file'):
                        reference += f" ({finding['file']}"
                        if finding.get('line_number'):
                            reference += f":line {finding['line_number']}"
                        reference += ")"

                    finding_data = dict(finding)

                    finding_data.update({
                        'phase': 'JavaScript Analysis',
                        'phase_num': 4,
                        'title': finding.get('title', 'JS Finding'),
                        'severity': finding.get('severity', 'low').lower(),
                        'reference': reference
                    })

                    self.add_finding(finding_data)

    def parse_phase5(self, data: Any, phase: str, filename: str):
        if isinstance(data, dict):
            for vuln in data.get('vulnerabilities', []):
                finding_data = dict(vuln)
                finding_data.update({
                    'phase': 'Threat Intelligence',
                    'phase_num': 5,
                    'title': vuln.get('title', 'Vulnerability Finding'),
                    'severity': vuln.get('severity', 'info').lower(),
                    'finding_type': 'vulnerability',
                    'reference': f"{phase}/{filename}"
                })
                self.add_finding(finding_data)

            for incident in data.get('incidents', []):
                finding_data = dict(incident)
                finding_data.update({
                    'phase': 'Threat Intelligence',
                    'phase_num': 5,
                    'title': incident.get('title', 'Security Incident'),
                    'severity': 'info',
                    'finding_type': 'incident',
                    'reference': f"{phase}/{filename}"
                })
                self.add_finding(finding_data)

            for feature in data.get('new_features', []):
                finding_data = dict(feature)
                finding_data.update({
                    'phase': 'Threat Intelligence',
                    'phase_num': 5,
                    'title': feature.get('title', 'New Feature'),
                    'severity': 'info',
                    'finding_type': 'new_feature',
                    'reference': f"{phase}/{filename}"
                })
                self.add_finding(finding_data)

    def parse_phase6(self, data: Any, phase: str, filename: str):
        if isinstance(data, dict) and 'findings' in data:
            data = data['findings']

        if isinstance(data, list):
            for finding in data:
                reference = f"{phase}/{filename}"
                if finding.get('webcheck_source'):
                    reference = finding['webcheck_source']

                finding_data = dict(finding)

                finding_data.update({
                    'phase': 'Infrastructure Analysis',
                    'phase_num': 6,
                    'title': finding.get('title', 'Infrastructure Finding'),
                    'severity': finding.get('severity', 'low').lower(),
                    'reference': reference
                })

                self.add_finding(finding_data)

    def parse_phase7(self, data: Any, phase: str, filename: str):
        if isinstance(data, dict):
            finding_data = dict(data)

            finding_data.update({
                'phase': 'Extended OSINT',
                'phase_num': 7,
                'title': data.get('title', 'OSINT Analysis'),
                'severity': data.get('severity', 'low').lower(),
                'reference': f"{phase}/{filename}"
            })

            self.add_finding(finding_data)

    def add_finding(self, finding: Dict):
        severity = finding.get('severity', 'low').lower()
        phase = finding.get('phase', 'Unknown')

        if severity == 'informational':
            severity = 'info'
            finding['severity'] = 'info'
        elif severity not in ['critical', 'high', 'medium', 'low', 'info']:
            severity = 'low'
            finding['severity'] = 'low'

        if severity in ['critical', 'high', 'medium', 'low', 'info']:
            self.stats[severity] += 1
            self.stats['total'] += 1
            self.findings.append(finding)
            self.findings_by_phase[phase].append(finding)

    def generate_pie_chart_svg(self) -> str:
        if self.stats['total'] == 0:
            return ''

        critical_pct = (self.stats['critical'] / self.stats['total']) * 100
        high_pct = (self.stats['high'] / self.stats['total']) * 100
        medium_pct = (self.stats['medium'] / self.stats['total']) * 100
        low_pct = (self.stats['low'] / self.stats['total']) * 100

        slices = []
        cumulative = 0

        colors = {
            'critical': '#000000',
            'high': '#333333',
            'medium': '#666666',
            'low': '#999999',
            'info': '#CCCCCC'
        }

        for severity, count in [('critical', self.stats['critical']),
                     ('high', self.stats['high']),
                     ('medium', self.stats['medium']),
                     ('low', self.stats['low']),
                     ('info', self.stats['info'])]:
            if count > 0:
                percentage = (count / self.stats['total']) * 100
                slices.append({
                    'severity': severity,
                    'count': count,
                    'percentage': percentage,
                    'cumulative': cumulative,
                    'color': colors[severity]
                })
                cumulative += percentage

        svg_parts = []
        svg_parts.append('''
        <div class="pie-chart-container">
            <svg viewBox="0 0 400 400" style="width: 300px; height: 300px;">
        ''')

        cx, cy, r = 200, 200, 150
        for i, slice_data in enumerate(slices):
            start_angle = (slice_data['cumulative'] / 100) * 360 - 90
            end_angle = ((slice_data['cumulative'] + slice_data['percentage']) / 100) * 360 - 90

            large_arc = 1 if slice_data['percentage'] > 50 else 0

            start_x = cx + r * cos_deg(start_angle)
            start_y = cy + r * sin_deg(start_angle)
            end_x = cx + r * cos_deg(end_angle)
            end_y = cy + r * sin_deg(end_angle)

            path = f'M {cx},{cy} L {start_x},{start_y} A {r},{r} 0 {large_arc},1 {end_x},{end_y} Z'

            svg_parts.append(f'''
                <path d="{path}" fill="{slice_data['color']}" stroke="white" stroke-width="2"/>
            ''')

        svg_parts.append(f'''
            <circle cx="{cx}" cy="{cy}" r="75" fill="white"/>
        ''')

        svg_parts.append(f'''
            <text x="{cx}" y="{cy}" text-anchor="middle" dominant-baseline="middle"
                  style="font-size: 48px; font-weight: bold; fill: #333;">
                {self.stats['total']}
            </text>
            <text x="{cx}" y="{cy + 30}" text-anchor="middle" dominant-baseline="middle"
                  style="font-size: 14px; fill: #666;">
                TOTAL
            </text>
        ''')

        svg_parts.append('</svg>')

        svg_parts.append('<div class="pie-legend">')
        for severity in ['critical', 'high', 'medium', 'low', 'info']:
            if self.stats[severity] > 0:
                svg_parts.append(f'''
                    <div class="legend-item">
            <span class="legend-color" style="background: {colors[severity]};"></span>
            <span class="legend-label">{severity.upper()}: {self.stats[severity]}</span>
                    </div>
                ''')
        svg_parts.append('</div></div>')

        return ''.join(svg_parts)

    def generate_html(self) -> str:
        scan_date = datetime.now().strftime('%Y-%m-%d %H:%M')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Security Report - {self.target}</title>
    <style>
        :root {{
            --black: #000;
            --dark-gray: #333;
            --gray: #666;
            --light-gray: #999;
            --border: #E0E0E0;
            --bg-light: #F5F5F5;
            --white: #FFF;
        }}

        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}

        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            line-height: 1.6;
            color: var(--dark-gray);
            background: var(--white);
        }}

        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 2rem;
        }}

        header {{
            border-bottom: 2px solid var(--border);
            padding-bottom: 2rem;
            margin-bottom: 3rem;
        }}

        h1 {{
            color: var(--black);
            font-size: 2rem;
            font-weight: 600;
            margin-bottom: 0.5rem;
        }}

        h2 {{
            color: var(--dark-gray);
            font-size: 1.5rem;
            font-weight: 600;
            margin: 2rem 0 1rem 0;
            padding-bottom: 0.5rem;
            border-bottom: 1px solid var(--border);
        }}

        .meta {{
            color: var(--gray);
            font-size: 0.875rem;
        }}

        .pie-chart-container {{
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 3rem;
            margin: 3rem 0;
        }}

        .pie-legend {{
            display: flex;
            flex-direction: column;
            gap: 1rem;
        }}

        .legend-item {{
            display: flex;
            align-items: center;
            gap: 0.75rem;
        }}

        .legend-color {{
            width: 20px;
            height: 20px;
            border: 1px solid var(--border);
        }}

        .legend-label {{
            font-size: 0.875rem;
            color: var(--dark-gray);
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .phase-section {{
            margin: 3rem 0;
        }}

        .phase-header {{
            background: var(--bg-light);
            padding: 1rem;
            margin-bottom: 1.5rem;
            border-left: 4px solid var(--dark-gray);
        }}

        .phase-title {{
            font-size: 1.25rem;
            font-weight: 600;
            color: var(--black);
        }}

        .phase-count {{
            font-size: 0.875rem;
            color: var(--gray);
            margin-top: 0.25rem;
        }}

        .filters {{
            background: var(--bg-light);
            padding: 1rem;
            margin-bottom: 2rem;
            display: flex;
            gap: 1rem;
            align-items: center;
            flex-wrap: wrap;
        }}

        .filter-btn {{
            background: var(--white);
            border: 1px solid var(--border);
            padding: 0.5rem 1rem;
            cursor: pointer;
            font-size: 0.875rem;
            transition: all 0.2s;
        }}

        .filter-btn:hover {{
            background: var(--dark-gray);
            color: var(--white);
        }}

        .filter-btn.active {{
            background: var(--black);
            color: var(--white);
        }}

        .search-box {{
            flex: 1;
            min-width: 200px;
            padding: 0.5rem;
            border: 1px solid var(--border);
            background: var(--white);
        }}

        .finding-card {{
            border: 1px solid var(--border);
            padding: 1.5rem;
            margin-bottom: 1rem;
            background: var(--white);
            transition: background 0.2s;
        }}

        .finding-card:hover {{
            background: var(--bg-light);
        }}

        .severity-critical {{
            border-left: 4px solid var(--black);
        }}

        .severity-high {{
            border-left: 4px solid var(--dark-gray);
        }}

        .severity-medium {{
            border-left: 4px solid var(--gray);
        }}

        .severity-low {{
            border-left: 4px solid var(--light-gray);
        }}

        .severity-info {{
            border-left: 4px solid #CCCCCC;
        }}

        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 1rem;
        }}

        .finding-title {{
            font-weight: 600;
            color: var(--black);
            font-size: 1.125rem;
        }}

        .finding-meta {{
            display: flex;
            gap: 1rem;
            align-items: center;
        }}

        .badge {{
            padding: 0.25rem 0.5rem;
            background: var(--bg-light);
            border: 1px solid var(--border);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .finding-content {{
            color: var(--dark-gray);
        }}

        .finding-field {{
            margin: 0.75rem 0;
        }}

        .field-label {{
            font-weight: 600;
            color: var(--gray);
            font-size: 0.875rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 0.25rem;
        }}

        .field-value {{
            color: var(--dark-gray);
            white-space: pre-wrap;
            word-break: break-word;
        }}

        .no-findings {{
            text-align: center;
            padding: 3rem;
            color: var(--gray);
        }}

        footer {{
            margin-top: 4rem;
            padding-top: 2rem;
            border-top: 1px solid var(--border);
            text-align: center;
            color: var(--light-gray);
            font-size: 0.875rem;
        }}

        @media print {{
            body {{
                font-size: 12pt;
            }}
            .filters {{
                display: none;
            }}
            .finding-card {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Security Report</h1>
            <div class="meta">
                Target: {self.target} | Scan Date: {scan_date}
            </div>
        </header>

        <section class="statistics">
            <h2>Findings Overview</h2>
            {self.generate_pie_chart_svg()}
        </section>

        <div class="filters">
            <button class="filter-btn active" onclick="filterByPhase('all')">All</button>
            <button class="filter-btn" onclick="filterByPhase('url-enumeration')">URL Enumeration</button>
            <button class="filter-btn" onclick="filterByPhase('google-dorking')">Google Dorking</button>
            <button class="filter-btn" onclick="filterByPhase('github-intelligence')">GitHub Intelligence</button>
            <button class="filter-btn" onclick="filterByPhase('javascript-analysis')">JavaScript Analysis</button>
            <button class="filter-btn" onclick="filterByPhase('threat-intelligence')">Threat Intelligence</button>
            <button class="filter-btn" onclick="filterByPhase('infrastructure')">Infrastructure</button>
            <button class="filter-btn" onclick="filterByPhase('osint-tools')">OSINT Tools</button>
            <input type="text" class="search-box" placeholder="Search findings..." onkeyup="searchFindings(this.value)">
        </div>

        <section id="findings">
            {self.generate_findings_html()}
        </section>

        <footer>
            Generated by ReconAgent Security Report Generator
        </footer>
    </div>

    <script>
        function filterByPhase(phase) {{
            // Update button states
            document.querySelectorAll('.filter-btn').forEach(btn => {{
                btn.classList.remove('active');
            }});
            event.target.classList.add('active');

            // Filter phase sections
            document.querySelectorAll('.phase-section').forEach(section => {{
                if (phase === 'all' || section.dataset.phase === phase) {{
                    section.style.display = 'block';
                }} else {{
                    section.style.display = 'none';
                }}
            }});
        }}

        function searchFindings(query) {{
            const q = query.toLowerCase();

            // If query is empty, show all sections
            if (!q) {{
                document.querySelectorAll('.phase-section').forEach(section => {{
                    section.style.display = 'block';
                }});
                document.querySelectorAll('.finding-card').forEach(card => {{
                    card.style.display = 'block';
                }});
                return;
            }}

            // Search and filter
            document.querySelectorAll('.phase-section').forEach(section => {{
                let hasMatch = false;
                section.querySelectorAll('.finding-card').forEach(card => {{
                    const text = card.textContent.toLowerCase();
                    if (text.includes(q)) {{
                        card.style.display = 'block';
                        hasMatch = true;
                    }} else {{
                        card.style.display = 'none';
                    }}
                }});
                section.style.display = hasMatch ? 'block' : 'none';
            }});
        }}
    </script>
</body>
</html>"""

        return html

    def generate_findings_html(self) -> str:
        if not self.findings:
            return '<div class="no-findings">No findings to display</div>'

        html_parts = []

        for phase_name in self.phase_order:
            if phase_name not in self.findings_by_phase:
                continue

            phase_findings = self.findings_by_phase[phase_name]
            if not phase_findings:
                continue

            severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'informational': 4}
            phase_findings.sort(key=lambda x: severity_order.get(x.get('severity', 'low'), 5))

            phase_data_map = {
                'URL Enumeration': 'url-enumeration',
                'Google Dorking': 'google-dorking',
                'GitHub Intelligence': 'github-intelligence',
                'JavaScript Analysis': 'javascript-analysis',
                'Threat Intelligence': 'threat-intelligence',
                'Infrastructure Analysis': 'infrastructure',
                'Infrastructure Fingerprinting': 'infrastructure',
                'Extended OSINT': 'osint-tools'
            }
            phase_data = phase_data_map.get(phase_name, phase_name.lower().replace(' ', '-'))

            html_parts.append(f'''
            <div class="phase-section" data-phase="{phase_data}">
                <div class="phase-header">
                    <div class="phase-title">Phase {phase_findings[0].get("phase_num", "")}: {phase_name}</div>
                    <div class="phase-count">{len(phase_findings)} finding{"s" if len(phase_findings) != 1 else ""}</div>
                </div>
            ''')

            for finding in phase_findings:
                severity = finding.get('severity', 'low')
                title = finding.get('title', 'Untitled Finding')

                fields = []
                phase_name_normalized = phase_name.lower()

                if 'url enumeration' in phase_name_normalized:
                    if finding.get('url'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">URL</div>
                <div class="field-value">{self.escape_html(finding['url'])}</div>
            </div>""")

                    if finding.get('category'):
                        category_display = finding['category']
                        if isinstance(category_display, str):
                            category_display = category_display.replace('_', ' ').title()
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Category</div>
                <div class="field-value">{self.escape_html(category_display)}</div>
            </div>""")

                    if finding.get('evidence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Evidence</div>
                <div class="field-value">{self.escape_html(finding['evidence'])}</div>
            </div>""")

                    if finding.get('payload_example'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Payload Example</div>
                <div class="field-value">{self.escape_html(finding['payload_example'])}</div>
            </div>""")

                    if finding.get('exploitation_notes'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Exploitation Notes</div>
                <div class="field-value">{self.format_exploitation_notes(finding['exploitation_notes'])}</div>
            </div>""")

                    if finding.get('params'):
                        params_str = ', '.join(finding['params']) if isinstance(finding['params'], list) else str(finding['params'])
                        if params_str and params_str != '[]':
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Parameters</div>
                    <div class="field-value">{self.escape_html(params_str)}</div>
                </div>""")

                    if finding.get('endpoint_type'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Endpoint Type</div>
                <div class="field-value">{self.escape_html(finding['endpoint_type'])}</div>
            </div>""")

                elif 'google dorking' in phase_name_normalized:
                    if finding.get('website_url') or finding.get('url'):
                        url_value = finding.get('website_url') or finding.get('url')
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Website URL</div>
                <div class="field-value">{self.escape_html(url_value)}</div>
            </div>""")

                    if finding.get('category'):
                        category_display = finding['category']
                        if isinstance(category_display, str):
                            category_display = category_display.replace('_', ' ').title()
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Category</div>
                <div class="field-value">{self.escape_html(category_display)}</div>
            </div>""")

                    if finding.get('evidence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Evidence</div>
                <div class="field-value">{self.escape_html(finding['evidence'])}</div>
            </div>""")

                    if finding.get('payload_example'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Payload Example</div>
                <div class="field-value">{self.escape_html(finding['payload_example'])}</div>
            </div>""")

                    if finding.get('exploitation_notes'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Exploitation Notes</div>
                <div class="field-value">{self.format_exploitation_notes(finding['exploitation_notes'])}</div>
            </div>""")

                    if finding.get('endpoints'):
                        endpoints = finding['endpoints']
                        if isinstance(endpoints, list) and endpoints:
                            endpoints_str = '<br>• '.join(self.escape_html(e) for e in endpoints)
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Endpoints</div>
                    <div class="field-value">• {endpoints_str}</div>
                </div>""")

                    if finding.get('parameters'):
                        params = finding['parameters']
                        if isinstance(params, list) and params:
                            params_str = ', '.join(params)
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Parameters</div>
                    <div class="field-value">{self.escape_html(params_str)}</div>
                </div>""")

                    if finding.get('description'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Description</div>
                <div class="field-value">{self.escape_html(finding['description'])}</div>
            </div>""")

                    if finding.get('potential_impact'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Potential Impact</div>
                <div class="field-value">{self.escape_html(finding['potential_impact'])}</div>
            </div>""")

                elif 'github' in phase_name_normalized:
                    if finding.get('repository_url') or finding.get('url'):
                        repo_url = finding.get('repository_url') or finding.get('url')
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Repository URL</div>
                <div class="field-value">{self.escape_html(repo_url)}</div>
            </div>""")

                    if finding.get('file_path'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">File Path</div>
                <div class="field-value">{self.escape_html(finding['file_path'])}</div>
            </div>""")

                    if finding.get('category'):
                        category_display = finding['category']
                        if isinstance(category_display, str):
                            category_display = category_display.replace('_', ' ').title()
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Category</div>
                <div class="field-value">{self.escape_html(category_display)}</div>
            </div>""")

                    if finding.get('evidence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Evidence</div>
                <div class="field-value">{self.escape_html(finding['evidence'])}</div>
            </div>""")

                    if finding.get('payload_example'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Payload Example</div>
                <div class="field-value">{self.escape_html(finding['payload_example'])}</div>
            </div>""")

                    if finding.get('exploitation_notes'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Exploitation Notes</div>
                <div class="field-value">{self.format_exploitation_notes(finding['exploitation_notes'])}</div>
            </div>""")

                    if finding.get('verification_status'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Verification Status</div>
                <div class="field-value">{self.escape_html(finding['verification_status'])}</div>
            </div>""")

                    if finding.get('sensitive_data_type'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Sensitive Data Type</div>
                <div class="field-value">{self.escape_html(finding['sensitive_data_type'])}</div>
            </div>""")

                    if finding.get('potential_impact'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Potential Impact</div>
                <div class="field-value">{self.escape_html(finding['potential_impact'])}</div>
            </div>""")

                elif 'javascript' in phase_name_normalized:
                    if finding.get('file'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">File</div>
                <div class="field-value">{self.escape_html(finding['file'])}</div>
            </div>""")

                    if finding.get('line_number') or finding.get('line'):
                        line_no = finding.get('line_number') or finding.get('line')
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Line Number</div>
                <div class="field-value">{line_no}</div>
            </div>""")

                    if finding.get('evidence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Evidence</div>
                <div class="field-value">{self.escape_html(finding['evidence'])}</div>
            </div>""")

                    if finding.get('potential_impact'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Potential Impact</div>
                <div class="field-value">{self.escape_html(finding['potential_impact'])}</div>
            </div>""")

                    if finding.get('exploitation_notes'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Exploitation Notes</div>
                <div class="field-value">{self.format_exploitation_notes(finding['exploitation_notes'])}</div>
            </div>""")

                elif 'threat intelligence' in phase_name_normalized:
                    if finding.get('finding_type'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Finding Type</div>
                <div class="field-value">{self.escape_html(finding['finding_type'])}</div>
            </div>""")

                    if finding.get('source'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Source</div>
                <div class="field-value">{self.escape_html(finding['source'])}</div>
            </div>""")

                    if finding.get('date_discovered'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Date Discovered</div>
                <div class="field-value">{self.escape_html(finding['date_discovered'])}</div>
            </div>""")

                    if finding.get('description'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Description</div>
                <div class="field-value">{self.escape_html(finding['description'])}</div>
            </div>""")

                    if finding.get('evidence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Evidence</div>
                <div class="field-value">{self.escape_html(finding['evidence'])}</div>
            </div>""")

                    if finding.get('impact_assessment'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Impact Assessment</div>
                <div class="field-value">{self.escape_html(finding['impact_assessment'])}</div>
            </div>""")

                    if finding.get('verification_status'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Verification Status</div>
                <div class="field-value">{self.escape_html(finding['verification_status'])}</div>
            </div>""")

                    if finding.get('threat_category'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Threat Category</div>
                <div class="field-value">{self.escape_html(finding['threat_category'])}</div>
            </div>""")

                    if finding.get('actionable_intelligence'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Actionable Intelligence</div>
                <div class="field-value">{self.escape_html(finding['actionable_intelligence'])}</div>
            </div>""")

                    if finding.get('attack_vectors'):
                        vectors = finding['attack_vectors']
                        if isinstance(vectors, list) and vectors:
                            vectors_str = '<br>• '.join(self.escape_html(v) for v in vectors)
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Attack Vectors</div>
                    <div class="field-value">• {vectors_str}</div>
                </div>""")

                elif 'osint' in phase_name_normalized or 'extended' in phase_name_normalized:
                    if finding.get('platform'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Platform</div>
                <div class="field-value">{self.escape_html(finding['platform']).upper()}</div>
            </div>""")

                    if finding.get('asset_type'):
                        asset_display = finding['asset_type'].replace('_', ' ').title()
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Asset Type</div>
                <div class="field-value">{self.escape_html(asset_display)}</div>
            </div>""")

                    if finding.get('target'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Target</div>
                <div class="field-value">{self.escape_html(finding['target'])}</div>
            </div>""")

                    if finding.get('description'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Description</div>
                <div class="field-value">{self.escape_html(finding['description'])}</div>
            </div>""")

                    if finding.get('evidence'):
                        evidence = finding['evidence']
                        if isinstance(evidence, dict):
                            evidence_parts = []
                            for key, value in evidence.items():
                                evidence_parts.append(f"<strong>{key}:</strong> {self.escape_html(value)}")
                            evidence_str = '<br>'.join(evidence_parts)
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Evidence</div>
                    <div class="field-value">{evidence_str}</div>
                </div>""")
                        else:
                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">Evidence</div>
                    <div class="field-value">{self.escape_html(evidence)}</div>
                </div>""")

                    if finding.get('attack_vectors'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Attack Vectors</div>
                <div class="field-value">{self.format_exploitation_notes(finding['attack_vectors'])}</div>
            </div>""")

                    if finding.get('exploitation_potential'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Exploitation Potential</div>
                <div class="field-value">{self.escape_html(finding['exploitation_potential']).replace('_', ' ').title()}</div>
            </div>""")

                    if finding.get('remediation_priority'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Remediation Priority</div>
                <div class="field-value">{self.escape_html(finding['remediation_priority']).upper()}</div>
            </div>""")

                    if finding.get('cross_platform_correlation'):
                        fields.append(f"""
            <div class="finding-field">
                <div class="field-label">Cross-Platform Correlation</div>
                <div class="field-value">{self.escape_html(finding['cross_platform_correlation'])}</div>
            </div>""")

                else:
                    field_mapping = {
                        'url': 'URL',
                        'evidence': 'Evidence',
                        'impact': 'Impact',
                        'exploitation': 'Exploitation',
                        'description': 'Description',
                        'potential_impact': 'Potential Impact',
                        'exploitation_notes': 'Exploitation Notes',
                        'payload_example': 'Payload Example',
                        'category': 'Category',
                        'confidence': 'Confidence',
                        'verification_status': 'Verification Status'
                    }

                    for field_key, field_label in field_mapping.items():
                        if finding.get(field_key):
                            value = finding[field_key]
                            if field_key == 'confidence' and isinstance(value, (int, float)):
                                value = f"{value}%"

                            if field_key == 'exploitation_notes':
                                formatted_value = self.format_exploitation_notes(value)
                            else:
                                formatted_value = self.escape_html(value)

                            fields.append(f"""
                <div class="finding-field">
                    <div class="field-label">{field_label}</div>
                    <div class="field-value">{formatted_value}</div>
                </div>""")

                    if finding.get('reference'):
                        fields.append(f"""
                    <div class="finding-field">
                        <div class="field-label">Reference</div>
                        <div class="field-value">{self.escape_html(finding['reference'])}</div>
                    </div>""")

                html_parts.append(f"""
                <div class="finding-card severity-{severity}" data-severity="{severity}">
                    <div class="finding-header">
                        <div class="finding-title">{self.escape_html(title)}</div>
                        <div class="finding-meta">
                            <span class="badge">{severity.upper()}</span>
                        </div>
                    </div>
                    <div class="finding-content">
                        {''.join(fields)}
                    </div>
                </div>""")

            html_parts.append('</div>')

        return ''.join(html_parts)

    def escape_html(self, text: Any) -> str:
        """Safely escape HTML characters in text, handling various input types."""
        if text is None:
            return ''
        if isinstance(text, (list, tuple)):
            return self.escape_html(', '.join(str(item) for item in text))
        if isinstance(text, dict):
            return self.escape_html(json.dumps(text, indent=2))

        text = str(text)
        return text.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#39;')

    def format_exploitation_notes(self, text: Any) -> str:
        """Format exploitation notes with line breaks after numbered items."""
        if text is None or text == '':
            return ''

        text = str(text)

        escaped = self.escape_html(text)

        import re
        formatted = re.sub(r'(\d+\.\s)', r'<br>\1', escaped)

        if formatted.startswith('<br>'):
            formatted = formatted[4:]

        return formatted

    def generate_report(self, output_path: Optional[str] = None):
        self.load_phase_data()
        html = self.generate_html()

        if not output_path:
            output_path = self.results_dir / f"{self.target}_security_report.html"

        output_path = Path(output_path)

        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html)


def cos_deg(angle):
    import math
    return math.cos(math.radians(angle))

def sin_deg(angle):
    import math
    return math.sin(math.radians(angle))


def main():
    parser = argparse.ArgumentParser(description='Generate security report from ReconAgent results')
    parser.add_argument('--target', '-t', required=True, help='Target domain name')
    parser.add_argument('--input', '-i', help='Input directory (default: results/TARGET)')
    parser.add_argument('--output', '-o', help='Output file path (default: TARGET_security_report.html)')

    args = parser.parse_args()

    if args.input:
        results_dir = args.input
    else:
        results_dir = f"results/{args.target}"

    if not os.path.exists(results_dir):
        sys.exit(1)

    generator = SecurityReportGenerator(results_dir)
    generator.generate_report(args.output)


if __name__ == '__main__':
    main()