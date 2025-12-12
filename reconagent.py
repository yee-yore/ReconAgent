#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, argparse, warnings, re, subprocess
from pathlib import Path
from dotenv import load_dotenv
from crewai import Crew

warnings.filterwarnings("ignore", category=DeprecationWarning)

REQUIRED_API_KEYS = [
    'OPENAI_API_KEY',
    'SERPER_API_KEY',
    'API_BASE',
    'ZOOMEYE_API_KEY',
    'FOFA_API_KEY',
    'URLSCAN_API_KEY',
    'GITHUB_API_TOKEN'
]

# Phase-specific API key requirements
PHASE_API_KEYS = {
    'url-enum': ['OPENAI_API_KEY'],
    'google-dork': ['OPENAI_API_KEY', 'SERPER_API_KEY'],
    'github-dork': ['OPENAI_API_KEY', 'GITHUB_API_TOKEN'],
    'js-analysis': ['OPENAI_API_KEY'],
    'threat-intel': ['OPENAI_API_KEY'],
    'infra': ['OPENAI_API_KEY', 'API_BASE'],
    'osint': ['OPENAI_API_KEY', 'ZOOMEYE_API_KEY', 'URLSCAN_API_KEY', 'FOFA_API_KEY'],
}

PHASE_DEPENDENCIES = {
    'url-enum': ['waymore', 'uro', 'uddup'],
    'js-analysis': ['nuclei', 'noir'],
    'infra': ['docker'],
}

PHASES = {
    'url-enum': {
        'name': 'URL Enumeration & Classification',
        'description': 'Collect URLs, distill, validate and analyze for attack vectors',
        'tasks': ['UE_fetch_urls', 'UE_distill_urls', 'UE_validate_urls', 'UE_analysis', 'UE_result'],
        'dependencies': []
    },
    'google-dork': {
        'name': 'Google Dorking & OSINT',
        'description': 'Execute comprehensive Google Dorking queries and vulnerability analysis',
        'tasks': ['GD_dorking', 'GD_url_analysis', 'GD_file_download', 'GD_file_analysis', 'GD_result'],
        'dependencies': []
    },
    'github-dork': {
        'name': 'GitHub Intelligence',
        'description': 'GitHub dorking and credential hunting via search engines',
        'tasks': ['GH_dorking', 'GH_analysis', 'GH_result'],
        'dependencies': []
    },
    'js-analysis': {
        'name': 'JavaScript Security Analysis',
        'description': 'Collect, scan with Nuclei/NOIR, and analyze JavaScript files for security vulnerabilities',
        'tasks': ['JA_collect', 'JA_nuclei_scan', 'JA_noir_scan', 'JA_analysis', 'JA_result'],
        'dependencies': []
    },
    'threat-intel': {
        'name': 'Threat Intelligence Research',
        'description': 'Research security incidents, vulnerabilities, and recent features',
        'tasks': ['TI_incident', 'TI_known_vuln', 'TI_new_feature', 'TI_analysis', 'TI_result'],
        'dependencies': []
    },
    'infra': {
        'name': 'Infrastructure Fingerprinting',
        'description': 'Fingerprint infrastructure and analyze security configurations',
        'tasks': ['WC_fingerprint', 'WC_analysis', 'WC_result'],
        'dependencies': []
    },
    'osint': {
        'name': 'Extended OSINT Tools',
        'description': 'Asset discovery using ZoomEye, URLScan.io, and FOFA platforms',
        'tasks': ['OT_zoomeye', 'OT_urlscan', 'OT_fofa', 'OT_analysis', 'OT_result'],
        'dependencies': []
    }
}

def load_env_config():
    """Load and return environment configuration."""
    env_path = Path('.env')
    if not env_path.exists():
        return None
    
    load_dotenv()
    return {key: os.getenv(key, '') for key in REQUIRED_API_KEYS + ['TARGET', 'RESULT_DIR']}

def validate_api_keys(config, phase=None):
    """Validate required API keys for the specified phase."""
    # Determine which keys are required for this phase
    if phase and phase in PHASE_API_KEYS:
        required_keys = PHASE_API_KEYS[phase]
    else:
        required_keys = ['OPENAI_API_KEY']  # Default: only OpenAI key required

    missing_keys = []
    placeholder_keys = []

    for key in required_keys:
        value = config.get(key, '')
        if not value:
            missing_keys.append(key)
        elif key != 'API_BASE' and 'your_' in value.lower() and '_here' in value.lower():
            placeholder_keys.append(key)

    if missing_keys:
        print(f"[-] Missing API keys in .env: {', '.join(missing_keys)}")
        return False

    if placeholder_keys:
        print(f"[-] Placeholder values detected in .env: {', '.join(placeholder_keys)}")
        print(f"[!] Tip: Replace 'your_*_key_here' with actual API keys")
        return False

    return True

def update_env_target(target):
    """Update TARGET and RESULT_DIR in .env file."""
    env_path = Path('.env')
    if not env_path.exists():
        print(f"[-] Error: .env file not found when updating target")
        return False

    try:
        content = env_path.read_text()
        lines = content.splitlines()

        result_dir = f"results/{target}"
        target_updated = False
        result_dir_updated = False

        for i, line in enumerate(lines):
            if line.startswith('TARGET='):
                lines[i] = f'TARGET={target}'
                target_updated = True
            elif line.startswith('RESULT_DIR='):
                lines[i] = f'RESULT_DIR={result_dir}'
                result_dir_updated = True

        if not target_updated:
            lines.append(f'TARGET={target}')
        if not result_dir_updated:
            lines.append(f'RESULT_DIR={result_dir}')

        env_path.write_text('\n'.join(lines) + '\n')
        return True

    except Exception as e:
        print(f"[-] Error: Failed to update .env file: {str(e)}")
        return False

def validate_domain(domain):
    """Validate domain format."""
    pattern = re.compile(
        r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
    )
    return pattern.match(domain) is not None

def check_waymore_installed():
    """Check if waymore is installed."""
    try:
        result = subprocess.run(
            ["waymore", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_uro_installed():
    """Check if uro is installed for URL deduplication."""
    try:
        result = subprocess.run(
            ["uro", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_uddup_installed():
    """Check if uddup is installed."""
    try:
        result = subprocess.run(
            ["uddup", "--help"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_docker_running():
    """Check if Docker is running for web-check server."""
    try:
        result = subprocess.run(
            ["docker", "ps"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_nuclei_installed():
    """Check if Nuclei is installed."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_noir_installed():
    """Check if NOIR is installed."""
    try:
        result = subprocess.run(
            ["noir", "--version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False

def check_dependencies(phase):
    """Check dependencies for a specific phase."""
    if phase not in PHASE_DEPENDENCIES:
        return True, None

    dependencies = PHASE_DEPENDENCIES[phase]
    for dep in dependencies:
        if dep == 'waymore':
            if not check_waymore_installed():
                return False, 'waymore'
        elif dep == 'uro':
            if not check_uro_installed():
                return False, 'uro'
        elif dep == 'uddup':
            if not check_uddup_installed():
                return False, 'uddup'
        elif dep == 'nuclei':
            if not check_nuclei_installed():
                return False, 'nuclei'
        elif dep == 'noir':
            if not check_noir_installed():
                return False, 'noir'
        elif dep == 'docker':
            if not check_docker_running():
                return False, 'docker'

    return True, None


def create_parser():
    """Create command line argument parser."""

    parser = argparse.ArgumentParser(
        description='ReconAgent - OSINT Security Reconnaissance Framework',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --target example.com --phase url-enum             # Single phase
  %(prog)s --target example.com --phase url-enum,google-dork  # Multiple phases
  %(prog)s --target example.com --all                        # Full pipeline
"""
    )
    
    parser.add_argument(
        '--target', '-t',
        metavar='',
        help='Target domain for reconnaissance (updates .env automatically)'
    )
    
    phase_group = parser.add_mutually_exclusive_group()
    phase_group.add_argument(
        '--phase', '-p',
        metavar='',
        help=f'Execute phase(s) - single name or comma-separated list. Phases: {", ".join(PHASES.keys())}'
    )
    phase_group.add_argument(
        '--all',
        action='store_true',
        help='Execute all reconnaissance phases (full pipeline)'
    )

    parser.add_argument(
        '--report', '-r',
        nargs='?',
        const='',
        metavar='PATH',
        help='Generate HTML report after phase execution or from existing results. Optional: specify custom output path'
    )

    parser.add_argument(
        '--skip-validation',
        action='store_true',
        help='Skip URL validation step in url-enum phase (faster but includes dead URLs)'
    )

    return parser

def generate_report_for_target(target, output_path=None):
    """Generate security report for target."""
    from generate_report import SecurityReportGenerator

    results_dir = f"results/{target}"
    if os.path.exists(results_dir):
        print(f"[*] Generating report for {target}...")
        generator = SecurityReportGenerator(results_dir)
        generator.generate_report(output_path)
        print(f"[+] Report generated successfully!")
        return True
    else:
        print(f"[-] Error: Results directory not found: {results_dir}")
        print(f"[!] Tip: Run reconnaissance phases first before generating report")
        return False

def resolve_dependencies(requested_phases):
    """Resolve phase dependencies and return execution order."""
    execution_order = []
    processed = set()
    
    def add_phase_with_deps(phase):
        if phase in processed:
            return
            
        for dep in PHASES[phase]['dependencies']:
            add_phase_with_deps(dep)
            
        if phase not in execution_order:
            execution_order.append(phase)
        processed.add(phase)
    
    for phase in requested_phases:
        add_phase_with_deps(phase)
        
    return execution_order

def get_phase_tasks(phases, skip_validation=False):
    """Get all task objects for the specified phases."""
    from task import (
        UE_fetch_urls, UE_distill_urls, UE_validate_urls, UE_analysis, UE_result,
        GD_dorking, GD_url_analysis, GD_file_download, GD_file_analysis, GD_result,
        GH_dorking, GH_analysis, GH_result,
        JA_collect, JA_nuclei_scan, JA_noir_scan, JA_analysis, JA_result,
        TI_incident, TI_known_vuln, TI_new_feature, TI_analysis, TI_result,
        WC_fingerprint, WC_analysis, WC_result,
        OT_zoomeye, OT_urlscan, OT_fofa, OT_analysis, OT_result
    )

    task_map = {
        'UE_fetch_urls': UE_fetch_urls,
        'UE_distill_urls': UE_distill_urls,
        'UE_validate_urls': UE_validate_urls,
        'UE_analysis': UE_analysis,
        'UE_result': UE_result,
        'GD_dorking': GD_dorking,
        'GD_url_analysis': GD_url_analysis,
        'GD_file_download': GD_file_download,
        'GD_file_analysis': GD_file_analysis,
        'GD_result': GD_result,
        'GH_dorking': GH_dorking,
        'GH_analysis': GH_analysis,
        'GH_result': GH_result,
        'JA_collect': JA_collect,
        'JA_nuclei_scan': JA_nuclei_scan,
        'JA_noir_scan': JA_noir_scan,
        'JA_analysis': JA_analysis,
        'JA_result': JA_result,
        'TI_incident': TI_incident,
        'TI_known_vuln': TI_known_vuln,
        'TI_new_feature': TI_new_feature,
        'TI_analysis': TI_analysis,
        'TI_result': TI_result,
        'WC_fingerprint': WC_fingerprint,
        'WC_analysis': WC_analysis,
        'WC_result': WC_result,
        'OT_zoomeye': OT_zoomeye,
        'OT_urlscan': OT_urlscan,
        'OT_fofa': OT_fofa,
        'OT_analysis': OT_analysis,
        'OT_result': OT_result
    }
    
    tasks = []
    for phase in phases:
        for task_name in PHASES[phase]['tasks']:
            # Skip validation task if --skip-validation flag is set
            if skip_validation and task_name == 'UE_validate_urls':
                continue
            if task_name in task_map:
                tasks.append(task_map[task_name])

    return tasks

def create_crew_for_phases(phases, target, skip_validation=False):
    """Create CrewAI crew for specified phases."""
    from agent import (
        phase1_url_analyst,
        phase2_dorking_specialist,
        phase3_github_researcher,
        phase4_javascript_auditor,
        phase5_threat_researcher,
        phase6_infrastructure_analyst,
        phase7_osint_integrator
    )

    tasks = get_phase_tasks(phases, skip_validation=skip_validation)

    crew_config = {
        "agents": [
            phase1_url_analyst,
            phase2_dorking_specialist,
            phase3_github_researcher,
            phase4_javascript_auditor,
            phase5_threat_researcher,
            phase6_infrastructure_analyst,
            phase7_osint_integrator
        ],
        "tasks": tasks,
        "verbose": True,
        "output_log_file": f"results/{target}/crew_logs.txt",
        "memory": False,
    }
    
    return Crew(**crew_config)

def execute_phases(phases, target, skip_validation=False):
    """Execute the specified reconnaissance phases."""
    print(f"[*] Starting reconnaissance for target: {target}")
    print(f"[*] Phases to execute: {', '.join(phases)}")
    if skip_validation and 'url-enum' in phases:
        print(f"[*] URL validation step will be skipped (--skip-validation)")

    execution_phases = resolve_dependencies(phases)
    result_dir = f"results/{target}"

    for phase in execution_phases:
        print(f"[*] Checking dependencies for phase: {phase}")
        deps_ok, missing = check_dependencies(phase)
        if not deps_ok:
            print(f"[-] Error: Missing dependencies for phase '{phase}': {missing}")
            return False

    print(f"[*] Creating results directory: {result_dir}")
    Path(result_dir).mkdir(parents=True, exist_ok=True)

    try:
        print("[*] Initializing AI agents and tasks...")
        crew = create_crew_for_phases(execution_phases, target, skip_validation=skip_validation)
        print("[*] Starting reconnaissance execution...")
        crew.kickoff()

        print("[+] Reconnaissance completed successfully!")
        return True

    except KeyboardInterrupt:
        print("\n[!] Execution interrupted by user")
        return False

    except Exception as e:
        import traceback
        print(f"[-] Error during execution: {str(e)}")
        print(f"[-] Full traceback:\n{traceback.format_exc()}")
        return False

def main():
    """Main CLI entry point."""
    parser = create_parser()
    args = parser.parse_args()

    env_path = Path('.env')
    if not env_path.exists():
        print(f"[-] Error: .env file not found at {env_path.absolute()}")
        return 1

    config = load_env_config()
    if config is None:
        print("[-] Error: Failed to load configuration from .env")
        return 1

    if not validate_api_keys(config, args.phase):
        print(f"[-] Error: API key validation failed for phase '{args.phase}'")
        return 1

    if not args.target:
        print("[-] Error: Target domain not specified - use --target <domain>")
        return 1

    if not validate_domain(args.target):
        print(f"[-] Error: Invalid domain format: {args.target}")
        return 1

    if not update_env_target(args.target):
        print(f"[-] Error: Failed to update .env with target {args.target}")
        return 1
    
    load_dotenv(override=True)
    
    if args.report is not None and not args.all and not args.phase:
        output_path = args.report if args.report else None
        success = generate_report_for_target(args.target, output_path)
        return 0 if success else 1

    if args.all:
        phases = list(PHASES.keys())
    elif args.phase:
        if ',' in args.phase:
            phases = [p.strip() for p in args.phase.split(',')]
        else:
            phases = [args.phase.strip()]

        invalid = [p for p in phases if p not in PHASES]
        if invalid:
            print(f"[-] Error: Invalid phase(s): {', '.join(invalid)}")
            print(f"Valid phases: {', '.join(PHASES.keys())}")
            return 1
    else:
        print("[-] Error: No phase specified - use --phase <phase> or --all")
        return 1

    success = execute_phases(
        phases=phases,
        target=args.target,
        skip_validation=args.skip_validation
    )

    if args.report is not None:
        output_path = args.report if args.report else None
        generate_report_for_target(args.target, output_path)

    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())