#!/usr/bin/env python3
"""URL Validator Tool - Validates collected URLs by checking HTTP status codes."""

from crewai.tools import BaseTool
import os
import json
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Any
from urllib.parse import urljoin


class URLValidatorTool(BaseTool):
    """Tool for validating collected URLs by checking their HTTP status codes."""

    name: str = "URL Validator"
    description: str = "Validate collected URLs by checking HTTP status codes and filter alive URLs"

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

    def _create_session(self) -> requests.Session:
        """Create a requests session with retry strategy."""
        session = requests.Session()

        # Only retry on 429 (rate limit) - preserve 5xx responses for SSRF analysis
        retry_strategy = Retry(
            total=2,
            backoff_factor=0.5,
            status_forcelist=[429],
            allowed_methods=["HEAD", "GET"]
        )

        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Connection': 'keep-alive',
        })

        return session

    def _validate_url(self, session: requests.Session, base_url: str, path: str) -> Dict[str, Any]:
        """Validate a single URL by sending HEAD request, fallback to GET if needed."""
        full_url = urljoin(base_url, path)

        result = {
            'url': path,
            'full_url': full_url,
            'status_code': None,
            'content_length': None,
            'content_type': None,
            'is_alive': False,
            'security_interest': None,  # 'auth_bypass' (401/403) or 'ssrf_potential' (5xx)
            'error': None
        }

        try:
            # Try HEAD request first (faster)
            response = session.head(full_url, timeout=5, allow_redirects=True)

            # Some servers don't support HEAD, fallback to GET
            if response.status_code == 405:
                response = session.get(full_url, timeout=5, allow_redirects=True, stream=True)
                response.close()

            result['status_code'] = response.status_code
            result['content_length'] = response.headers.get('Content-Length')
            result['content_type'] = response.headers.get('Content-Type', '').split(';')[0].strip()

            # Security interest classification
            if response.status_code in (401, 403):
                result['security_interest'] = 'auth_bypass'
            elif response.status_code >= 500:
                result['security_interest'] = 'ssrf_potential'

            # Consider URL alive if: 2xx/3xx (normal) OR 401/403 (bypass target) OR 5xx (SSRF target)
            result['is_alive'] = (
                200 <= response.status_code < 400 or
                response.status_code in (401, 403) or
                response.status_code >= 500
            )

        except requests.exceptions.Timeout:
            result['error'] = 'timeout'
        except requests.exceptions.ConnectionError:
            result['error'] = 'connection_error'
        except requests.exceptions.TooManyRedirects:
            result['error'] = 'too_many_redirects'
        except requests.exceptions.RequestException as e:
            result['error'] = str(e)[:100]

        return result

    def _run(self, domain: str) -> str:
        """Execute URL validation for the specified domain."""
        result_dir = os.getenv("RESULT_DIR")
        if not result_dir:
            return json.dumps({"status": "ERROR", "message": "RESULT_DIR environment variable not set"})

        # Input file path
        urls_file = os.path.join(result_dir, "phase1", "url", "urls.txt")
        if not os.path.exists(urls_file):
            return json.dumps({"status": "ERROR", "message": f"URLs file not found: {urls_file}"})

        # Output paths
        url_dir = os.path.join(result_dir, "phase1", "url")
        alive_urls_file = os.path.join(url_dir, "alive_urls.txt")
        validated_json_file = os.path.join(url_dir, "validated_urls.json")

        # Read URLs to validate
        with open(urls_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]

        if not urls:
            return json.dumps({"status": "ERROR", "message": "No URLs to validate"})

        # Determine base URL
        base_url = f"https://{domain}"

        # Create session
        session = self._create_session()

        # Validate URLs in parallel
        max_workers = int(os.getenv("URL_VALIDATOR_WORKERS", "10"))
        validated_results: List[Dict[str, Any]] = []
        alive_urls: List[str] = []

        try:
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_url = {
                    executor.submit(self._validate_url, session, base_url, url): url
                    for url in urls
                }

                for future in as_completed(future_to_url):
                    result = future.result()
                    validated_results.append(result)
                    if result['is_alive']:
                        alive_urls.append(result['url'])

        except Exception as e:
            return json.dumps({"status": "ERROR", "message": f"Validation failed: {str(e)}"})

        finally:
            session.close()

        # Sort results by URL for consistency
        validated_results.sort(key=lambda x: x['url'])
        alive_urls.sort()

        # Write alive URLs
        with open(alive_urls_file, 'w', encoding='utf-8') as f:
            for url in alive_urls:
                f.write(f"{url}\n")

        # Write detailed validation results
        with open(validated_json_file, 'w', encoding='utf-8') as f:
            json.dump(validated_results, f, indent=2, ensure_ascii=False)

        # Generate summary statistics
        total = len(urls)
        alive = len(alive_urls)
        dead = total - alive

        status_codes = {}
        for r in validated_results:
            code = r.get('status_code')
            if code:
                status_codes[code] = status_codes.get(code, 0) + 1

        # Security interest counts
        auth_bypass_count = sum(1 for r in validated_results if r.get('security_interest') == 'auth_bypass')
        ssrf_potential_count = sum(1 for r in validated_results if r.get('security_interest') == 'ssrf_potential')

        summary = {
            "status": "SUCCESS",
            "total_urls": total,
            "alive_urls": alive,
            "dead_urls": dead,
            "alive_percentage": round(alive / total * 100, 1) if total > 0 else 0,
            "security_interest": {
                "auth_bypass": auth_bypass_count,
                "ssrf_potential": ssrf_potential_count
            },
            "status_code_distribution": dict(sorted(status_codes.items())),
            "output_files": {
                "alive_urls": alive_urls_file,
                "validated_json": validated_json_file
            }
        }

        return json.dumps(summary, indent=2)
