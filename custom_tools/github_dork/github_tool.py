#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, json, time, requests, random
from typing import List, Dict, Any, Optional
from datetime import datetime

SECOND_LEVEL_TLDS = ['co', 'ac', 'gov', 'org', 'net', 'edu', 'mil', 'com']

NOISE_PATTERNS = ['-fake', '-example', '-test', '-XXXX', '-1234', '-ABCD',
                 '-dummy', '-sample', '-demo', '-mock', '-placeholder']

def extract_root_domain(domain: str) -> str:
    """Extract root domain from any subdomain."""
    parts = domain.split('.')
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL_TLDS:
        return '.'.join(parts[-3:])
    elif len(parts) >= 2:
        return '.'.join(parts[-2:])
    else:
        return domain

def extract_domain_info(target_domain: str) -> Dict[str, str]:
    """Extract domain information for comprehensive searching."""
    domain = target_domain.replace("https://", "").replace("http://", "").strip("/")
    root_domain = extract_root_domain(domain)
    parts = domain.split(".")

    if len(parts) >= 3:
        subdomain = parts[0]
        main_domain = ".".join(parts[1:])
        org_name = root_domain.split('.')[0]
    elif len(parts) == 2:
        subdomain = None
        main_domain = domain
        org_name = parts[0]
    else:
        subdomain = None
        main_domain = domain
        org_name = domain

    return {
        "original": target_domain,
        "clean_domain": domain,
        "subdomain": subdomain,
        "main_domain": main_domain,
        "root_domain": root_domain,
        "org_name": org_name
    }


class GitHubDorkingTool(BaseTool):
    name: str = "GitHub Dorking Tool"
    description: str = "Execute GitHub dorking queries using direct GitHub Search API for credential discovery"
    api_tokens: List[str] = []
    current_token_index: int = 0
    api_base: str = "https://api.github.com"
    session: Optional[requests.Session] = None
    pattern_filter: bool = True
    recently_indexed: bool = False
    max_results_per_dork: int = 10
    rate_limit_remaining: int = 30
    rate_limit_reset: Optional[datetime] = None

    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        single_token = os.getenv("GITHUB_API_TOKEN")
        multiple_tokens = os.getenv("GITHUB_API_TOKENS", "").split(',')

        if single_token and ',' in single_token:
            self.api_tokens = [t.strip() for t in single_token.split(',') if t.strip() and not self._is_placeholder(t.strip())]
        elif single_token and not self._is_placeholder(single_token):
            self.api_tokens = [single_token]
        elif multiple_tokens and multiple_tokens[0]:
            self.api_tokens = [t.strip() for t in multiple_tokens if t.strip() and not self._is_placeholder(t.strip())]
        else:
            self.api_tokens = []

        self.api_base = os.getenv("GITHUB_API_BASE", "https://api.github.com")
        self.pattern_filter = os.getenv("GITHUB_PATTERN_FILTER", "true").lower() == "true"
        self.recently_indexed = os.getenv("GITHUB_RECENTLY_INDEXED", "false").lower() == "true"
        self.max_results_per_dork = int(os.getenv("GITHUB_MAX_RESULTS_PER_DORK", "10"))

        self.session = requests.Session()

        if self.api_tokens:
            self.setup_session_with_token(self.api_tokens[0])
            self.validate_token()
        else:
            self.session.headers.update({
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": os.getenv("GITHUB_USER_AGENT", "ReconAgent-Security-Research/1.0")
            })

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        if not value:
            return True
        return 'your_' in value.lower() and '_here' in value.lower()

    def setup_session_with_token(self, token: str):
        """Setup session headers with the given token."""
        self.session.headers.update({
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": os.getenv("GITHUB_USER_AGENT", "ReconAgent-Security-Research/1.0")
        })

    def rotate_token(self):
        """Rotate to the next available token if multiple tokens are configured."""
        if len(self.api_tokens) > 1:
            self.current_token_index = (self.current_token_index + 1) % len(self.api_tokens)
            new_token = self.api_tokens[self.current_token_index]
            self.setup_session_with_token(new_token)
            return True
        return False

    def validate_token(self):
        """Validate GitHub API token on initialization."""
        try:
            response = self.session.get(f"{self.api_base}/user")
            if response.status_code == 401:
                    if self.rotate_token():
                        response = self.session.get(f"{self.api_base}/user")
                    if response.status_code == 401:
                        raise ValueError(f"[ERROR] Invalid GitHub API token(s). Please update GITHUB_API_TOKEN(S) in .env file.")
                    else:
                        raise ValueError(f"[ERROR] Invalid GitHub API token. Please update GITHUB_API_TOKEN in .env file.")
            elif response.status_code != 200:
                pass
            else:
                user = response.json().get("login", "Unknown")
                self.update_rate_limit_status(response.headers)

        except requests.exceptions.RequestException:
            pass

    def update_rate_limit_status(self, headers):
        """Update rate limit status from response headers."""
        try:
            self.rate_limit_remaining = int(headers.get("X-RateLimit-Remaining", 30))
            reset_time = int(headers.get("X-RateLimit-Reset", 0))
            if reset_time:
                self.rate_limit_reset = datetime.fromtimestamp(reset_time)
        except:
            pass

    def extract_root_domain_method(self, domain: str) -> str:
        return extract_root_domain(domain)

    def extract_domain_info_method(self, target_domain: str) -> Dict[str, str]:
        return extract_domain_info(target_domain)

    def load_github_dorks(self) -> List[str]:
        """Load GitHub dorks from file, excluding comments and empty lines."""
        dorks_file = os.path.join(os.path.dirname(__file__), 'github_dorks.txt')
        try:
            with open(dorks_file, 'r') as f:
                dorks = []
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        dorks.append(line)
                return dorks
        except FileNotFoundError:
            return []
        except Exception:
            return []

    def generate_search_terms(self, domain_info: Dict[str, str]) -> List[str]:
        """Generate optimized search terms for GitHub dorking."""
        terms = []
        if domain_info["org_name"] not in ['com', 'net', 'org', 'io', 'co', 'app'] and len(domain_info["org_name"]) > 3:
            terms.append(f'org:{domain_info["org_name"]}')
        return terms

    def build_query_with_filters(self, base_query: str) -> str:
        """Build query with noise pattern filters if enabled."""
        if self.pattern_filter:
            filtered_query = base_query + ' ' + ' '.join(NOISE_PATTERNS)
            return filtered_query
        return base_query

    def wait_for_rate_limit(self, retry_after: Optional[int] = None):
        """Wait for rate limit reset with exponential backoff."""
        if retry_after:
            wait_time = retry_after
        elif self.rate_limit_reset:
            wait_time = max(1, (self.rate_limit_reset - datetime.now()).total_seconds())
        else:
            wait_time = random.uniform(3, 5)

        if self.rotate_token():
            time.sleep(1)
        else:
            time.sleep(wait_time)

    def search_code(self, query: str, per_page: int = 10, max_results: int = None) -> List[Dict[str, Any]]:
        """Search for code using GitHub Search API with enhanced features."""
        if max_results is None:
            max_results = self.max_results_per_dork

        results = []
        page = 1

        filtered_query = self.build_query_with_filters(query)

        sort_param = "indexed" if self.recently_indexed else None

        while len(results) < max_results:
            try:
                url = f"{self.api_base}/search/code"
                params = {
                    "q": filtered_query,
                    "per_page": min(per_page, max_results - len(results)),
                    "page": page
                }

                if sort_param:
                    params["sort"] = sort_param
                    params["order"] = "desc"

                response = self.session.get(url, params=params)

                self.update_rate_limit_status(response.headers)

                if response.status_code == 403:
                    retry_after = int(response.headers.get("Retry-After", 5))
                    self.wait_for_rate_limit(retry_after)
                    continue
                elif response.status_code == 422:
                    break
                elif response.status_code == 401:
                    if self.rotate_token():
                        continue
                    else:
                        break
                elif response.status_code != 200:
                    break

                data = response.json()
                items = data.get("items", [])

                if not items:
                    break

                for item in items:
                    repo_info = item.get("repository", {})
                    result = {
                        "file_name": item.get("name", ""),
                        "file_path": item.get("path", ""),
                        "file_type": os.path.splitext(item.get("name", ""))[1].lstrip(".") or "unknown",
                        "html_url": item.get("html_url", ""),
                        "repository": repo_info.get("full_name", ""),
                        "repository_url": repo_info.get("html_url", ""),
                        "owner_type": repo_info.get("owner", {}).get("type", "User"),
                        "score": item.get("score", 0.0)
                    }
                    results.append(result)

                if len(items) < per_page:
                    break
                page += 1

                if self.rate_limit_remaining <= 5 and len(self.api_tokens) > 1:
                    if self.rotate_token():
                        time.sleep(0.1)
                    else:
                        time.sleep(2.5)
                elif self.rate_limit_remaining > 10:
                    time.sleep(0.5)
                else:
                    time.sleep(1.5)

            except Exception:
                break

        if len(results) > 1:
            results.sort(key=lambda x: x.get("score", 0), reverse=True)

        return results

    def assess_risk_level(self, item: Dict, repo_info: Dict) -> str:
        """Assess the risk level of a finding based on various factors."""
        risk_score = 0

        high_risk_extensions = ['.env', '.pem', '.key', '.p12', '.pfx']
        medium_risk_extensions = ['.json', '.yml', '.yaml', '.xml', '.ini', '.cfg']

        file_ext = os.path.splitext(item.get("name", ""))[1].lower()
        if file_ext in high_risk_extensions:
            risk_score += 3
        elif file_ext in medium_risk_extensions:
            risk_score += 2

        stars = repo_info.get("stargazers_count", 0)
        if stars > 1000:
            risk_score += 2
        elif stars > 100:
            risk_score += 1

        file_path = item.get("path", "").lower()
        if any(sensitive in file_path for sensitive in ['config', 'secret', 'credential', 'password', 'key']):
            risk_score += 2

        if risk_score >= 5:
            return "high"
        elif risk_score >= 3:
            return "medium"
        else:
            return "low"

    def classify_sensitive_data(self, file_path: str, query: str) -> str:
        """Classify the type of sensitive data based on file path and query."""
        file_path_lower = file_path.lower()
        query_lower = query.lower()

        if any(aws in query_lower for aws in ['aws', 'amazon', 's3', 'akia', 'asia']):
            return "AWS credentials"
        elif any(db in query_lower for db in ['mysql', 'postgres', 'mongodb', 'redis', 'database']):
            return "Database credentials"
        elif any(key in query_lower for key in ['private', 'rsa', 'pem', 'ppk', 'ssh']):
            return "Private keys"
        elif 'api' in query_lower or 'token' in query_lower:
            return "API keys/tokens"
        elif 'password' in query_lower or 'passwd' in query_lower:
            return "Passwords"
        elif '.env' in file_path_lower:
            return "Environment variables"
        elif any(cfg in file_path_lower for cfg in ['config', 'settings']):
            return "Configuration files"
        else:
            return "Sensitive information"

    def calculate_rank_score(self, item: Dict, repo_info: Dict) -> float:
        """Calculate a ranking score for prioritizing results."""
        score = 0.0

        stars = repo_info.get("stargazers_count", 0)
        forks = repo_info.get("forks_count", 0)
        score += min(stars / 100, 20)
        score += min(forks / 50, 10)

        try:
            updated_at = repo_info.get("updated_at", "")
            if updated_at:
                update_date = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                days_ago = (datetime.now(update_date.tzinfo) - update_date).days
                if days_ago < 30:
                    score += 15
                elif days_ago < 90:
                    score += 10
                elif days_ago < 365:
                    score += 5
        except:
            pass

        file_path = item.get("path", "").lower()
        if '.env' in file_path:
            score += 10
        elif any(cfg in file_path for cfg in ['.key', '.pem', 'secret', 'password']):
            score += 8
        elif any(cfg in file_path for cfg in ['config', 'credential']):
            score += 5

        github_score = item.get("score", 0)
        score += min(github_score / 10, 10)

        return score

    def execute_github_queries(self, target_domain: str) -> Dict[str, Any]:
        """Execute multiple GitHub search queries for a target domain."""
        domain_info = self.extract_domain_info_method(target_domain)
        search_terms = self.generate_search_terms(domain_info)

        dorks = self.load_github_dorks()
        if not dorks:
            dorks = ['password', 'api_key', 'secret', 'token', 'credentials']

        if search_terms:
            search_prefix = search_terms[0]
        else:
            search_prefix = f'"{domain_info["root_domain"]}"'

        all_results = []
        query_results = []
        successful_queries = 0

        for query_index, dork in enumerate(dorks, 1):
            full_query = f"{search_prefix} {dork}"

            print(f"[{query_index}/{len(dorks)}] {full_query}")

            try:
                search_results = self.search_code(full_query)

                if search_results:
                    successful_queries += 1

                    for result in search_results:
                        result["query_index"] = query_index
                        result["search_term"] = search_prefix
                        result["dork"] = dork
                        result["query_group"] = self.categorize_dork(dork)

                    query_results.append({
                        "query_index": query_index,
                        "search_term": search_prefix,
                        "dork": dork,
                        "full_query": full_query,
                        "repos_found": search_results
                    })
                    all_results.extend(search_results)

                if self.rate_limit_remaining <= 5 and len(self.api_tokens) > 1:
                    if self.rotate_token():
                        time.sleep(0.1)
                    else:
                        time.sleep(2.0)
                elif self.rate_limit_remaining > 20:
                    time.sleep(0.3)
                elif self.rate_limit_remaining > 10:
                    time.sleep(0.5)
                else:
                    time.sleep(1.0)

            except Exception:
                pass

        unique_repos = set(r["repository"] for r in all_results)

        summary_stats = {
            "credential_files": sum(1 for r in all_results if "env" in r.get("file_path", "").lower() or "config" in r.get("file_path", "").lower()),
            "total_repositories": len(unique_repos),
            "total_findings": len(all_results),
            "dorks_with_results": len(query_results),
            "dorks_executed": len(dorks),
            "successful_queries": successful_queries,
            "tokens_used": len(self.api_tokens) if self.api_tokens else 0
        }

        top_findings = sorted(all_results, key=lambda x: x.get("score", 0), reverse=True)[:10]

        return {
            "target": target_domain,
            "domain_info": domain_info,
            "search_terms": search_terms,
            "total_queries": len(dorks),
            "queries_with_results": len(query_results),
            "total_repos_found": len(unique_repos),
            "results": query_results,
            "summary_stats": summary_stats,
            "top_findings": top_findings,
            "configuration": {
                "pattern_filter": self.pattern_filter,
                "recently_indexed": self.recently_indexed,
                "max_results_per_dork": self.max_results_per_dork,
                "tokens_available": len(self.api_tokens)
            }
        }

    def categorize_dork(self, dork: str) -> str:
        """Categorize a dork based on its content."""
        dork_lower = dork.lower()

        if any(cloud in dork_lower for cloud in ['aws', 'amazon', 's3', 'azure', 'gcp', 'google']):
            return "Cloud Credentials"
        elif any(db in dork_lower for db in ['mysql', 'postgres', 'mongodb', 'redis', 'database', 'sql']):
            return "Database"
        elif any(key in dork_lower for key in ['private', 'rsa', 'pem', 'ppk', 'ssh', '.key']):
            return "Private Keys"
        elif 'api' in dork_lower or 'token' in dork_lower:
            return "API Keys"
        elif 'password' in dork_lower or 'passwd' in dork_lower:
            return "Passwords"
        elif '.env' in dork_lower or 'environment' in dork_lower:
            return "Environment"
        elif any(cfg in dork_lower for cfg in ['config', 'settings', '.cfg', '.ini']):
            return "Configuration"
        elif 'filename:' in dork_lower:
            return "Sensitive Files"
        elif 'extension:' in dork_lower:
            return "File Extensions"
        else:
            return "General Secrets"

    def _run(self, target_domain: str) -> str:
        """Execute GitHub dorking for the target domain and return JSON results."""
        if not self.api_tokens:
            no_token_result = {
                "target": target_domain,
                "status": "NO GITHUB API TOKEN",
                "findings": [],
                "message": "GitHub search requires API token. Set GITHUB_API_TOKEN in .env file",
                "queries_executed": 0
            }
            self._search_results = no_token_result
            return json.dumps(no_token_result)

        try:
            results = self.execute_github_queries(target_domain)
            total_files = sum(len(q.get("repos_found", [])) for q in results.get("results", []))

            if total_files == 0 or results.get('total_repos_found', 0) == 0:
                empty_result = {
                    "target": target_domain,
                    "status": "NO CREDENTIAL EXPOSURES FOUND",
                    "findings": [],
                    "message": f"No GitHub repositories found for {target_domain}",
                    "queries_executed": results.get('total_queries', 0),
                    "search_terms": results.get('search_terms', []),
                    "configuration": results.get('configuration', {})
                }
                self._search_results = empty_result
                return json.dumps(empty_result)

            stats = results.get('summary_stats', {})
            message = (f"GitHub dorking completed for {target_domain}: "
                      f"{total_files} files found across {results.get('total_repos_found', 0)} repositories. "
                      f"Executed {stats.get('successful_queries', 0)}/{results.get('total_queries', 0)} queries successfully.")

            self._search_results = results
            return json.dumps(results.get('results', []), indent=2)

        except Exception as e:
            error_result = {
                "target": target_domain,
                "status": "ERROR",
                "findings": [],
                "error": str(e)
            }
            self._search_results = error_result
            return f"GitHub dorking failed for {target_domain}: {str(e)}"