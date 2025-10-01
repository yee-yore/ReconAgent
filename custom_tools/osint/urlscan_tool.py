#!/usr/bin/env python3
"""URLScan.io Web Security Analysis Tool using API for security assessment."""

import os, json, time, requests
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Type
from urllib.parse import urljoin, urlparse

from crewai.tools import BaseTool
from pydantic import BaseModel, Field

class URLScanInput(BaseModel):
    """URLScan tool input schema"""
    domain: str = Field(..., description="Domain to analyze (e.g., example.com)")

class URLScanTool(BaseTool):
    """URLScan.io Web Security Analysis Tool"""
    
    name: str = "URLScan Web Security Analyzer"
    description: str = (
        "Uses URLScan.io API to perform security analysis of domain-related websites. "
        "Provides comprehensive web security assessment through phishing site detection, malicious code hosting verification, "
        "screenshot and DOM analysis, and network connection information collection."
    )
    args_schema: Type[BaseModel] = URLScanInput
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        object.__setattr__(self, 'api_key', os.getenv('URLSCAN_API_KEY'))
        object.__setattr__(self, 'base_url', "https://urlscan.io/api/v1")
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })
        
        if self.api_key:
            session.headers['API-Key'] = self.api_key
            
        object.__setattr__(self, 'session', session)
    
    def _make_request(self, endpoint: str, method: str = 'GET', 
                     params: Optional[Dict] = None, json_data: Optional[Dict] = None) -> Optional[Dict]:
        """Execute API request"""
        try:
            url = urljoin(self.base_url + '/', endpoint)
            
            if method == 'GET':
                response = self.session.get(url, params=params, timeout=30)
            elif method == 'POST':
                response = self.session.post(url, json=json_data, timeout=30)
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 429:
                reset_after = response.headers.get('X-Rate-Limit-Reset-After')
                if reset_after:
                    time.sleep(int(reset_after) + 1)
                else:
                    time.sleep(60)
                return None
            elif response.status_code == 404:
                return {'status': 'not_found', 'message': 'Resource not found'}
            elif response.status_code == 410:
                return {'status': 'deleted', 'message': 'Resource deleted'}
            elif response.status_code == 400:
                return None
            elif response.status_code == 403:
                return None
            else:
                return None
                
        except requests.exceptions.RequestException:
            return None
    
    def search_domain(self, domain: str, limit: int = 100) -> List[Dict]:
        """Search domain-related scan results - modified query"""
        search_queries = [
            f'domain:{domain}',
            f'page.domain:{domain}',
            f'task.url:"{domain}"',
        ]
        
        all_results = []
        
        for query in search_queries:
            
            params = {
                'q': query,
                'size': min(limit, 10000)
            }
            
            result = self._make_request('search/', params=params)
            
            if result and result.get('results'):
                all_results.extend(result['results'])
            elif result is None:
                continue
            else:
                continue
                
            time.sleep(2)
        
        seen_uuids = set()
        unique_results = []
        
        for result in all_results:
            uuid = result.get('_id')
            if uuid and uuid not in seen_uuids:
                seen_uuids.add(uuid)
                unique_results.append(result)
        
        return unique_results[:limit]
    
    def submit_scan(self, url: str, visibility: str = 'unlisted', 
                   tags: Optional[List[str]] = None) -> Optional[Dict]:
        """Submit new URL scan"""
        if not self.api_key:
            return None
        
        scan_data = {
            'url': url,
            'visibility': visibility
        }
        
        if tags:
            scan_data['tags'] = tags[:10]
        
        result = self._make_request('scan/', method='POST', json_data=scan_data)
        
        if result and result.get('uuid'):
            return result
        
        return None
    
    def get_scan_result(self, uuid: str, max_wait: int = 300) -> Optional[Dict]:
        """Retrieve scan results (including polling)"""
        start_time = time.time()
        
        while time.time() - start_time < max_wait:
            result = self._make_request(f'result/{uuid}/')
            
            if result:
                if result.get('status') == 'not_found':
                    time.sleep(10)
                    continue
                elif result.get('status') == 'deleted':
                    return None
                else:
                    return result
            
            time.sleep(5)
        
        return None
    
    def analyze_scan_results(self, scan_results: List[Dict]) -> Dict[str, Any]:
        """Analyze scan results and extract security insights - error fixed"""
        analysis = {
            'total_scans': len(scan_results),
            'scan_summary': {
                'malicious': 0,
                'suspicious': 0,
                'clean': 0,
                'unknown': 0
            },
            'technology_stack': set(),
            'security_issues': [],
            'network_analysis': {
                'unique_ips': set(),
                'unique_domains': set(),
                'suspicious_connections': []
            },
            'certificate_analysis': [],
            'screenshot_urls': [],
            'recent_scans': []
        }
        
        for scan in scan_results:
            try:
                uuid = scan.get('_id', '')
                task = scan.get('task', {})
                page = scan.get('page', {})
                stats = scan.get('stats', {})
                
                scan_time = task.get('time')
                if scan_time:
                    analysis['recent_scans'].append({
                        'uuid': uuid,
                        'url': task.get('url', ''),
                        'time': scan_time,
                        'title': page.get('title', 'No title')
                    })
                
                verdicts = scan.get('verdicts', {})
                if verdicts:
                    overall = verdicts.get('overall', {})
                    if overall.get('malicious', 0) > 0:
                        analysis['scan_summary']['malicious'] += 1
                    elif overall.get('suspicious', 0) > 0:
                        analysis['scan_summary']['suspicious'] += 1
                    else:
                        analysis['scan_summary']['clean'] += 1
                else:
                    analysis['scan_summary']['unknown'] += 1
                
                if 'lists' in scan:
                    lists = scan['lists']
                    if 'servers' in lists and isinstance(lists['servers'], (list, set)):
                        analysis['technology_stack'].update(lists['servers'])
                
                if 'stats' in scan:
                    stats = scan['stats']
                    if 'uniqIPs' in stats:
                        uniq_ips = stats['uniqIPs']
                        if isinstance(uniq_ips, list):
                            analysis['network_analysis']['unique_ips'].update(
                                str(ip) for ip in uniq_ips
                            )
                        elif isinstance(uniq_ips, int):
                            pass
                    
                    if 'requests' in stats:
                        requests_data = stats['requests']
                        if isinstance(requests_data, list):
                            for req in requests_data[:10]:
                                if isinstance(req, dict) and 'request' in req:
                                    request_info = req['request']
                                    url = request_info.get('url', '')
                                    if url:
                                        domain = urlparse(url).netloc
                                        if domain:
                                            analysis['network_analysis']['unique_domains'].add(domain)
                
                if uuid:
                    analysis['screenshot_urls'].append(f"https://urlscan.io/screenshots/{uuid}.png")
                
                if page:
                    title = page.get('title', '').lower()
                    url = task.get('url', '').lower()
                    
                    suspicious_keywords = [
                        'login', 'signin', 'password', 'admin', 'panel',
                        'phishing', 'verification', 'suspended', 'locked',
                        'security', 'alert', 'warning', 'error', 'expired'
                    ]
                    
                    found_keywords = [kw for kw in suspicious_keywords if kw in title or kw in url]
                    if found_keywords:
                        analysis['security_issues'].append({
                            'uuid': uuid,
                            'url': task.get('url', ''),
                            'issue': 'Suspicious keywords detected',
                            'keywords': found_keywords,
                            'title': page.get('title', '')
                        })
                
            except Exception:
                continue
        
        analysis['technology_stack'] = list(analysis['technology_stack'])
        analysis['network_analysis']['unique_ips'] = list(analysis['network_analysis']['unique_ips'])
        analysis['network_analysis']['unique_domains'] = list(analysis['network_analysis']['unique_domains'])
        
        analysis['recent_scans'].sort(key=lambda x: x.get('time', ''), reverse=True)
        analysis['recent_scans'] = analysis['recent_scans'][:20]
        
        return analysis
    
    def get_user_quotas(self) -> Optional[Dict]:
        """Query user quotas"""
        if not self.api_key:
            return None
        return self._make_request('user/quotas/')
    
    def check_recent_submissions(self, domain: str, hours: int = 24) -> List[Dict]:
        """Check recently submitted scans - modified query"""
        cutoff_time = datetime.now() - timedelta(hours=hours)
        cutoff_date = cutoff_time.strftime('%Y-%m-%d')
        
        params = {
            'q': f'domain:{domain} AND task.time:>{cutoff_date}',
            'size': 100
        }
        
        result = self._make_request('search/', params=params)
        return result.get('results', []) if result else []
    
    def _run(self, domain: str) -> str:
        """Tool execution main function"""
        try:
            quotas = None
            if self.api_key:
                quotas = self.get_user_quotas()
            
            search_results = self.search_domain(domain, limit=500)
            
            analysis = self.analyze_scan_results(search_results)

            recent_submissions = self.check_recent_submissions(domain)
            
            should_scan_new = len(recent_submissions) == 0 and self.api_key
            
            new_scan_result = None
            if should_scan_new:
                scan_submission = self.submit_scan(f"https://{domain}", visibility='unlisted', 
                                                 tags=['security-research', 'automated'])
                
                if scan_submission:
                    uuid = scan_submission.get('uuid')
                    if uuid:
                        new_scan_result = self.get_scan_result(uuid, max_wait=120)
            
            final_result = {
                'domain': domain,
                'scan_time': datetime.now().isoformat(),
                'api_quotas': quotas,
                'search_summary': {
                    'total_found': len(search_results),
                    'recent_submissions': len(recent_submissions)
                },
                'security_analysis': analysis,
                'raw_search_results': search_results[:50],
                'new_scan_result': new_scan_result,
                'success': True
            }
            
            return json.dumps(final_result, default=str, ensure_ascii=False)
            
        except Exception as e:
            error_result = {
                'domain': domain,
                'error': str(e),
                'scan_time': datetime.now().isoformat(),
                'success': False
            }
            return json.dumps(error_result, ensure_ascii=False)