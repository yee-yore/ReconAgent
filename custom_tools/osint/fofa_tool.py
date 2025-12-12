#!/usr/bin/env python3
"""FOFA Cyberspace Asset Search Tool for comprehensive asset discovery."""

import os, json, time, base64, requests
from datetime import datetime
from typing import Dict, Any, Optional
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

class FOFAInput(BaseModel):
    """FOFA tool input schema"""
    domain: str = Field(..., description="Domain to analyze (e.g., example.com)")

class FOFASearchTool(BaseTool):
    """FOFA Cyberspace Asset Search Tool"""
    
    name: str = "FOFA Asset Search"
    description: str = (
        "Search cyberspace assets related to domain using FOFA API. "
        "Collect information about hosts, ports, services, SSL certificates, tech stack "
        "for attack surface analysis and vulnerability discovery."
    )
    args_schema: type[BaseModel] = FOFAInput
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        api_key = os.getenv('FOFA_API_KEY', '')

        # Skip if placeholder or missing
        if not api_key or self._is_placeholder(api_key):
            object.__setattr__(self, 'api_key', None)
        else:
            object.__setattr__(self, 'api_key', api_key)
        object.__setattr__(self, 'base_url', os.getenv('FOFA_BASE_URL', "https://fofa.info/api/v1"))
        object.__setattr__(self, 'free_account_mode', False)
        
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36'
        })
        object.__setattr__(self, 'session', session)

    def _is_placeholder(self, value: str) -> bool:
        """Check if value is a placeholder."""
        if not value:
            return True
        return 'your_' in value.lower() and '_here' in value.lower()

    def _encode_query(self, query: str) -> str:
        """Encode query to base64"""
        return base64.b64encode(query.encode('utf-8')).decode('utf-8')
    
    def _make_request(self, endpoint: str, params: Dict) -> Optional[Dict]:
        """Execute API request with detailed error handling"""
        try:
            params['key'] = self.api_key
            url = f"{self.base_url}/{endpoint}"
            
            response = self.session.get(url, params=params, timeout=30)
            
            
            if response.status_code == 200:
                json_response = response.json()
                
                if 'error' in json_response and json_response['error']:
                    error_msg = json_response.get('errmsg', 'Unknown error')
                    error_code = json_response.get('error', '')
                    
                    if '820001' in error_msg:
                        object.__setattr__(self, 'free_account_mode', True)
                        raise ValueError(f"FOFA_FREE_ACCOUNT_RESTRICTION: {error_msg}")
                    
                    if 'credit' in error_msg.lower() or 'insufficient' in error_msg.lower():
                        raise ValueError(f"FOFA API credits exhausted: {error_msg}")
                    
                    if 'auth' in error_msg.lower() or 'invalid' in error_msg.lower() or 'key' in error_msg.lower():
                        raise ValueError(f"FOFA API authentication failed: {error_msg}")
                    
                    return None
                
                result_count = len(json_response.get('results', []))
                return json_response
                
            elif response.status_code == 401:
                raise ValueError("FOFA API authentication failed - invalid API key")
            elif response.status_code == 403:
                raise ValueError("FOFA API access forbidden - check credits or permissions")
            elif response.status_code == 429:
                time.sleep(10)
                return None
            else:
                return None
                
        except requests.exceptions.RequestException as e:
            return None
    
    def search_assets(self, domain: str, max_pages: int = 10) -> Dict[str, Any]:
        """Search domain-related assets - automatic free/paid account adaptation"""
        
        free_queries = [
            f'host="dev.{domain}"',
            f'host="test.{domain}" OR host="staging.{domain}" OR host="admin.{domain}"',

            f'domain="{domain}" && (title="admin" OR title="phpMyAdmin" OR title="login")',

            f'domain="{domain}" && title="Index of"',

            f'domain="{domain}" && (title="500" OR title="403" OR title="404")',

            f'domain="{domain}" && (title="API" OR title="phpinfo")',
        ]
        
        paid_queries = [
            f'domain="{domain}" && (product="WordPress" OR product="Drupal")',
            f'domain="{domain}" && (product="Jenkins" OR product="GitLab")'
        ]
        
        if self.free_account_mode:
            search_queries = free_queries
        else:
            search_queries = free_queries + paid_queries
        
        collected_data = {}
        total_results = 0
        
        for i, query in enumerate(search_queries, 1):
            
            query_results = []
            
            try:
                for page in range(1, max_pages + 1):
                    if self.free_account_mode:
                        fields = 'host,ip,port,title'
                    else:
                        fields = 'host,ip,port,protocol,country,title,server,product,os,asn,org,cert,domain'
                    
                    params = {
                        'qbase64': self._encode_query(query),
                        'fields': fields,
                        'page': page,
                        'size': 100,
                        'r_type': 'json'
                    }
                    
                    result = self._make_request('search/all', params)
                    
                    
                    if not result:
                        break
                    
                    if result.get('error'):
                        error_msg = result.get('errmsg', 'Unknown error')
                        break
                    
                    results = result.get('results', [])
                    size = result.get('size', 0)
                    total = result.get('total', 0)
                    
                    
                    if not results:
                        break
                    
                    
                    for item in results:
                        if isinstance(item, list) and len(item) >= 1:
                            if self.free_account_mode:
                                structured_item = {
                                    'host': item[0] if len(item) > 0 else '',
                                    'ip': item[1] if len(item) > 1 else '',
                                    'port': item[2] if len(item) > 2 else '',
                                    'title': item[3] if len(item) > 3 else '',
                                    'protocol': '',
                                    'country': '',
                                    'server': '',
                                    'product': '',
                                    'os': '',
                                    'asn': '',
                                    'org': '',
                                    'cert': '',
                                    'domain': ''
                                }
                            else:
                                        structured_item = {
                                    'host': item[0] if len(item) > 0 else '',
                                    'ip': item[1] if len(item) > 1 else '',
                                    'port': item[2] if len(item) > 2 else '',
                                    'protocol': item[3] if len(item) > 3 else '',
                                    'country': item[4] if len(item) > 4 else '',
                                    'title': item[5] if len(item) > 5 else '',
                                    'server': item[6] if len(item) > 6 else '',
                                    'product': item[7] if len(item) > 7 else '',
                                    'os': item[8] if len(item) > 8 else '',
                                    'asn': item[9] if len(item) > 9 else '',
                                    'org': item[10] if len(item) > 10 else '',
                                    'cert': item[11] if len(item) > 11 else '',
                                    'domain': item[12] if len(item) > 12 else ''
                                }
                            query_results.append(structured_item)

                    total_results += len(results)
                    
                    time.sleep(0.5)
                    
                    if len(results) < 50:
                        break
                
                collected_data[query] = {
                    'total_results': len(query_results),
                    'data': query_results
                }
                
            except Exception as e:
                error_msg = str(e)
                
                if 'FOFA_FREE_ACCOUNT_RESTRICTION' in error_msg:
                    break
                
                collected_data[query] = {
                    'error': error_msg,
                    'total_results': 0,
                    'data': []
                }
                
                if 'credit' in error_msg.lower() or 'insufficient' in error_msg.lower():
                    break
            
            time.sleep(1)
        
        if self.free_account_mode and len(collected_data) < len(search_queries):
            remaining_errors = sum(1 for q in collected_data.values() if 'FOFA_FREE_ACCOUNT_RESTRICTION' in q.get('error', ''))
            if remaining_errors > 0:
                return self.search_assets(domain, max_pages)
        
        return {
            'domain': domain,
            'scan_time': datetime.now().isoformat(),
            'total_queries': len(search_queries),
            'total_results': total_results,
            'query_results': collected_data
        }
    
    
    def categorize_finding_risk(self, item: Dict[str, Any], query: str) -> str:
        """Categorize risk level of discovered assets"""
        host = item.get('host', '').lower()
        title = item.get('title', '').lower()
        product = item.get('product', '').lower()
        port = str(item.get('port', '')).lower()
        
        critical_indicators = [
            '.git' in query or 'git' in title or 'gitconfig' in title,
            '.env' in query or 'config.php' in query or 'wp-config' in query,
            '.sql' in query or '.db' in query or '.backup' in query,
            'phpmyadmin' in title or 'adminer' in title or 'pma' in host,
            'admin:admin' in query or 'default password' in query,
            'phpinfo' in title or 'server information' in title
        ]
        
        high_indicators = [
            'admin' in title or 'dashboard' in title or 'wp-admin' in query,
            any(env in host for env in ['dev.', 'test.', 'staging.', 'beta.']),
            'jenkins' in title or 'gitlab' in title or 'jenkins' in product,
            'upload' in title or 'file manager' in title,
            'swagger' in title or 'api documentation' in title,
            'index of' in title or 'directory listing' in title,
            'router' in title or 'firewall' in title or product in ['cisco', 'ubiquiti']
        ]
        
        medium_indicators = [
            'apache' in product or 'nginx' in product or 'iis' in product,
            port in ['3306', '5432', '1521', '27017', '6379'],
            port in ['22', '23', '3389'],
            '500' in title or '403' in title or 'error' in title,
            'wordpress' in product or 'drupal' in product or 'joomla' in product
        ]
        
        if any(critical_indicators):
            return 'critical'
        elif any(high_indicators):
            return 'high'
        elif any(medium_indicators):
            return 'medium'
        else:
            return 'low'
    
    def extract_summary_stats(self, search_results: Dict[str, Any]) -> Dict[str, Any]:
        """Extract summary statistics from search results (including risk levels)"""
        unique_ips = set()
        unique_hosts = set()
        unique_ports = set()
        unique_products = set()
        unique_countries = set()
        
        risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
        high_value_findings = []
        
        for query, query_data in search_results['query_results'].items():
            for item in query_data.get('data', []):
                if item.get('ip'):
                    unique_ips.add(item['ip'])
                if item.get('host'):
                    unique_hosts.add(item['host'])
                if item.get('port'):
                    unique_ports.add(str(item['port']))
                if item.get('product'):
                    unique_products.add(item['product'])
                if item.get('country'):
                    unique_countries.add(item['country'])
                
                risk_level = self.categorize_finding_risk(item, query)
                risk_counts[risk_level] += 1
                
                if risk_level in ['critical', 'high']:
                    high_value_findings.append({
                        'host': item.get('host'),
                        'ip': item.get('ip'),
                        'port': item.get('port'),
                        'title': item.get('title'),
                        'product': item.get('product'),
                        'risk_level': risk_level,
                        'query_matched': query[:100] + '...' if len(query) > 100 else query
                    })
        
        return {
            'unique_ips': len(unique_ips),
            'unique_hosts': len(unique_hosts), 
            'unique_ports': len(unique_ports),
            'unique_products': len(unique_products),
            'unique_countries': len(unique_countries),
            'risk_distribution': risk_counts,
            'total_critical_high': risk_counts['critical'] + risk_counts['high'],
            'high_value_findings': high_value_findings[:50],
            'top_ips': list(unique_ips)[:20],
            'top_hosts': list(unique_hosts)[:50],
            'top_ports': list(unique_ports)[:20],
            'top_products': list(unique_products)[:20],
            'countries': list(unique_countries)
        }
    
    def _run(self, domain: str) -> str:
        """Tool execution main function"""
        try:
            
            search_results = self.search_assets(domain)
            
            total_queries = len(search_results.get('query_results', {}))
            error_queries = sum(1 for q in search_results.get('query_results', {}).values() 
                               if 'error' in q)
            
            
            if total_queries > 0 and (error_queries / total_queries) >= 0.8:
                credit_errors = 0
                for query_data in search_results.get('query_results', {}).values():
                    if 'error' in query_data:
                        error_msg = query_data.get('error', '').lower()
                        if 'credit' in error_msg or 'insufficient' in error_msg:
                            credit_errors += 1
                
                if credit_errors > 0:
                    skip_result = {
                        'domain': domain,
                        'scan_time': datetime.now().isoformat(),
                        'status': 'skipped',
                        'reason': 'FOFA API credits exhausted',
                        'message': 'FOFA reconnaissance skipped due to insufficient API credits. Please check your FOFA account credits.',
                        'summary_stats': {
                            'unique_ips': 0,
                            'unique_hosts': 0,
                            'unique_ports': 0,
                            'unique_products': 0,
                            'unique_countries': 0,
                            'risk_distribution': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                            'total_critical_high': 0,
                            'high_value_findings': [],
                            'top_ips': [],
                            'top_hosts': [],
                            'top_ports': [],
                            'top_products': [],
                            'countries': []
                        },
                        'search_results': {
                            'domain': domain,
                            'scan_time': datetime.now().isoformat(),
                            'total_queries': total_queries,
                            'total_results': 0,
                            'query_results': {}
                        },
                        'success': False
                    }
                    return json.dumps(skip_result, default=str, ensure_ascii=False)
            
            summary_stats = self.extract_summary_stats(search_results)
            
            final_result = {
                'domain': domain,
                'scan_time': search_results['scan_time'],
                'summary_stats': summary_stats,
                'search_results': search_results,
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