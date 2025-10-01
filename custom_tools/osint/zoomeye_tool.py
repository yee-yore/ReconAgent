#!/usr/bin/env python3
"""ZoomEye Raw Data Collection Tool for domain reconnaissance."""

import os, json, base64, requests
from datetime import datetime
from typing import Type, Dict, Any
from crewai.tools import BaseTool
from pydantic import BaseModel, Field

class ZoomEyeInput(BaseModel):
    """ZoomEye tool input schema"""
    domain: str = Field(..., description="Domain to analyze (e.g., example.com)")

class ZoomEyeSDK:
    """ZoomEye API client"""
    
    def __init__(self, api_key=""):
        self.api_key = api_key
        self.search_api = "https://api.zoomeye.ai/v2/search"

    def _request(self, url, params=None, headers=None, method='GET'):
        """Handle HTTP requests"""
        try:
            if method == "GET":
                resp = requests.get(url, params=params, headers=headers, timeout=30)
            elif method == "POST" and headers.get("Content-Type", "") == "application/json":
                resp = requests.post(url, json=params, headers=headers, timeout=30)
            else:
                resp = requests.post(url, data=params, headers=headers, timeout=30)

            if resp and resp.status_code == 200:
                return resp.json()
            elif resp.status_code == 403 and 'specified resource' in resp.text:
                return None
            else:
                error_msg = "Unknown error"
                try:
                    error_msg = resp.json().get('message', 'Unknown error')
                except Exception:
                    error_msg = resp.text
                raise ValueError(f"API Error: {error_msg}")
                
        except requests.exceptions.Timeout:
            raise ValueError("Request timeout")
        except requests.exceptions.ConnectionError:
            raise ValueError("Connection error")

    def _check_header(self):
        """Generate headers"""
        headers = {'API-KEY': self.api_key} if self.api_key else {}
        headers["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
        return headers

    def search(self, dork, page=1, pagesize=100, sub_type='v4', fields=None):
        """Execute search - supports official API parameters"""
        dork_encoded = base64.b64encode(dork.encode('utf-8')).decode('utf-8')
        
        headers = self._check_header()
        headers["Content-Type"] = "application/json"
        
        params = {
            "qbase64": dork_encoded,
            "page": page,
            "pagesize": min(pagesize, 10000),
            "sub_type": sub_type
        }
        
        if fields:
            params["fields"] = fields
        
        resp = self._request(self.search_api, method='POST', params=params, headers=headers)
        return resp

class ZoomEyeOSINTTool(BaseTool):
    """ZoomEye Raw Data Collection Tool"""
    
    name: str = "ZoomEye Data Collector"
    description: str = (
        "Collects domain-related raw data using ZoomEye. "
        "Provides raw data including hostnames, subdomains, SSL certificates, and organization information."
    )
    args_schema: Type[BaseModel] = ZoomEyeInput
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        api_key = os.getenv('ZOOMEYE_API_KEY')
        if not api_key:
            raise ValueError("ZOOMEYE_API_KEY environment variable is required")
        self._zm = ZoomEyeSDK(api_key=api_key)
    
    def collect_data(self, domain: str, max_pages: int = 5) -> Dict[str, Any]:
        """Collect domain-related data - comprehensive collection for bug hunting/penetration testing"""
        
        COMMON_WEB_PORTS = "(port:80 OR port:443 OR port:8080 OR port:8443 OR port:9000 OR port:8000 OR port:3000 OR port:5000 OR port:8888 OR port:9999)"
        DB_PORTS         = "(port:3306 OR port:5432 OR port:1521 OR port:27017 OR port:6379 OR port:5984 OR port:9200)"
        REMOTE_PORTS     = "(port:22 OR port:23 OR port:3389 OR port:5985 OR port:5986)"
        FILE_PORTS       = "(port:21 OR port:990 OR port:445 OR port:139)"
        CACHE_PORTS      = "(port:11211 OR port:6379 OR port:6080)"
        MQ_PORTS         = "(port:15672 OR port:9092 OR port:61616)"

        queries = [
            f'hostname:"{domain}" (title:"admin" OR title:"login" OR title:"dashboard" OR title:"phpmyadmin" OR title:"jenkins" OR title:"gitlab")',

            f'hostname:"{domain}" (product:"Apache/2.0" OR product:"Apache/2.2" OR product:"nginx/0." OR product:"nginx/1.0" OR product:"IIS/6.0" OR product:"PHP/5." OR product:"WordPress 4." OR product:"Drupal 7." OR product:"Struts 2.3")',

            f'hostname:"{domain}" (title:"Index of" OR title:"Directory Listing" OR filename:".bak" OR filename:".old" OR filename:".git" OR filename:".env" OR path:"/.git" OR path:"/.svn")',

            f'hostname:"{domain}" (title:"Swagger" OR title:"API" OR title:"GraphQL" OR path:"/api" OR path:"/swagger" OR path:"/api-docs")',

            f'(hostname:"dev.{domain}" OR hostname:"staging.{domain}" OR hostname:"test.{domain}" OR hostname:"admin.{domain}")',

            f'hostname:"{domain}" (filename:".sql" OR filename:".db" OR filename:".log" OR filename:".conf" OR filename:".key" OR filename:".pem")',

            f'hostname:"{domain}" (title:"401 Unauthorized" OR title:"403 Forbidden" OR title:"500 Internal" OR body:"stack trace" OR body:"debug")',

            f'hostname:"{domain}" (header:"Access-Control-Allow-Origin: *" OR NOT header:"X-Frame-Options" OR NOT header:"Content-Security-Policy")',
        ]
        collected_data = {}
        
        for query in queries:
            query_results = []
            
            try:
                for page in range(1, max_pages + 1):
                    fields = "ip,port,domain,hostname,title,service,product,os,country.name,city.name,update_time,url,banner,header.server.name,asn,organization.name"
                    result = self._zm.search(query, page=page, pagesize=100, fields=fields)
                    
                    if not result or result.get('code') != 60000:
                        break
                    
                    data = result.get('data', [])
                    if not data:
                        break
                    
                    query_results.extend(data)
                    
                    # time.sleep(1)
                    
                    if len(data) < 50:
                        break
                
                collected_data[query] = {
                    'total_results': len(query_results),
                    'data': query_results
                }
                
            except Exception as e:
                collected_data[query] = {
                    'error': str(e),
                    'total_results': 0,
                    'data': []
                }
        
        return collected_data
    
    def extract_basic_info(self, raw_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract basic information (for deduplication)"""
        unique_ips = set()
        unique_domains = set()
        
        for query_data in raw_data.values():
            for item in query_data.get('data', []):
                if item.get('ip'):
                    unique_ips.add(item.get('ip'))
                if item.get('hostname'):
                    unique_domains.add(item.get('hostname'))
        
        return {
            'unique_ips': list(unique_ips),
            'unique_domains': list(unique_domains),
            'total_unique_ips': len(unique_ips),
            'total_unique_domains': len(unique_domains)
        }
    
    def _run(self, domain: str) -> str:
        """Tool execution main function"""
        try:
            raw_data = self.collect_data(domain)
            
            credit_errors = 0
            total_queries = len(raw_data)
            
            for query_data in raw_data.values():
                if 'error' in query_data and 'resource credits is insufficient' in query_data.get('error', ''):
                    credit_errors += 1
            
            if total_queries > 0 and (credit_errors / total_queries) >= 0.8:
                skip_result = {
                    'domain': domain,
                    'scan_time': datetime.now().isoformat(),
                    'status': 'skipped',
                    'reason': 'ZoomEye API credits exhausted',
                    'message': 'ZoomEye reconnaissance skipped due to insufficient API credits. Please check your ZoomEye account credits.',
                    'basic_info': {
                        'unique_ips': [],
                        'unique_domains': [],
                        'total_unique_ips': 0,
                        'total_unique_domains': 0
                    },
                    'raw_data': {},
                    'data_summary': {
                        'total_queries': total_queries,
                        'successful_queries': 0,
                        'total_records': 0,
                        'credit_errors': credit_errors
                    }
                }
                return json.dumps(skip_result, default=str, ensure_ascii=False)
            
            basic_info = self.extract_basic_info(raw_data)
            
            result = {
                'domain': domain,
                'scan_time': datetime.now().isoformat(),
                'basic_info': basic_info,
                'raw_data': raw_data,
                'data_summary': {
                    'total_queries': len(raw_data),
                    'successful_queries': len([q for q in raw_data.values() if 'error' not in q]),
                    'total_records': sum(q.get('total_results', 0) for q in raw_data.values())
                }
            }
            
            return json.dumps(result, default=str, ensure_ascii=False)
            
        except Exception as e:
            error_result = {
                'domain': domain,
                'error': str(e),
                'scan_time': datetime.now().isoformat()
            }
            return json.dumps(error_result)