#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, re, subprocess, json
from typing import Set, Optional, List, Dict
from urllib.parse import urlparse, parse_qs

FILE_EXTENSIONS = {
    '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.xml', '.json',
    '.csv', '.zip', '.rar', '.tar', '.gz', '.7z', '.mp3', '.mp4', '.avi', '.mov',
    '.wmv', '.flv', '.swf', '.php', '.asp', '.aspx', '.jsp', '.cfm', '.pl', '.py',
    '.rb', '.sql', '.db', '.bak', '.backup', '.old', '.tmp', '.log', '.conf', '.cfg',
    '.ini', '.yaml', '.yml', '.properties', '.js', '.exe', '.html'
}

DYNAMIC_PATTERNS = {
    'numeric': re.compile(r'^\d+$'),
    'uuid10': re.compile(r'^[a-zA-Z0-9]{10}$'),
    'uuid32': re.compile(r'^[a-fA-F0-9]{32}$', re.IGNORECASE),
    'uuid64': re.compile(r'^[a-fA-F0-9]{64}$', re.IGNORECASE),
    'alphanumeric_with_num': re.compile(r'^[a-zA-Z0-9_-]*\d+[a-zA-Z0-9_-]*$'),
    'hex_hash': re.compile(r'^[a-fA-F0-9]{8,}$', re.IGNORECASE),
    'mixed_alpha_num': re.compile(r'^([a-zA-Z]+\d+|\d+[a-zA-Z]+)$')
}

INVALID_PARAM_CHARS = {'http', 'https', '/', '\\', ' '}
INVALID_PARAM_PREFIXES = ('amp;', 'nbsp;', 'gt;', 'lt;')

JUICY_WORDS = {
    # Authentication & Authorization
    'auth', 'login', 'logout', 'signup', 'signin', 'register',
    'user', 'admin', 'passwd', 'password', 'reset', 'token',
    'session', 'id', 'email', 'oauth', 'sso', 'saml', 'jwt',
    # API & Keys
    'api', 'key', 'secret', 'private', 'apikey', 'access_token',
    # Sensitive Operations
    'internal', 'debug', 'test', 'dev', 'staging', 'beta',
    'config', 'setting', 'backup', 'dump', 'export', 'download', 'upload',
    # File & Path
    'file', 'path', 'doc', 'document', 'folder', 'directory',
    # Redirect & Navigation
    'redirect', 'callback', 'return', 'next', 'goto', 'url', 'uri', 'dest',
    # Data Operations
    'query', 'search', 'delete', 'remove', 'edit', 'update', 'create', 'modify',
    # Payment & Financial
    'payment', 'invoice', 'order', 'cart', 'checkout', 'billing', 'account'
}

VULN_PARAM_PATTERNS = {
    'open_redirect': [
        'url', 'redirect', 'return', 'next', 'goto', 'dest', 'rurl',
        'target', 'link', 'continue', 'forward', 'callback', 'ret',
        'returnurl', 'return_url', 'redirect_uri', 'redirect_url',
        'redir', 'destination', 'out', 'view', 'ref', 'to'
    ],
    'ssrf': [
        'url', 'uri', 'host', 'domain', 'dest', 'site', 'server',
        'fetch', 'proxy', 'request', 'load', 'img', 'image', 'src',
        'href', 'path', 'endpoint', 'api', 'webhook'
    ],
    'lfi': [
        'file', 'path', 'page', 'doc', 'folder', 'template', 'include',
        'dir', 'document', 'root', 'pg', 'style', 'pdf', 'view',
        'content', 'layout', 'mod', 'conf', 'lang', 'locale'
    ],
    'sqli': [
        'id', 'user_id', 'item', 'no', 'num', 'order', 'sort', 'column',
        'table', 'field', 'select', 'where', 'cat', 'category', 'type',
        'filter', 'limit', 'offset', 'group', 'by', 'asc', 'desc'
    ],
    'idor': [
        'id', 'uid', 'pid', 'user_id', 'account', 'doc_id', 'file_id',
        'order_id', 'invoice', 'report', 'profile', 'account_id',
        'customer_id', 'user', 'userid', 'member', 'member_id'
    ],
    'xss': [
        'q', 'query', 'search', 'keyword', 's', 'term', 'message',
        'comment', 'text', 'input', 'name', 'title', 'content', 'callback',
        'body', 'data', 'value', 'html', 'error', 'msg', 'description'
    ],
    'auth': [
        'token', 'auth', 'key', 'api_key', 'apikey', 'access_token',
        'session', 'jwt', 'bearer', 'secret', 'password', 'passwd',
        'credential', 'hash', 'sig', 'signature', 'nonce'
    ]
}

def is_noise_param(param: str) -> bool:
    """Filter out noise parameters that have no security testing value."""
    # Pure numeric (timestamps, dates, indices)
    if param.isdigit():
        return True
    # Version/cache busters: _v1234567890, v1, v2
    if re.match(r'^_?v\d+$', param):
        return True
    # Encoded/corrupted params (URL encoded or excessively long)
    if '%' in param or len(param) > 50:
        return True
    return False

def classify_param_vulnerability(param: str) -> List[str]:
    """Classify parameter by potential vulnerability types based on name patterns."""
    param_lower = param.lower().strip()
    if not param_lower:
        return []

    vulnerabilities = []
    for vuln_type, patterns in VULN_PARAM_PATTERNS.items():
        for pattern in patterns:
            if pattern == param_lower or pattern in param_lower or param_lower in pattern:
                if vuln_type not in vulnerabilities:
                    vulnerabilities.append(vuln_type)
                break

    return vulnerabilities

def apply_segment_pattern(segment: str) -> str:
    """Apply pattern replacement to a single URL segment."""
    if not segment:
        return ''
    patterns = [
        (DYNAMIC_PATTERNS['numeric'], '{id}'),
        (DYNAMIC_PATTERNS['uuid10'], '{uuid}'),
        (DYNAMIC_PATTERNS['uuid32'], '{uuid}'),
        (DYNAMIC_PATTERNS['uuid64'], '{uuid}'),
        (DYNAMIC_PATTERNS['alphanumeric_with_num'], '{param}'),
        (DYNAMIC_PATTERNS['hex_hash'], '{hash}'),
        (DYNAMIC_PATTERNS['mixed_alpha_num'], '{mixed}')
    ]
    for pattern, replacement in patterns:
        if pattern.match(segment):
            return replacement
    return segment

def transform_path(path: str) -> tuple[str, bool]:
    """Transform path segments and return (transformed_path, has_dynamic)."""
    segments = path.split('/')
    transformed = []
    has_dynamic = False

    for s in segments:
        new_s = apply_segment_pattern(s)
        transformed.append(new_s)
        if new_s != s and s:  
            has_dynamic = True

    return '/'.join(transformed), has_dynamic

def extract_files(urls: List[str]) -> tuple[Set[str], List[str], Dict[str, Set[str]]]:
    """Extract file URLs and classify by extension."""
    file_urls = set()
    regular_urls = []
    ext_map = {}

    for u in urls:
        path = u.split('?')[0].split('#')[0].lower()
        if any(path.endswith(ext) for ext in FILE_EXTENSIONS):
            file_urls.add(u)
            parsed = urlparse(u) if u.startswith('http') else urlparse('http://' + u)
            path = parsed.path.lower().split('?')[0]
            for ext in FILE_EXTENSIONS:
                if path.endswith(ext):
                    ext_map.setdefault(ext, set()).add(u)
                    break
        else:
            regular_urls.append(u)

    return file_urls, regular_urls, ext_map

def extract_query_urls(url: str) -> Optional[str]:
    """Extract query parameter pattern from URL with dynamic path segments replaced."""
    parsed = urlparse(url)
    if not parsed.query:
        return None
    params = parse_qs(parsed.query, keep_blank_values=True)
    if not params:
        return None

    pattern_path, _ = transform_path(parsed.path)
    keys = sorted(params.keys())
    return f"{parsed.netloc}{pattern_path}?" + "&".join(f"{k}=" for k in keys)

def extract_path_urls(url: str) -> Optional[str]:
    """Extract dynamic path pattern from URL."""
    parsed = urlparse(url)
    pattern_path, has_dynamic = transform_path(parsed.path)

    if not has_dynamic:
        return None

    return f"{parsed.netloc}{pattern_path}"

def extract_params(url: str) -> Set[str]:
    """Extract valid query parameters from URL."""
    parsed = urlparse(url.replace('&amp;', '&'))
    query = parse_qs(parsed.query, keep_blank_values=True)
    result = set()
    for k in query:
        if (
            not k or
            any(c in k for c in INVALID_PARAM_CHARS) or
            any(k.startswith(prefix) for prefix in INVALID_PARAM_PREFIXES)
        ):
            continue
        result.add(k.strip())
    return result

def normalize_path(url: str, target_domain: str) -> str:
    """Normalize URL to domain-relative path and filter by target domain."""
    url = url.strip()
    if not url:
        return ""

    if url.startswith("http://"):
        url = url[7:]
    elif url.startswith("https://"):
        url = url[8:]

    try:
        parsed = urlparse("http://" + url)
        clean_netloc = parsed.netloc.split(":")[0]

        if not (clean_netloc == target_domain or clean_netloc.endswith('.' + target_domain)):
            return ""

        path = parsed.path or "/"
        normalized = path if path.startswith("/") else "/" + path

        return normalized + (("?" + parsed.query) if parsed.query else "")
    except Exception:
        return ""

def process_urls_txt(url_dir: str, domain: str):
    """Generate urls.txt with pattern replacement and deduplication."""
    general_url_file = os.path.join(url_dir, "general_urls.txt")
    urls_txt_file = os.path.join(url_dir, "urls.txt")

    if not os.path.exists(general_url_file):
        return

    with open(general_url_file, 'r', encoding='utf-8') as f:
        regular_urls_raw = [line.strip() for line in f if line.strip()]

    pattern_applied = []
    for url in regular_urls_raw:
        parsed = urlparse(url if url.startswith('http') else 'http://' + url)
        pattern_path, _ = transform_path(parsed.path)
        scheme = parsed.scheme if parsed.scheme else 'https'
        netloc = parsed.netloc if parsed.netloc else domain
        pattern_url = f"{scheme}://{netloc}{pattern_path}" + (('?' + parsed.query) if parsed.query else '')
        pattern_applied.append(pattern_url)

    temp_pattern_file = os.path.join(url_dir, "temp_pattern.txt")
    with open(temp_pattern_file, 'w', encoding='utf-8') as f:
        f.writelines(f"{line}\n" for line in pattern_applied)

    temp_uro = os.path.join(url_dir, "temp_uro.txt")
    subprocess.run(["uro", "-i", temp_pattern_file, "-o", temp_uro], capture_output=True, text=True, timeout=600)
    if os.path.exists(temp_uro):
        os.replace(temp_uro, temp_pattern_file)

    temp_uddup = os.path.join(url_dir, "temp_uddup.txt")
    subprocess.run(["uddup", "-u", temp_pattern_file, "-o", temp_uddup], capture_output=True, text=True, timeout=600)
    if os.path.exists(temp_uddup):
        os.replace(temp_uddup, temp_pattern_file)

    with open(temp_pattern_file, 'r', encoding='utf-8') as f:
        deduped_urls = [line.strip() for line in f if line.strip()]

    final_urls = []
    for url in deduped_urls:
        normalized = normalize_path(url, domain)
        if normalized:
            final_urls.append(normalized)

    with open(urls_txt_file, 'w', encoding='utf-8') as f:
        unique_urls = sorted(set(final_urls))
        f.writelines(f"{line}\n" for line in unique_urls)

    os.remove(temp_pattern_file)

def write_output(file_path: str, data):
    """Write data to file."""
    with open(file_path, 'w', encoding='utf-8') as f:
        if isinstance(data, set):
            data = sorted(data)
        f.writelines(f"{line}\n" for line in data)

def process_file_urls(file_urls: Set[str], file_dir: str) -> Set[str]:
    """Apply uro only to file URLs to preserve them."""
    if not file_urls:
        return set()

    temp_file = os.path.join(file_dir, "temp_file_urls.txt")
    temp_uro = os.path.join(file_dir, "temp_file_uro.txt")

    with open(temp_file, 'w', encoding='utf-8') as f:
        for url in sorted(file_urls):
            f.write(f"{url}\n")

    subprocess.run(["uro", "-i", temp_file, "-o", temp_uro], capture_output=True, text=True, timeout=600)

    result = set()
    if os.path.exists(temp_uro):
        with open(temp_uro, 'r', encoding='utf-8') as f:
            result = {line.strip() for line in f if line.strip()}
        os.remove(temp_uro)

    os.remove(temp_file)
    return result

def distill(domain: str, output_root: str):
    """Process and classify URLs into various categories."""
    url_file = os.path.join(output_root, domain, "phase1", "all_urls.txt")

    try:
        with open(url_file, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f if line.strip()]
    except IOError:
        urls = []

    if not urls:
        return

    domain_dir = os.path.join(output_root, domain, "phase1")
    os.makedirs(domain_dir, exist_ok=True)

    url_dir = os.path.join(domain_dir, "url")
    file_dir = os.path.join(domain_dir, "file")
    pattern_dir = os.path.join(domain_dir, "pattern")
    for dir_path in [url_dir, file_dir, pattern_dir]:
        os.makedirs(dir_path, exist_ok=True)

    file_urls, regular_urls, ext_map = extract_files(urls)

    file_urls = process_file_urls(file_urls, file_dir)

    ext_map_deduped = {}
    for url in file_urls:
        parsed = urlparse(url) if url.startswith('http') else urlparse('http://' + url)
        path = parsed.path.lower().split('?')[0]
        for ext in FILE_EXTENSIONS:
            if path.endswith(ext):
                ext_map_deduped.setdefault(ext, set()).add(url)
                break

    query_patterns = set()
    all_params = set()
    path_patterns = set()
    juicy_urls = set()

    for u in urls:
        qp = extract_query_urls(u)
        if qp:
            query_patterns.add(qp)

        all_params.update(extract_params(u))

        pp = extract_path_urls(u)
        if pp:
            path_patterns.add(pp)

        parsed = urlparse(u)
        path_lower, query_lower = parsed.path.lower(), parsed.query.lower()
        for word in JUICY_WORDS:
            if word in path_lower or word in query_lower:
                juicy_urls.add(u)
                break

    write_output(os.path.join(url_dir, "general_urls.txt"), regular_urls)
    write_output(os.path.join(file_dir, "file_urls.txt"), file_urls)

    for ext, urls_with_ext in ext_map_deduped.items():
        filename = ext.lstrip('.') + ".txt"
        write_output(os.path.join(file_dir, filename), urls_with_ext)

    write_output(os.path.join(url_dir, "query_urls.txt"), query_patterns)
    write_output(os.path.join(url_dir, "path_urls.txt"), path_patterns)
    write_output(os.path.join(pattern_dir, "juicy.txt"), juicy_urls)

    # Generate param_hints.json with all parameters and their vulnerability classifications
    param_hints = {}
    for param in all_params:
        if is_noise_param(param):
            continue
        vulns = classify_param_vulnerability(param)
        param_hints[param] = vulns  # Empty list if no vulnerabilities

    param_hints_file = os.path.join(pattern_dir, "param_hints.json")
    with open(param_hints_file, 'w', encoding='utf-8') as f:
        json.dump(param_hints, f, indent=2, ensure_ascii=False)

    process_urls_txt(url_dir, domain)

class URLDistillerTool(BaseTool):
    """Tool for analyzing and classifying collected URLs into various categories."""
    name: str = "URL Distiller"
    description: str = "Analyze collected URLs and save .txt summaries"

    def _run(self, domain: str) -> str:
        """Execute URL distillation and classification."""
        result_dir = os.getenv("RESULT_DIR")
        if not result_dir:
            return "RESULT_DIR environment variable not set"

        output_root = os.path.dirname(result_dir)

        try:
            distill(domain, output_root)
            return "Distillation complete"
        except Exception as e:
            return f"Error during distillation for {domain}: {str(e)}"