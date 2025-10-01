#!/usr/bin/env python3
"""Shared utilities for JavaScript analysis tools."""
import os, re, json
from typing import List, Dict, Tuple
from urllib.parse import urlparse

THIRD_PARTY_DOMAINS = {
    'cdnjs.cloudflare.com', 'cdn.jsdelivr.net', 'unpkg.com', 'ajax.googleapis.com',
    'code.jquery.com', 'google-analytics.com', 'googletagmanager.com',
    'facebook.net', 'connect.facebook.net', 'platform.twitter.com', 'gstatic.com',
    'googlesyndication.com', 'doubleclick.net', 'amazon-adsystem.com',
    'youtube.com', 'vimeo.com', 'twitter.com', 'linkedin.com'
}

THIRD_PARTY_PATTERNS = [
    r'jquery.*\.js$', r'bootstrap.*\.js$', r'angular.*\.js$', r'react.*\.js$',
    r'ga\.js$', r'gtag\.js$', r'analytics.*\.js$', r'moment.*\.js$',
    r'^[a-z]{2}(-[a-z]{2})?\.js$', r'ads.*\.js$', r'track.*\.js$'
]


def should_exclude(url: str, target_domain: str) -> bool:
    """Check if URL should be excluded as third-party."""
    try:
        parsed = urlparse(url)
        domain = parsed.netloc.lower()
        filename = os.path.basename(parsed.path).lower()

        if domain in THIRD_PARTY_DOMAINS:
            return True

        target_base = '.'.join(target_domain.split('.')[-2:])
        url_base = '.'.join(domain.split('.')[-2:]) if '.' in domain else domain
        if url_base != target_base:
            return True

        for pattern in THIRD_PARTY_PATTERNS:
            if re.search(pattern, filename, re.IGNORECASE):
                return True

        return False
    except Exception:
        return True


def get_base_filename(filename: str) -> str:
    """Extract base filename by removing version/hash suffixes."""
    name = filename[:-3] if filename.endswith('.js') else filename
    name = re.sub(r'[-_][a-f0-9]{8,}$', '', name)
    name = re.sub(r'[-_]v?\d{4,}$', '', name)
    name = re.sub(r'\.(min|prod|dev|staging)$', '', name)
    name = re.sub(r'[-_](analysis|debug|test|dev|prod|staging)$', '', name)
    return name


def base_file_exists(filename: str, js_folder: str) -> Tuple[bool, str]:
    """Check if a file with the same base name already exists."""
    if not os.path.exists(js_folder):
        return False, ""

    base_name = get_base_filename(filename)

    for existing_file in os.listdir(js_folder):
        if existing_file.endswith('.js'):
            existing_base = get_base_filename(existing_file)
            if base_name == existing_base:
                return True, existing_file

    return False, ""


def find_natural_split_point(content: str, target_pos: int, search_range: int = 1000) -> int:
    """Find natural JavaScript split point near target position."""
    if target_pos >= len(content):
        return len(content)

    best_pos = target_pos
    best_score = 0

    split_patterns = [
        (r'\n\n', 10),
        (r'\n}\s*\n', 9),
        (r';\s*\n', 8),
        (r'\n(?=function\s)', 7),
        (r'\n(?=const\s)', 6),
        (r'\n(?=let\s)', 5),
        (r'\n(?=var\s)', 4),
        (r'\n(?=//)', 3),
        (r'\n', 2),
        (r';\s*', 1),
    ]

    start = max(0, target_pos - search_range)
    end = min(len(content), target_pos + search_range)
    search_text = content[start:end]

    for pattern, score in split_patterns:
        matches = list(re.finditer(pattern, search_text))
        if matches:
            for match in matches:
                pos = start + match.end()
                if abs(pos - target_pos) < abs(best_pos - target_pos) or score > best_score:
                    best_pos = pos
                    best_score = score

    return best_pos


def chunk_large_js_file(filepath: str, max_chunk_size: int = 500000) -> List[Dict]:
    """Split large JavaScript file into manageable chunks."""
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        content = f.read()

    if len(content) <= max_chunk_size:
        return []

    chunks = []
    chunk_num = 1
    position = 0
    overlap_size = int(max_chunk_size * 0.3)

    while position < len(content):
        chunk_end = position + max_chunk_size

        if chunk_end < len(content):
            chunk_end = find_natural_split_point(content, chunk_end)

        if chunk_num > 1:
            chunk_start = max(0, position - overlap_size)
        else:
            chunk_start = position

        chunk_content = content[chunk_start:chunk_end]

        base_name = os.path.splitext(os.path.basename(filepath))[0]
        chunk_filename = f"{base_name}.chunk{chunk_num}.js"
        chunk_path = os.path.join(os.path.dirname(filepath), chunk_filename)

        with open(chunk_path, 'w', encoding='utf-8') as f:
            f.write(chunk_content)

        chunks.append({
            'chunk_num': chunk_num,
            'filename': chunk_filename,
            'filepath': chunk_path,
            'start': chunk_start,
            'end': chunk_end,
            'size': len(chunk_content),
            'has_overlap': chunk_num > 1
        })

        position = chunk_end
        chunk_num += 1

    return chunks


def save_chunking_metadata(js_folder: str, original_filename: str, chunks: List[Dict], original_url: str) -> None:
    """Save metadata about chunked files for tracking."""
    metadata_file = os.path.join(js_folder, 'chunking_metadata.json')

    if os.path.exists(metadata_file):
        with open(metadata_file, 'r') as f:
            metadata = json.load(f)
    else:
        metadata = {}

    metadata[original_filename] = {
        'original_url': original_url,
        'num_chunks': len(chunks),
        'chunks': chunks,
        'chunked_at': os.path.getctime(chunks[0]['filepath']) if chunks else None
    }

    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)


def is_error_page_content(content: str) -> bool:
    """Check if content is an error page instead of JavaScript."""
    try:
        text = content[:2000].lower()

        error_indicators = [
            '<!doctype', '<html', '<head>', '<body>',
            '<meta ', '<title>', '<div',
            '404', 'not found', 'page not found', 'cannot find',
            'error', 'forbidden', '403', '500',
            'internal server', 'bad request', '400'
        ]

        js_indicators = [
            'function ', 'function(', 'var ', 'const ', 'let ',
            '=>', 'export ', 'import ', 'require(', 'module.exports',
            'window.', 'document.', 'console.', 'return ',
            'if (', 'for (', 'while (', 'typeof ', 'new '
        ]

        error_count = sum(1 for indicator in error_indicators if indicator in text)
        js_count = sum(1 for indicator in js_indicators if indicator in text)

        if text.strip().startswith('<!doctype') or text.strip().startswith('<html'):
            return True

        if error_count > 3 and error_count > js_count:
            return True

        if js_count == 0 and error_count > 0:
            return True

        return False
    except:
        return False


def generate_safe_filename(url: str) -> str:
    """Generate safe filename from URL."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    path_parts = parsed.path.strip('/').split('/')

    if path_parts and path_parts[-1].endswith('.js'):
        filename = path_parts[-1]
    elif len(path_parts) > 1:
        filename = f"{path_parts[-2]}_{path_parts[-1]}.js"
    else:
        filename = f"{parsed.netloc.replace('.', '_')}_script.js"

    safe_filename = re.sub(r'[^\w\-_\.]', '_', filename)
    return safe_filename[:100] if len(safe_filename) > 100 else safe_filename


def beautify_minified_files(js_folder: str) -> int:
    """Beautify minified JavaScript files to make them readable."""
    import jsbeautifier
    beautified_count = 0

    if not os.path.exists(js_folder):
        return 0

    for filename in os.listdir(js_folder):
        if not filename.endswith('.js') or filename.endswith('.min.js'):
            continue

        file_path = os.path.join(js_folder, filename)

        try:
            file_size = os.path.getsize(file_path)

            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            if len(lines) <= 3 and file_size > 10000:

                content = ''.join(lines)

                options = jsbeautifier.default_options()
                options.indent_size = 2
                options.max_preserve_newlines = 2
                options.wrap_line_length = 120

                beautified = jsbeautifier.beautify(content, options)

                backup_path = file_path + '.min'
                os.rename(file_path, backup_path)

                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(beautified)

                beautified_count += 1

        except Exception as e:
            continue

    return beautified_count