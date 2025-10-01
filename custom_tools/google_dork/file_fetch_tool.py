#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, json, requests, hashlib, re
from urllib.parse import urlparse, unquote

class FileFetchTool(BaseTool):
    """Tool for downloading files from URLs."""
    name: str = "File Downloader"
    description: str = "Download files (PDF/DOC/CSV/TXT/etc) from URLs to local directory"

    def _run(self, website_url: str = None) -> str:
        """Download file from URL to phase2/files directory."""
        if not website_url:
            return json.dumps({'error': 'website_url is required', 'message': 'Please provide a website_url to download'})

        result_dir = os.getenv("RESULT_DIR")
        if not result_dir:
            return json.dumps({'error': 'RESULT_DIR environment variable not set'})

        file_dir = os.path.join(result_dir, "phase2", "files")
        os.makedirs(file_dir, exist_ok=True)

        try:
            parsed_url = urlparse(website_url)
            filename = os.path.basename(unquote(parsed_url.path))
            if not filename:
                filename = f"file_{hashlib.md5(website_url.encode()).hexdigest()[:8]}"

            safe_filename = re.sub(r'[<>:"|?*/\\]', '_', filename)
            safe_filename = safe_filename.strip()
            safe_filename = re.sub(r'_+', '_', safe_filename)
            filepath = os.path.join(file_dir, safe_filename)

            response = requests.get(website_url, timeout=30, verify=False)
            response.raise_for_status()

            content_disposition = response.headers.get('Content-Disposition', '')
            if content_disposition:
                import cgi
                _, params = cgi.parse_header(content_disposition)

                header_filename = None
                if 'filename*' in params:
                    try:
                        encoding, _, encoded_name = params['filename*'].split("'", 2)
                        header_filename = unquote(encoded_name, encoding=encoding)
                    except:
                        pass

                if not header_filename and 'filename' in params:
                    header_filename = params['filename']
                    if header_filename.startswith('"') and header_filename.endswith('"'):
                        header_filename = header_filename[1:-1]

                    try:
                        header_filename = header_filename.encode('iso-8859-1').decode('utf-8')
                    except (UnicodeDecodeError, UnicodeEncodeError):
                        pass

                if header_filename:
                    filename = header_filename
                    safe_filename = re.sub(r'[<>:"|?*/\\]', '_', filename)
                    safe_filename = safe_filename.strip()
                    safe_filename = re.sub(r'_+', '_', safe_filename)
                    filepath = os.path.join(file_dir, safe_filename)

            with open(filepath, 'wb') as f:
                f.write(response.content)

            target = os.getenv('TARGET', 'unknown')
            relative_path = f"results/{target}/phase2/files/{safe_filename}"
            return json.dumps({'status': 'success', 'filename': safe_filename, 'file_path': relative_path})

        except requests.exceptions.Timeout:
            return json.dumps({'error': 'Download timeout', 'url': website_url})
        except requests.exceptions.HTTPError as e:
            return json.dumps({'error': f'HTTP error: {e}', 'url': website_url})
        except requests.exceptions.ConnectionError:
            return json.dumps({'error': 'Connection failed', 'url': website_url})
        except Exception as e:
            return json.dumps({'error': f'Download failed: {str(e)}', 'url': website_url})