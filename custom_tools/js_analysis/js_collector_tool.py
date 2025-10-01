#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, asyncio, requests, hashlib, time, json
from typing import Set, Dict, Optional, Tuple, Any
from urllib.parse import urljoin

from custom_tools.js_analysis.js_utils import (
    should_exclude,
    base_file_exists,
    generate_safe_filename
)

class JavaScriptCollectorTool(BaseTool):
    name: str = "JavaScript URL Collector and Downloader"
    description: str = "Collect JavaScript URLs from Phase 1 and Playwright, then download all files"

    async def setup_browser(self) -> Optional[Tuple[Any, Any, Any]]:
        """Initialize Playwright browser."""
        try:
            from playwright.async_api import async_playwright

            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(
                headless=True,
                args=['--no-sandbox', '--disable-dev-shm-usage']
            )

            context = await browser.new_context(
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
                viewport={'width': 1366, 'height': 768},
                ignore_https_errors=True
            )

            return playwright, browser, context
        except Exception:
            return None

    async def cleanup_browser(self, playwright: Any, browser: Any, context: Any) -> None:
        """Clean up browser resources."""
        try:
            if context:
                await context.close()
            if browser:
                await browser.close()
            if playwright:
                await playwright.stop()
        except Exception:
            pass

    async def extract_js_urls_from_page(self, url: str, target_domain: str, context) -> Set[str]:
        """Extract JavaScript URLs from a single page."""
        js_urls = set()

        try:
            page = await context.new_page()

            async def handle_request(request):
                if request.resource_type == 'script':
                    js_url = request.url
                    if not should_exclude(js_url, target_domain):
                        js_urls.add(js_url)

            page.on('request', handle_request)

            await page.goto(url, wait_until='networkidle', timeout=30000)
            await page.wait_for_timeout(2000)

            try:
                script_elements = await page.query_selector_all('script[src]')
                for element in script_elements:
                    src = await element.get_attribute('src')
                    if src:
                        full_url = urljoin(url, src) if not src.startswith('http') else src
                        if not should_exclude(full_url, target_domain):
                            js_urls.add(full_url)
            except Exception:
                pass

            await page.close()

        except Exception:
            pass

        return js_urls

    async def crawl_with_playwright(self, target_domain: str, context) -> Set[str]:
        """Crawl main page to discover JavaScript URLs."""
        url = f"https://{target_domain}/"
        try:
            return await self.extract_js_urls_from_page(url, target_domain, context)
        except Exception:
            return set()

    def read_phase1_urls(self, phase1_path: str) -> Set[str]:
        """Read JavaScript URLs from Phase 1 results."""
        js_urls = set()

        if not os.path.exists(phase1_path):
            return js_urls

        try:
            with open(phase1_path, 'r', encoding='utf-8') as f:
                for line in f:
                    url = line.strip()
                    if url and url.startswith('http'):
                        js_urls.add(url)
        except Exception:
            pass

        return js_urls

    def download_js_file(self, url: str, js_folder: str) -> tuple:
        """Download a JavaScript file from URL."""
        try:
            headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
            response = requests.get(url, headers=headers, timeout=10)

            if response.status_code >= 400:
                return False, f"HTTP {response.status_code}"

            content_type = response.headers.get('content-type', '').lower()
            if 'javascript' not in content_type and 'text' not in content_type and not url.endswith('.js'):
                return False, "Not JavaScript content"

            content = response.content

            if len(content) < 50:
                return False, "File too small"

            filename = generate_safe_filename(url)

            exists, existing_file = base_file_exists(filename, js_folder)
            if exists:
                return False, f"Already exists ({existing_file})"

            filepath = os.path.join(js_folder, filename)

            if os.path.exists(filepath):
                hash_suffix = hashlib.md5(url.encode()).hexdigest()[:8]
                name, ext = os.path.splitext(filename)
                filename = f"{name}_{hash_suffix}{ext}"
                filepath = os.path.join(js_folder, filename)

            with open(filepath, 'wb') as f:
                f.write(content)

            return True, filename
        except Exception as e:
            return False, str(e)

    async def collect_all_urls(self, target_domain: str, result_dir: str) -> Dict:
        """Main collection method."""
        phase1_path = os.path.join(result_dir, "phase1", "file", "js.txt")
        phase4_dir = os.path.join(result_dir, "phase4")
        js_url_file = os.path.join(phase4_dir, "js_url.txt")
        js_folder = os.path.join(phase4_dir, "js")

        os.makedirs(phase4_dir, exist_ok=True)
        os.makedirs(js_folder, exist_ok=True)

        phase1_urls = self.read_phase1_urls(phase1_path)

        playwright_urls = set()
        browser_setup = await self.setup_browser()

        if browser_setup:
            playwright, browser, context = browser_setup
            try:
                playwright_urls = await self.crawl_with_playwright(target_domain, context)
            finally:
                await self.cleanup_browser(playwright, browser, context)

        all_urls = phase1_urls | playwright_urls

        with open(js_url_file, 'w', encoding='utf-8') as f:
            for url in sorted(all_urls):
                f.write(f"{url}\n")

        downloaded = 0
        failed = 0

        for url in all_urls:
            success, result = self.download_js_file(url, js_folder)
            if success:
                downloaded += 1
            else:
                failed += 1
            time.sleep(0.3)

        return {
            "phase1_urls": len(phase1_urls),
            "playwright_urls": len(playwright_urls),
            "total_unique_urls": len(all_urls),
            "downloaded": downloaded,
            "failed": failed,
            "js_url_file": js_url_file,
            "js_folder": js_folder
        }

    def _run(self) -> str:
        """Run the JavaScript collection and download tool."""
        try:
            target_domain = os.getenv("TARGET")
            if not target_domain:
                return json.dumps({"status": "ERROR", "message": "TARGET environment variable not set"})

            result_dir = os.getenv("RESULT_DIR")
            if not result_dir:
                return json.dumps({"status": "ERROR", "message": "RESULT_DIR environment variable not set"})

            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            result = loop.run_until_complete(self.collect_all_urls(target_domain, result_dir))
            loop.close()

            return json.dumps({
                "status": "SUCCESS",
                "message": f"Collected {result['total_unique_urls']} unique URLs (Phase1: {result['phase1_urls']}, Playwright: {result['playwright_urls']}). Downloaded {result['downloaded']} files, {result['failed']} failed.",
                **result
            }, indent=2)

        except Exception as e:
            return json.dumps({"status": "ERROR", "message": f"Collection failed: {str(e)}"})
