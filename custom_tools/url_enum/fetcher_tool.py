#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, re, subprocess
from typing import List

def fetch_urls(domain: str, output_root: str) -> List[str]:
    """Collect URLs using waymore."""
    domain_dir = os.path.join(output_root, domain, "phase1")
    save_path = os.path.join(domain_dir, "all_urls.txt")
    raw_path = os.path.join(domain_dir, "raw_urls.txt")

    os.makedirs(domain_dir, exist_ok=True)

    try:
        subprocess.run(["waymore", "-i", domain, "-mode", "U", "-oU", save_path], capture_output=True, text=True, timeout=3600)

        with open(save_path, "r", encoding="utf-8") as f:
            raw_urls = f.readlines()

        with open(raw_path, "w", encoding="utf-8") as f:
            f.writelines(raw_urls)

        normalized_urls = []
        for url in raw_urls:
            url = url.strip()
            if not url:
                continue

            if '...' in url:
                continue
            if re.search(r'/\.\.\./|/\.\.$', url):
                continue
            if re.search(r'[a-f0-9]{10,}\.\.\.', url):
                continue

            if url.startswith("http://") and ":80/" in url:
                url = url.replace(":80/", "/", 1)

            normalized_urls.append(url)

        with open(save_path, "w", encoding="utf-8") as f:
            f.write("\n".join(normalized_urls) + "\n")

        with open(save_path, "r", encoding="utf-8") as fp:
            urls = [line.strip() for line in fp if line.strip()]

        return urls

    except subprocess.TimeoutExpired:
        raise RuntimeError("URL collection timed out")
    except Exception as e:
        raise RuntimeError(f"URL collection failed: {e}")


class URLFetcherTool(BaseTool):
    name: str = "URL Fetcher"
    description: str = "Collect archived URLs for a given domain"

    def _run(self, domain: str) -> str:
        """Execute URL fetching for the specified domain."""
        result_dir = os.getenv("RESULT_DIR")
        if not result_dir:
            return "RESULT_DIR environment variable not set"

        output_root = os.path.dirname(result_dir)

        try:
            urls = fetch_urls(domain, output_root)
            count = len(urls)
            return f"{count} URLs collected for {domain}"
        except Exception as e:
            return f"Error collecting URLs for {domain}: {str(e)}"