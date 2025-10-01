#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, subprocess, json

class NoirScannerTool(BaseTool):
    name: str = "NOIR JavaScript Scanner"
    description: str = "Scan JavaScript files with OWASP NOIR AST-based analysis"

    def _run(self) -> str:
        """Run NOIR scanner on downloaded JavaScript files."""
        try:
            result_dir = os.getenv("RESULT_DIR")
            if not result_dir:
                return json.dumps({"status": "ERROR", "message": "RESULT_DIR environment variable not set"})

            phase4_dir = os.path.join(result_dir, "phase4")
            js_folder = os.path.join(phase4_dir, "js")
            output_file = os.path.join(phase4_dir, "js_noir.json")

            if not os.path.exists(js_folder):
                return json.dumps({
                    "status": "NO_FILES",
                    "message": f"JavaScript folder not found: {js_folder}",
                    "endpoints": 0
                })

            cmd = ["noir", "-b", js_folder, "--format", "json", "-o", output_file, "-P", "--passive-scan-severity", "low", "-t", "js_express,js_restify,js_fastify,js_koa,js_nestjs", "--no-log"]

            subprocess.run(cmd, capture_output=True, text=True)

            return json.dumps({
                "status": "SUCCESS",
                "output_file": output_file
            })
        except Exception as e:
            return json.dumps({"status": "ERROR", "message": f"NOIR scan failed: {str(e)}"})
