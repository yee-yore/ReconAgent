#!/usr/bin/env python3
from crewai.tools import BaseTool
import os, subprocess, json

class NucleiScannerTool(BaseTool):
    name: str = "Nuclei JavaScript Scanner"
    description: str = "Scan JavaScript URLs with Nuclei regex-based templates"

    def _run(self) -> str:
        """Run Nuclei scanner on collected JavaScript URLs."""
        try:
            result_dir = os.getenv("RESULT_DIR")
            phase4_dir = os.path.join(result_dir, "phase4")
            js_url_file = os.path.join(phase4_dir, "js_url.txt")
            output_file = os.path.join(phase4_dir, "js_nuclei.json")
            template_path = os.path.expanduser("~/nuclei-templates/http/exposures")

            cmd = ["nuclei", "-l", js_url_file, "-t", template_path, "-j", "-o", output_file, "-rl", "5", "-c", "3", "-timeout", "20", "-severity", "medium,high,critical"]

            subprocess.run(cmd, capture_output=True, text=True)

            return json.dumps({
                "status": "SUCCESS",
                "output_file": output_file
            })

        except Exception as e:
            return json.dumps({"status": "ERROR", "message": f"Nuclei scan failed: {str(e)}"})