"""
YARA Analyzer Module
Dedicated handler for YARA rule compilation and scanning.
"""
import os
from typing import Tuple, List, Dict
import yara
from pathlib import Path
import sys


class YaraAnalyzer:
    def __init__(self, rules_dir: str = "./yara_rules"):
        if getattr(sys, 'frozen', False):
            # אם רץ כ-EXE
            self.rules_dir = Path(sys.executable).parent.parent / "yara_rules"
        else:
            # אם רץ כסקריפט פייתון רגיל
            self.rules_dir = Path(__file__).resolve().parent / "yara_rules"
        self.rules = None
        self.compiled = False
        self._compile_rules()

    def _compile_rules(self):
        """Compiles all .yar files in the specified directory"""
        if not os.path.exists(self.rules_dir):
            print(f"[YARA] Warning: Directory '{self.rules_dir}' not found. Skipping YARA.")
            return

        filepaths = {}
        try:
            # Find all .yar files
            for filename in os.listdir(self.rules_dir):
                if filename.endswith(".yar") or filename.endswith(".yara"):
                    # Use filename (w/o extension) as the namespace
                    namespace = os.path.splitext(filename)[0]
                    filepaths[namespace] = os.path.join(self.rules_dir, filename)

            if filepaths:
                # print(f"[YARA] Compiling {len(filepaths)} rule files...")
                self.rules = yara.compile(filepaths=filepaths)
                self.compiled = True
                # print("[YARA] Rules compiled successfully.")
            else:
                print("[YARA] No rules found in directory.")

        except Exception as e:
            print(f"[YARA] Compilation Error: {e}")

    def scan_file(self, file_path: str) -> Tuple[float, List[str], Dict]:
        """
        Scans a file against loaded YARA rules.

        Returns:
            - Score (float): 0.0 to 100.0 (100.0 if any rule matches)
            - Findings (List[str]): Description of matches
            - Metadata (Dict): Rule metadata
        """
        score = 0.0
        findings = []
        metadata = {}

        if not self.compiled or not self.rules:
            return 0.0, [], {}

        if not os.path.exists(file_path):
            return 0.0, [""], {}

        matches = self.rules.match(file_path)

        if matches:
            # A YARA match is usually a high-confidence indicator
            score = 100.0

            match_names = [m.rule for m in matches]
            findings.append(f"[YARA] DETECTED: {', '.join(match_names)}\n")

            # Extract metadata from matches
            for match in matches:
                if match.meta:
                    metadata[match.rule] = match.meta

                    # Optional: Adjust score based on 'severity' meta field if present
                    if 'severity' in match.meta:
                        severity = str(match.meta['severity']).lower()
                        if severity == 'low':
                            score = 50.0  # Lower confidence for 'low' severity rules

        return score, findings, metadata
