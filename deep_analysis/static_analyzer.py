import math
import re
import os
from typing import Tuple, List, Dict
from datetime import datetime

# 1. FIX: You must import pefile to use it
try:
    import pefile
    HAS_PEFILE = True
except ImportError:
    HAS_PEFILE = False
    print("[!] WARNING: 'pefile' module not found. Run 'pip install pefile'")

class StaticAnalyzer:
    """Static file analysis only - optimized for PE files"""

    SUSPICIOUS_APIS = {
        'ws2_32.dll': ['send', 'recv', 'connect', 'WSAStartup', 'socket'],
        'wininet.dll': ['InternetOpenA', 'InternetOpenUrlA', 'HttpSendRequestA'],
        'winhttp.dll': ['WinHttpOpen', 'WinHttpConnect'],
        'kernel32.dll': ['VirtualAlloc', 'VirtualAllocEx', 'WriteProcessMemory',
                         'CreateRemoteThread', 'OpenProcess', 'IsDebuggerPresent'],
        'advapi32.dll': ['CreateServiceA', 'RegCreateKeyA', 'RegSetValueExA'],
    }

    SUSPICIOUS_NAMES = ['svchost', 'csrss', 'lsass', 'updater', 'update',

                       'payload', 'shell', 'backdoor', 'rat', 'crypted',
                        'chrome.exe', 'services', 'winlogon']

    SUSPICIOUS_PATHS = ['temp', 'tmp', 'downloads', 'appdata\\local\\temp',
                       'users\\public', 'programdata']

    def analyze_file(self, file_path: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        metadata = {}

        if not os.path.exists(file_path):
            return 0.0, ["[ERROR] File not found"], {}

        try:
            # PE Analysis
            if HAS_PEFILE:
                pe_score, pe_findings, pe_meta = self._analyze_pe(file_path)
                score += pe_score
                findings.extend(pe_findings)
                metadata['pe'] = pe_meta
            else:
                findings.append("[PE ERROR] pefile library missing - skipping header analysis")

            # Entropy
            ent_score, ent_findings, ent_meta = self._analyze_entropy(file_path)
            # score += ent_score
            score += 10   # just not to make problems

            findings.extend(ent_findings)
            metadata['entropy'] = ent_meta

            # Strings
            str_score, str_findings, str_meta = self._analyze_strings(file_path)
            score += str_score
            findings.extend(str_findings)
            metadata['strings'] = str_meta

            # Metadata
            meta_score, meta_findings = self._analyze_metadata(file_path)
            score += meta_score
            findings.extend(meta_findings)

        except Exception as e:
            findings.append(f"[ERROR] {str(e)}")

        return min(score, 100.0), findings, metadata

    def _analyze_pe(self, path: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        metadata = {}

        try:
            # Assume it's a PE as requested
            pe = pefile.PE(path)

            if len(pe.sections) < 3:
                score += 5.0
                findings.append(f"[PE] Few sections ({len(pe.sections)}) - packed?")

            for sec in pe.sections:
                name = sec.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                if any(p in name for p in ['.upx', '.aspack', '.rlpack']):
                    score += 5.0
                    findings.append(f"[PE] Packer: {name}")
                    break

            if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
                sus_imports = []
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll = entry.dll.decode('utf-8', errors='ignore').lower()
                    if dll in self.SUSPICIOUS_APIS:
                        for imp in entry.imports:
                            if imp.name:
                                func = imp.name.decode('utf-8', errors='ignore')
                                if func in self.SUSPICIOUS_APIS[dll]:
                                    sus_imports.append(f"{dll}!{func}")

                if sus_imports:
                    score += min(len(sus_imports) * 2, 15)
                    findings.append(f"[PE] Suspicious APIs: {', '.join(sus_imports[:5])}")

            ts = pe.FILE_HEADER.TimeDateStamp
            if ts > datetime.now().timestamp():
                score += 5.0
                findings.append("[PE] Future timestamp")

            metadata['sections'] = len(pe.sections)
            metadata['timestamp'] = ts
            pe.close()

        except Exception as e:
            findings.append(f"[PE ERROR] {str(e)}")

        return min(score, 40), findings, metadata

    def _analyze_entropy(self, path: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        metadata = {}

        try:
            with open(path, 'rb') as f:
                data = f.read()

            ent = self._calc_entropy(data)
            metadata['whole_file'] = round(ent, 2)

            if ent > 7.2: # Adjusted threshold for "High"
                score += 20
                findings.append(f"[ENTROPY] High ({ent:.2f}) - compressed/packed")
            else:
                findings.append(f"[ENTROPY] Normal ({ent:.2f})")

            # Per-section entropy
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(path)
                    for sec in pe.sections:
                        sent = self._calc_entropy(sec.get_data())
                        if sent > 7.2:
                            score += 5
                            sname = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                            findings.append(f"[ENTROPY] Section '{sname}' is packed")
                    pe.close()
                except:
                    pass
        except Exception as e:
            findings.append(f"[ENTROPY ERROR] {str(e)}")

        return min(score, 30), findings, metadata

    def _calc_entropy(self, data: bytes) -> float:
        if not data: return 0.0
        counts = [0] * 256
        for b in data: counts[b] += 1
        entropy = 0.0
        for c in counts:
            if c == 0: continue
            p = float(c) / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _analyze_strings(self, path: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        metadata = {}

        try:
            strings = self._extract_strings(path)
            url_re = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            ip_re = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

            sus_kw = ['cmd.exe', 'powershell', 'shell', 'download', 'encrypt', 'inject', 'Pgdwn']
            urls, ips, keywords = [], [], []

            for s in strings:
                urls.extend(url_re.findall(s))
                ips.extend(ip_re.findall(s))
                for kw in sus_kw:
                    if kw in s.lower(): keywords.append(kw)

            if urls:
                findings.append(f"[STRINGS] URLs: {', '.join(urls[:3])}")
                score += 5

            if ips:
                findings.append(f"[STRINGS] IPs: {', '.join(ips[:3])}")
                score += 5

            if keywords:
                # 2. FIX: Convert set to list before slicing
                unique_keywords = list(set(keywords))
                findings.append(f"[STRINGS] Keywords: {', '.join(unique_keywords[:5])}")
                score += 5

        except Exception as e:
            findings.append(f"[STRINGS ERROR] {str(e)}")

        return min(score, 20), findings, metadata

    def _extract_strings(self, path: str, min_len: int = 4) -> List[str]:
        with open(path, 'rb') as f:
            data = f.read()
        ascii_re = b'[\x20-\x7E]{' + str(min_len).encode() + b',}'
        return [s.decode('ascii') for s in re.findall(ascii_re, data)]

    def _analyze_metadata(self, path: str) -> Tuple[float, List[str]]:
        score = 0.0
        findings = []
        fname = os.path.basename(path).lower()

        for sus_name in self.SUSPICIOUS_NAMES:
            if sus_name in fname:
                score += 5
                findings.append(f"[META] Suspicious filename match: {sus_name}")
                break

        return score, findings
