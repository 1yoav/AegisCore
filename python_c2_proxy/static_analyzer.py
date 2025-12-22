"""
Static File Analyzer - PE, Entropy, Strings, Metadata
Analyzes executable files without running them
"""
import math
import re
import os
from typing import Tuple, List, Dict
from datetime import datetime

class StaticAnalyzer:
    """Static file analysis only - no behavioral/network stuff"""

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
                        'chrome.exe', 'services', 'winlogon', 'update', 'updater']

    SUSPICIOUS_PATHS = ['temp', 'tmp', 'downloads', 'appdata\\local\\temp',
                       'users\\public', 'programdata']

    def analyze_file(self, file_path: str) -> Tuple[float, List[str], Dict]:
        """
        Analyze a file statically
        Returns: (score 0-100, findings list, metadata dict)
        """
        score = 0.0
        findings = []
        metadata = {}

        if not os.path.exists(file_path):
            return 0.0, ["[ERROR] File not found"], {}

        try:
            # PE Analysis (40 pts)
            pe_score, pe_findings, pe_meta = self._analyze_pe(file_path)
            score += pe_score
            findings.extend(pe_findings)
            metadata['pe'] = pe_meta

            # Entropy (30 pts)
            ent_score, ent_findings, ent_meta = self._analyze_entropy(file_path)
            score += ent_score
            findings.extend(ent_findings)
            metadata['entropy'] = ent_meta

            # Strings (20 pts)
            str_score, str_findings, str_meta = self._analyze_strings(file_path)
            score += str_score
            findings.extend(str_findings)
            metadata['strings'] = str_meta

            # Metadata (10 pts)
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
            pe = pefile.PE(path)

            # Section checks
            if len(pe.sections) < 3:
                score += 5.0
                findings.append(f"[PE] Few sections ({len(pe.sections)}) - packed?")

            for sec in pe.sections:
                name = sec.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                if any(p in name for p in ['.upx', '.aspack', '.rlpack']):
                    score += 5.0
                    findings.append(f"[PE] Packer: {name}")
                    break

            # Imports
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

            # Timestamp
            ts = pe.FILE_HEADER.TimeDateStamp
            if ts > datetime.now().timestamp():
                score += 5.0
                findings.append("[PE] Future timestamp")
            elif ts < 946684800:
                score += 3.0
                findings.append("[PE] Old timestamp")

            # Entry point
            ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
            in_text = False
            for sec in pe.sections:
                if sec.VirtualAddress <= ep < sec.VirtualAddress + sec.Misc_VirtualSize:
                    sname = sec.Name.decode('utf-8', errors='ignore').strip('\x00').lower()
                    if sname not in ['.text', 'code', '.code']:
                        score += 5.0
                        findings.append(f"[PE] Entry in '{sname}'")
                    in_text = True
                    break

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

            if ent > 7.5:
                score += 30
                findings.append(f"[ENTROPY] Very high ({ent:.2f}) - packed")
            elif ent > 7.0:
                score += 20
                findings.append(f"[ENTROPY] High ({ent:.2f}) - compressed")
            elif ent > 6.5:
                score += 10
                findings.append(f"[ENTROPY] Elevated ({ent:.2f})")
            else:
                findings.append(f"[ENTROPY] Normal ({ent:.2f})")

            # Per-section
            if HAS_PEFILE:
                try:
                    pe = pefile.PE(path)
                    for sec in pe.sections:
                        sdata = sec.get_data()
                        sent = self._calc_entropy(sdata)
                        sname = sec.Name.decode('utf-8', errors='ignore').strip('\x00')
                        if sname == '.text' and sent > 7.0:
                            score += 5
                            findings.append(f"[ENTROPY] Code section packed")
                    pe.close()
                except:
                    pass
        except Exception as e:
            findings.append(f"[ENTROPY ERROR] {str(e)}")

        return min(score, 30), findings, metadata

    def _calc_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        entropy = 0.0
        for c in counts:
            if c == 0:
                continue
            p = float(c) / len(data)
            entropy -= p * math.log2(p)
        return entropy

    def _analyze_strings(self, path: str) -> Tuple[float, List[str], Dict]:
        score = 0.0
        findings = []
        metadata = {}

        try:
            strings = self._extract_strings(path)
            metadata['count'] = len(strings)

            urls = []
            ips = []
            keywords = []

            url_re = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')
            ip_re = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

            sus_kw = ['cmd.exe', 'powershell', 'shell', 'download', 'upload',
                     'encrypt', 'decrypt', 'inject']

            for s in strings:
                urls.extend(url_re.findall(s))
                ips.extend(ip_re.findall(s))
                for kw in sus_kw:
                    if kw in s.lower():
                        keywords.append(kw)

            if urls:
                score += min(len(urls) * 3, 10)
                findings.append(f"[STRINGS] URLs: {', '.join(urls[:3])}")
                metadata['urls'] = urls[:10]

            if ips:
                score += min(len(ips) * 2, 5)
                findings.append(f"[STRINGS] IPs: {', '.join(ips[:3])}")
                metadata['ips'] = ips[:10]

            if keywords:
                score += min(len(set(keywords)), 5)
                findings.append(f"[STRINGS] Keywords: {', '.join(set(keywords)[:5])}")

            if len(strings) < 50:
                score += 5
                findings.append(f"[STRINGS] Few strings ({len(strings)}) - obfuscated?")

        except Exception as e:
            findings.append(f"[STRINGS ERROR] {str(e)}")

        return min(score, 20), findings, metadata

    def _extract_strings(self, path: str, min_len: int = 4) -> List[str]:
        strings = []
        with open(path, 'rb') as f:
            data = f.read()

        # ASCII
        ascii_re = b'[\x20-\x7E]{' + str(min_len).encode() + b',}'
        strings.extend([s.decode('ascii') for s in re.findall(ascii_re, data)])

        # Unicode
        uni_re = b'(?:[\x20-\x7E]\x00){' + str(min_len).encode() + b',}'
        strings.extend([s.decode('utf-16le', errors='ignore') for s in re.findall(uni_re, data)])

        return strings

    def _analyze_metadata(self, path: str) -> Tuple[float, List[str]]:
        score = 0.0
        findings = []

        path_lower = path.lower()
        for sus_path in self.SUSPICIOUS_PATHS:
            if sus_path in path_lower:
                score += 5
                findings.append(f"[META] Suspicious location: {sus_path}")
                break

        fname = os.path.basename(path).lower()
        for sus_name in self.SUSPICIOUS_NAMES:
            if sus_name in fname:
                score += 3
                findings.append(f"[META] Suspicious name: {sus_name}")
                break

        size = os.path.getsize(path)
        if size < 10 * 1024:
            score += 2
            findings.append(f"[META] Small file: {size} bytes")
        elif size > 50 * 1024 * 1024:
            score += 1
            findings.append(f"[META] Large file: {size/(1024*1024):.1f} MB")

        return min(score, 10), findings
