"""
IOC (Indicator of Compromise) Extraction
Extracts IPs, domains, URLs, and potential encryption keys from traffic
"""

import re
import base64
from typing import Dict, List

class ConfigExtractor:
    """Extracts IOCs and configuration data from malware traffic"""
    
    # Regex patterns
    IP_PATTERN = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
    DOMAIN_PATTERN = re.compile(r'\b[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.([a-z]{2,}|xn--[a-z0-9]+)\b', re.IGNORECASE)
    URL_PATTERN = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE)
    EMAIL_PATTERN = re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{20,}={0,2}')
    
    def extract_iocs(self, raw_data: bytes) -> Dict[str, List[str]]:
        """
        Main extraction function
        Returns dictionary of IOC types and their values
        """
        iocs = {
            'ips': [],
            'domains': [],
            'urls': [],
            'emails': [],
            'potential_keys': [],
            'suspicious_strings': []
        }
        
        # Try to decode as UTF-8
        try:
            decoded = raw_data.decode('utf-8', errors='ignore')
        except:
            decoded = str(raw_data)
        
        # Extract IPs
        iocs['ips'] = list(set(self.IP_PATTERN.findall(decoded)))
        
        # Extract domains (filter out IPs that were caught)
        domains = self.DOMAIN_PATTERN.findall(decoded)
        iocs['domains'] = list(set([
            f"{d[0]}.{d[1]}" for d in domains 
            if not self._is_ip(f"{d[0]}.{d[1]}")
        ]))
        
        # Extract URLs
        iocs['urls'] = list(set(self.URL_PATTERN.findall(decoded)))
        
        # Extract emails
        iocs['emails'] = list(set(self.EMAIL_PATTERN.findall(decoded)))
        
        # Extract potential encryption keys (base64 strings)
        base64_candidates = self.BASE64_PATTERN.findall(decoded)
        for candidate in base64_candidates:
            # Filter: must be long enough and valid base64
            if len(candidate) >= 32 and self._is_valid_base64(candidate):
                iocs['potential_keys'].append(candidate)
        
        # Look for suspicious command strings
        iocs['suspicious_strings'] = self._find_suspicious_strings(decoded)
        
        return iocs
    
    def _is_ip(self, text: str) -> bool:
        """Check if string is an IP address"""
        parts = text.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except:
            return False
    
    def _is_valid_base64(self, text: str) -> bool:
        """Check if string is valid base64"""
        try:
            base64.b64decode(text, validate=True)
            return True
        except:
            return False
    
    def _find_suspicious_strings(self, text: str) -> List[str]:
        """Find command-like strings in traffic"""
        suspicious = []
        
        # Common malware commands
        commands = [
            'download', 'upload', 'execute', 'shell', 'cmd',
            'powershell', 'inject', 'keylog', 'screenshot',
            'encrypt', 'ransom', 'exfil', 'steal', 'dump'
        ]
        
        text_lower = text.lower()
        for cmd in commands:
            if cmd in text_lower:
                # Extract context (20 chars before and after)
                idx = text_lower.index(cmd)
                start = max(0, idx - 20)
                end = min(len(text), idx + len(cmd) + 20)
                context = text[start:end].strip()
                suspicious.append(f"Command '{cmd}': {context}")
        
        return suspicious
    
    def extract_config(self, raw_data: bytes) -> Dict:
        """
        Attempt to extract malware configuration
        Looks for common config patterns
        """
        config = {
            'c2_servers': [],
            'encryption_key': None,
            'campaign_id': None,
            'version': None
        }
        
        try:
            decoded = raw_data.decode('utf-8', errors='ignore')
            
            # Look for JSON config
            if '{' in decoded and '}' in decoded:
                import json
                try:
                    # Try to extract JSON
                    start = decoded.index('{')
                    end = decoded.rindex('}') + 1
                    json_str = decoded[start:end]
                    parsed = json.loads(json_str)
                    
                    # Common config keys
                    if 'c2' in parsed or 'server' in parsed:
                        config['c2_servers'] = parsed.get('c2', parsed.get('server', []))
                    if 'key' in parsed:
                        config['encryption_key'] = parsed.get('key')
                    if 'id' in parsed or 'campaign' in parsed:
                        config['campaign_id'] = parsed.get('id', parsed.get('campaign'))
                    if 'version' in parsed or 'ver' in parsed:
                        config['version'] = parsed.get('version', parsed.get('ver'))
                except:
                    pass
        except:
            pass
        
        return config