"""
C2 Server Emulation
Responds to malware traffic to trigger additional behaviors
"""

import json
from typing import Dict, Optional

class C2Emulator:
    """Emulates C2 server responses to extract more intel from malware"""
    
    def __init__(self):
        self.interaction_count = {}  # Track per-PID
    
    def generate_response(self, pid: int, protocol: str, 
                         parsed_data: Optional[Dict], 
                         raw_request: bytes) -> bytes:
        """
        Generate appropriate C2 response based on protocol and request
        """
        # Track interactions
        self.interaction_count[pid] = self.interaction_count.get(pid, 0) + 1
        interaction_num = self.interaction_count[pid]
        
        if protocol == 'HTTP':
            return self._emulate_http_c2(pid, parsed_data, raw_request, interaction_num)
        elif protocol == 'DNS':
            return self._emulate_dns_c2(raw_request)
        elif protocol == 'TLS':
            # Can't easily emulate without proper TLS handshake
            return b''
        else:
            return self._emulate_generic_c2(raw_request, interaction_num)
    
    def _emulate_http_c2(self, pid: int, parsed_data: Optional[Dict], 
                        raw_request: bytes, interaction_num: int) -> bytes:
        """
        Emulate HTTP-based C2 server
        Progressive responses to trigger different malware behaviors
        """
        if not parsed_data:
            return self._build_http_response({"status": "error"})
        
        path = parsed_data.get('path', '/').lower()
        method = parsed_data.get('method', 'GET')
        body = parsed_data.get('body', '')
        
        # Interaction 1: Initial beacon - respond with "idle"
        if interaction_num == 1:
            response_data = {
                "status": "ok",
                "command": "idle",
                "interval": 60,
                "jitter": 5
            }
            print(f"[C2 EMU] Sending 'idle' command to PID {pid}")
            return self._build_http_response(response_data)
        
        # Interaction 2: Send reconnaissance command
        elif interaction_num == 2:
            response_data = {
                "status": "ok",
                "command": "sysinfo",
                "params": ["hostname", "username", "os", "arch"]
            }
            print(f"[C2 EMU] Requesting sysinfo from PID {pid}")
            return self._build_http_response(response_data)
        
        # Interaction 3: Request file listing
        elif interaction_num == 3:
            response_data = {
                "status": "ok",
                "command": "list_files",
                "path": "C:\\Users"
            }
            print(f"[C2 EMU] Requesting file listing from PID {pid}")
            return self._build_http_response(response_data)
        
        # Interaction 4+: Send download command (fake payload)
        else:
            response_data = {
                "status": "ok",
                "command": "download_execute",
                "url": "http://fake-stage2.local/payload.exe",
                "save_as": "update.exe"
            }
            print(f"[C2 EMU] Sending fake download command to PID {pid}")
            return self._build_http_response(response_data)
    
    def _emulate_dns_c2(self, raw_request: bytes) -> bytes:
        """
        Emulate DNS C2 response
        DNS tunneling typically expects CNAME or TXT records
        """
        # Simple DNS response (would need proper DNS packet construction)
        # For now, just return empty to avoid crashing malware
        return b''
    
    def _emulate_generic_c2(self, raw_request: bytes, interaction_num: int) -> bytes:
        """
        Generic binary protocol emulation
        Echo back with slight modifications
        """
        if interaction_num == 1:
            # First contact: Simple ACK
            return b'\x00\x01OK'
        elif interaction_num == 2:
            # Second contact: Send fake command code
            return b'\x00\x02\x10\x20\x30\x40'  # Fake command bytes
        else:
            # Echo back (some malware expects this)
            return raw_request[:50]  # Echo first 50 bytes
    
    def _build_http_response(self, data: Dict) -> bytes:
        """Construct HTTP response with JSON body"""
        body = json.dumps(data).encode('utf-8')
        
        response = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41\r\n"
            b"Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n".encode('utf-8') +
            b"Connection: close\r\n"
            b"Cache-Control: no-cache\r\n"
            b"\r\n" +
            body
        )
        
        return response
