"""
Protocol Detection and Analysis
Identifies HTTP, TLS, DNS, Binary protocols and calculates entropy
"""

import math
import re
from typing import Tuple, Optional, Dict

class ProtocolDetector:
    """Detects and analyzes network protocols"""
    
    @staticmethod
    def detect(raw_data: bytes) -> Tuple[str, Optional[Dict]]:
        """
        Main detection function
        Returns: (protocol_name, parsed_data)
        """
        if len(raw_data) == 0:
            return 'EMPTY', None
        
        # HTTP Detection
        if raw_data.startswith(b'GET ') or \
           raw_data.startswith(b'POST ') or \
           raw_data.startswith(b'HEAD ') or \
           raw_data.startswith(b'PUT '):
            return 'HTTP', ProtocolDetector.parse_http(raw_data)
        
        # TLS/SSL Detection (Handshake starts with 0x16 0x03)
        if len(raw_data) >= 2 and raw_data[0:2] == b'\x16\x03':
            return 'TLS', ProtocolDetector.parse_tls(raw_data)
        
        # DNS Detection (simple heuristic)
        if ProtocolDetector.looks_like_dns(raw_data):
            return 'DNS', ProtocolDetector.parse_dns(raw_data)
        
        # Check entropy
        entropy = ProtocolDetector.calculate_entropy(raw_data)
        if entropy > 7.5:
            return 'ENCRYPTED', {'entropy': entropy}
        
        return 'BINARY', {'entropy': entropy}
    
    @staticmethod
    def parse_http(raw_data: bytes) -> Dict:
        """Extract HTTP headers and body"""
        try:
            decoded = raw_data.decode('utf-8', errors='ignore')
            lines = decoded.split('\r\n')
            
            # Parse request line
            request_line = lines[0] if lines else ""
            method = request_line.split(' ')[0] if ' ' in request_line else "UNKNOWN"
            path = request_line.split(' ')[1] if len(request_line.split(' ')) > 1 else "/"
            
            # Parse headers
            headers = {}
            body_start = 0
            for i, line in enumerate(lines[1:], 1):
                if line == '':
                    body_start = i + 1
                    break
                if ':' in line:
                    key, value = line.split(':', 1)
                    headers[key.strip().lower()] = value.strip()
            
            # Extract body
            body = '\r\n'.join(lines[body_start:]) if body_start > 0 else ""
            
            return {
                'method': method,
                'path': path,
                'headers': headers,
                'user_agent': headers.get('user-agent', 'MISSING'),
                'host': headers.get('host', 'MISSING'),
                'body': body,
                'content_length': len(body)
            }
        except Exception as e:
            return {'error': str(e)}
    
    @staticmethod
    def parse_tls(raw_data: bytes) -> Dict:
        """Extract TLS handshake info"""
        try:
            # TLS Record: [type(1)][version(2)][length(2)][data...]
            record_type = raw_data[0]
            tls_version = (raw_data[1] << 8) | raw_data[2]
            record_length = (raw_data[3] << 8) | raw_data[4]
            
            version_map = {
                0x0301: "TLS 1.0",
                0x0302: "TLS 1.1",
                0x0303: "TLS 1.2",
                0x0304: "TLS 1.3"
            }
            
            return {
                'record_type': record_type,
                'version': version_map.get(tls_version, f"Unknown (0x{tls_version:04x})"),
                'length': record_length
            }
        except:
            return {'error': 'TLS parse failed'}
    
    @staticmethod
    def looks_like_dns(raw_data: bytes) -> bool:
        """Heuristic DNS detection"""
        if len(raw_data) < 12:
            return False
        
        # DNS has 12-byte header
        # Check for reasonable flags and counts
        try:
            # Transaction ID: first 2 bytes (can be anything)
            # Flags: bytes 2-3
            flags = (raw_data[2] << 8) | raw_data[3]
            
            # QR bit (bit 15): 0=query, 1=response
            # Opcode (bits 11-14): should be 0 for standard query
            qr = (flags >> 15) & 0x1
            opcode = (flags >> 11) & 0xF
            
            # QDCOUNT (bytes 4-5): number of questions (usually 1)
            qdcount = (raw_data[4] << 8) | raw_data[5]
            
            # Heuristic: standard query with 1 question
            if opcode == 0 and 0 <= qdcount <= 10:
                return True
        except:
            pass
        
        return False
    
    @staticmethod
    def parse_dns(raw_data: bytes) -> Dict:
        """Basic DNS parsing"""
        try:
            transaction_id = (raw_data[0] << 8) | raw_data[1]
            flags = (raw_data[2] << 8) | raw_data[3]
            qdcount = (raw_data[4] << 8) | raw_data[5]
            ancount = (raw_data[6] << 8) | raw_data[7]
            
            return {
                'transaction_id': transaction_id,
                'questions': qdcount,
                'answers': ancount,
                'is_response': (flags >> 15) & 0x1
            }
        except:
            return {'error': 'DNS parse failed'}
    
    @staticmethod
    def calculate_entropy(data: bytes) -> float:
        """
        Shannon entropy calculation
        Returns 0-8 (bits of entropy per byte)
        High entropy (>7.5) = encrypted/compressed data
        """
        if not data:
            return 0.0
        
        # Count byte frequencies
        byte_counts = [0] * 256
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0.0
        data_len = len(data)
        
        for count in byte_counts:
            if count == 0:
                continue
            probability = float(count) / data_len
            entropy -= probability * math.log2(probability)
        
        return entropy
