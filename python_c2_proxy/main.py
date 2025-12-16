"""
C2 Proxy - Main Entry Point
Intercepts redirected malware traffic, analyzes it, and emulates C2 responses
"""

import socket
import threading
import json
from datetime import datetime
from typing import Optional

from analyzer import Analyzer
from c2_emulator import C2Emulator
from config_extractor import ConfigExtractor
from driver_ipc import DriverContext
from threat_logger import ThreatLogger
from protocol_detector import ProtocolDetector
import config as cfg

class C2Proxy:
    """Main C2 Proxy Server"""

    def __init__(self):
        print("[*] Initializing C2 Proxy...")

        # Core components
        self.analyzer = Analyzer()
        self.emulator = C2Emulator()
        self.driver = DriverContext()
        self.logger = ThreatLogger(cfg.DATABASE_PATH)

        # Load threat intelligence
        self._load_threat_intel()

        print(f"[✓] C2 Proxy initialized")
        print(f"[✓] Known C2 IPs: {len(cfg.KNOWN_C2_IPS)}")

    def _load_threat_intel(self):
        """Load known C2 IPs from database (if available)"""
        try:
            # In production, load from your SQLDatabase CIDR_IPS table
            # For now, add some test IPs
            test_c2_ips = {
                "185.220.101.50",   # Known Tor exit node
                "172.67.14.99",     # Cloudflare (often abused)
                "192.0.78.24",      # Example malicious IP
            }
            cfg.KNOWN_C2_IPS.update(test_c2_ips)
            self.analyzer.load_threat_intel(test_c2_ips)
        except Exception as e:
            print(f"[!] Could not load threat intel: {e}")

    def handle_connection(self, conn: socket.socket, addr: tuple):
        """Handle a single redirected connection"""
        client_ip, client_port = addr

        try:
            # --- STEP 1: Get Process Metadata from C++ Driver ---
            pid, proc_name, orig_ip, orig_port = self.driver.get_process_metadata(client_port)

            print(f"\n{'='*60}")
            print(f"[+] NEW CONNECTION")
            print(f"    Process: {proc_name} (PID {pid})")
            print(f"    Original Destination: {orig_ip}:{orig_port}")
            print(f"{'='*60}")

            # --- STEP 2: Receive Data ---
            raw_data = conn.recv(8192)

            if not raw_data:
                print("[-] No data received, closing connection")
                return

            print(f"[→] Received {len(raw_data)} bytes")

            # --- STEP 3: Analyze Threat ---
            confidence, findings, metadata = self.analyzer.analyze(
                pid, proc_name, raw_data, orig_ip, orig_port
            )

            # --- STEP 4: Generate Verdict ---
            verdict = self._generate_verdict(
                pid, proc_name, orig_ip, orig_port,
                confidence, findings, metadata
            )

            # --- STEP 5: Display Results ---
            self._print_verdict(verdict)

            # --- STEP 6: Take Action ---
            response = self._take_action(conn, verdict, raw_data, metadata)

            # --- STEP 7: Log Everything ---
            self.logger.log_traffic(verdict, raw_data, response)

        except Exception as e:
            print(f"[!] Error handling connection: {e}")
            import traceback
            traceback.print_exc()
        finally:
            try:
                conn.close()
            except:
                pass

    def _generate_verdict(self, pid: int, proc_name: str,
                         dest_ip: str, dest_port: int,
                         confidence: float, findings: list,
                         metadata: dict) -> dict:
        """Generate structured verdict"""

        # Determine verdict string
        if confidence >= cfg.KILL_THRESHOLD:
            verdict_str = "MALICIOUS"
        elif confidence >= cfg.ALERT_THRESHOLD:
            verdict_str = "SUSPICIOUS"
        elif confidence >= cfg.LOG_THRESHOLD:
            verdict_str = "QUESTIONABLE"
        else:
            verdict_str = "BENIGN"

        return {
            'timestamp': datetime.now().isoformat(),
            'pid': pid,
            'process': proc_name,
            'dest_ip': dest_ip,
            'dest_port': dest_port,
            'protocol': metadata.get('protocol', 'unknown'),
            'confidence': round(confidence * 100, 2),  # Convert to percentage
            'verdict': verdict_str,
            'findings': findings,
            'iocs': metadata.get('iocs', {}),
            'config': metadata.get('config', {})
        }

    def _print_verdict(self, verdict: dict):
        """Pretty-print the analysis results"""
        confidence = verdict['confidence']

        # Color coding
        if confidence >= 85:
            color = '\033[1;31m'  # Bright red
        elif confidence >= 60:
            color = '\033[1;33m'  # Yellow
        elif confidence >= 30:
            color = '\033[1;34m'  # Blue
        else:
            color = '\033[1;32m'  # Green

        reset = '\033[0m'

        print(f"\n{color}[VERDICT: {verdict['verdict']}]{reset}")
        print(f"Confidence Score: {color}{confidence}%{reset}")
        print(f"Protocol: {verdict['protocol']}")

        if verdict['findings']:
            print(f"\nFindings ({len(verdict['findings'])}):")
            for finding in verdict['findings']:
                print(f"  • {finding}")

        # Print IOCs if found
        iocs = verdict.get('iocs', {})
        if any(iocs.values()):
            print(f"\nExtracted IOCs:")
            if iocs.get('ips'):
                print(f"  IPs: {', '.join(iocs['ips'][:5])}")
            if iocs.get('domains'):
                print(f"  Domains: {', '.join(iocs['domains'][:5])}")
            if iocs.get('urls'):
                print(f"  URLs: {', '.join(iocs['urls'][:3])}")
            if iocs.get('suspicious_strings'):
                print(f"  Commands: {len(iocs['suspicious_strings'])} detected")

        # Print config if extracted
        config_data = verdict.get('config', {})
        if any(config_data.values()):
            print(f"\n[!] Malware Configuration Extracted:")
            print(json.dumps(config_data, indent=2))

    def _take_action(self, conn: socket.socket, verdict: dict,
                    raw_data: bytes, metadata: dict) -> bytes:
        """Decide what to do based on verdict"""
        confidence = verdict['confidence']
        pid = verdict['pid']
        protocol = metadata.get('protocol')
        parsed_data = metadata.get('parsed')

        # HIGH CONFIDENCE (>85%) = Kill Process
        if confidence >= cfg.KILL_THRESHOLD * 100:
            print(f"\n[!] HIGH THREAT DETECTED - Terminating PID {pid}")
            self.driver.send_kill_command(pid)
            self.logger.mark_killed(pid)
            conn.close()
            return b''

        # MEDIUM/LOW CONFIDENCE = Emulate C2 to gather more intel
        else:
            print(f"[→] Emulating C2 response to gather more intelligence...")
            response = self.emulator.generate_response(
                pid, protocol, parsed_data, raw_data
            )

            if response:
                conn.sendall(response)
                print(f"[←] Sent {len(response)} byte response")

            return response

    def start(self, host: str = None, port: int = None):
        """Start the C2 Proxy server"""
        host = host or cfg.LISTEN_IP
        port = port or cfg.LISTEN_PORT

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((host, port))
        server.listen(10)

        print(f"\n{'='*60}")
        print(f"[*] C2 Proxy Server Started")
        print(f"[*] Listening on {host}:{port}")
        print(f"[*] Waiting for WFP-redirected traffic...")
        print(f"[*] Press Ctrl+C to stop")
        print(f"{'='*60}\n")

        try:
            while True:
                conn, addr = server.accept()

                # Handle each connection in a separate thread
                handler = threading.Thread(
                    target=self.handle_connection,
                    args=(conn, addr),
                    daemon=True
                )
                handler.start()

        except KeyboardInterrupt:
            print("\n[*] Shutting down C2 Proxy...")
            server.close()

            # Print summary
            summary = self.logger.get_threat_summary(limit=10)
            if summary:
                print(f"\n{'='*60}")
                print("[*] Session Summary - Top 10 Threats:")
                print(f"{'='*60}")
                for threat in summary:
                    print(f"PID {threat['pid']:5d} | {threat['process']:20s} | "
                          f"Conf: {threat['max_confidence']*100:5.1f}% | "
                          f"Conns: {threat['connections']:3d} | "
                          f"Killed: {'YES' if threat['killed'] else 'NO'}")
                print(f"{'='*60}\n")

def main():
    """Entry point"""
    print("""
    ╔═══════════════════════════════════════════════════════════╗
    ║                                                           ║
    ║              C2 PROXY - Malware Analysis System           ║
    ║                                                           ║
    ║  Intercepts suspicious network traffic and analyzes it   ║
    ║  for Command & Control (C2) communication patterns       ║
    ║                                                           ║
    ╚═══════════════════════════════════════════════════════════╝
    """)

    proxy = C2Proxy()
    proxy.start()

if __name__ == '__main__':
    main()
