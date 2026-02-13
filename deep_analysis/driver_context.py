"""
Driver Context - Handles C++ alerts and manages investigations
Updated: Removed C2 Emulator interactions
"""
import threading
import json
import win32pipe
import win32file
import pywintypes
from typing import Dict
from datetime import datetime

from events import Event, InvestigationContext
from analyzer import Analyzer
# from c2_emulator import C2Emulator  <-- REMOVED
from threat_logger import ThreatLogger

DRIVER_PIPE_NAME = r"\\.\pipe\AVDeepScanPipe"
DATABASE_PATH = "c2_threats.db"


class DriverContext:
    """Manages communication with C++ driver and threat investigations"""

    def __init__(self):
        self.pipe_name = DRIVER_PIPE_NAME
        self.running = False
        self.investigations: Dict[int, InvestigationContext] = {}

        # Core components
        self.analyzer = Analyzer()
        # self.emulator = C2Emulator() <-- REMOVED
        self.logger = ThreatLogger(DATABASE_PATH)

        print("[*] Driver Context initialized (Static Analysis Enabled)")

    def start_listening(self):
        """Start the pipe server thread"""
        self.running = True
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()
        print(f"[*] IPC Pipe Server listening on {self.pipe_name}")

    def _server_loop(self):
        """Main pipe server loop - waits for C++ alerts"""
        while self.running:
            try:
                # Create named pipe
                pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    0, None
                )

                # Wait for C++ to connect
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as e:
                    if e.args[0] == 109:  # ERROR_BROKEN_PIPE
                        pass

                # Read data from C++
                result, data = win32file.ReadFile(pipe, 4096)

                if result == 0:
                    message = data.decode("utf-8")
                    try:
                        # metadata = json.loads(message)
                        self.handle_alert(message) # for now not parsing just send the msg
                    except json.JSONDecodeError:
                        print(f"[!] Invalid JSON: {message}")

            except Exception as e:
                print(f"[!] Pipe Error: {e}")
            finally:
                try:
                    win32file.CloseHandle(pipe)
                except:
                    pass

    def handle_alert(self, msg):
        """
        Process an alert from C++ about a suspicious process
        """
        # pid = metadata.get("pid")
        # path = metadata.get("process_name", "<unknown>")
        # orig_ip = metadata.get("orig_ip", "0.0.0.0")
        # orig_port = metadata.get("orig_port", 0)
        #
        # # Get or create investigation context
        # if pid in self.investigations:
        #     ctx = self.investigations[pid]
        # else:
        path = msg.split('!')[1]
        ctx = InvestigationContext(0, path)

        #TO DO: checks for the sender and add the related data e.g the tls cert

        ctx.events.append(Event("PROCESS_FLAGGED"))
        #     self.investigations[pid] = ctx
        #     print(f"\n{'='*60}")
        #     print(f"[ALERT] New suspicious process detected")
        #     print(f"  PID: {pid}")
        #     print(f"  Path: {path}")
        #     print(f"{'='*60}")
        #
        # # Log network activity attempt
        # ctx.events.append(Event("NETWORK_ACTIVITY_ATTEMPT"))
        # # ctx.dest_ip = orig_ip
        # # ctx.dest_port = orig_port
        #
        # # Run full analysis (Static + Dynamic)
        confidence = self.analyzer.analyze_context(ctx)
        # verdict = self.analyzer.get_verdict(confidence)

        # Display results
        # self._print_analysis(ctx, confidence, verdict)

        # NOTE: C2 Emulation has been removed.
        # We no longer send fake responses to the malware.

        # Log to database
        # self._log_threat(ctx, confidence, verdict)

        # Check if we should recommend killing the process
        if confidence >= 85:
            print(f"\n[!] RECOMMENDATION: Terminate PID {pid} (High threat)")
            print(f"[!] C++ should call TerminateProcess() for PID {pid}")

    def _print_analysis(self, ctx: InvestigationContext, confidence: float, verdict: str):
        """Pretty-print the analysis results"""

        # Color coding
        if confidence >= 85:
            color = '\033[1;31m'  # Red
        elif confidence >= 60:
            color = '\033[1;33m'  # Yellow
        elif confidence >= 30:
            color = '\033[1;34m'  # Blue
        else:
            color = '\033[1;32m'  # Green

        reset = '\033[0m'

        print(f"\n{color}[VERDICT: {verdict}]{reset}")
        print(f"Confidence Score: {color}{confidence:.1f}%{reset}")
        print(f"Stage: {ctx.stage}")

        if ctx.findings:
            print(f"\nFindings ({len(ctx.findings)}):")
            for finding in ctx.findings:
                print(f"  • {finding}")

    def _log_threat(self, ctx: InvestigationContext, confidence: float, verdict: str):
        """Log threat to database"""
        threat_data = {
            'timestamp': datetime.now().isoformat(),
            'pid': ctx.pid,
            'process': ctx.process_path,
            'dest_ip': getattr(ctx, 'dest_ip', 'Unknown'),
            'dest_port': getattr(ctx, 'dest_port', 0),
            'protocol': 'BLOCKED',
            'confidence': confidence,
            'verdict': verdict,
            'findings': ctx.findings,
            'iocs': {},
            'config': {}
        }

        self.logger.log_traffic(threat_data, b'', b'')

    def get_summary(self) -> dict:
        """Get summary of all investigations"""
        summary = {
            'total_investigations': len(self.investigations),
            'malicious': 0,
            'suspicious': 0,
            'benign': 0
        }

        for ctx in self.investigations.values():
            verdict = self.analyzer.get_verdict(ctx.confidence)
            if verdict == "MALICIOUS":
                summary['malicious'] += 1
            elif verdict in ["SUSPICIOUS", "QUESTIONABLE"]:
                summary['suspicious'] += 1
            else:
                summary['benign'] += 1

        return summary
