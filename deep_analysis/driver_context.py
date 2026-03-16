"""
Driver Context - Handles C++ alerts and manages investigations
Updated: Removed C2 Emulator interactions
"""
import terminateVirus
import threading
import json
import psutil
import win32pipe
import win32file
import pywintypes
import dataBase
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
        self.investigations: Dict[str, InvestigationContext] = {}

        # Core components
        self.analyzer = Analyzer()
        # self.emulator = C2Emulator() <-- REMOVED
        self.logger = ThreatLogger(DATABASE_PATH)


    def get_pids_by_filename(self,filename):
        pids = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                if proc.info['name'] and proc.info['name'].lower() == filename.lower():
                    pids.append(proc.info['pid'])
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        # maybe for later return more then one pid for deeper invistigate
        if pids:
            return pids[0]
        return 0

    def start_listening(self):
        """Start the pipe server thread"""
        self.running = True
        self._server_loop()

    def _server_loop(self):
        """Main pipe server loop - spawns threads for each client"""
        while self.running:
            try:
                # 1. Create the pipe instance
                pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    win32pipe.PIPE_UNLIMITED_INSTANCES, # Support multiple concurrent clients
                    65536, 65536, 0, None
                )

                # 2. Wait for a client to connect
                win32pipe.ConnectNamedPipe(pipe, None)

                # 3. Start a new thread to handle this specific client
                # This allows the loop to immediately return to CreateNamedPipe for the next client
                client_thread = threading.Thread(
                    target=self._handle_client_connection,
                    args=(pipe,)
                )
                client_thread.daemon = True
                client_thread.start()

            except Exception as e:
                if self.running:
                    print(f"[!] Pipe Server Error: {e}")

    def _handle_client_connection(self, pipe):
        """Worker thread to read data from a single client"""
        full_data = b""

        try:
            while True:
                # Read chunks until the message is complete
                hr, data = win32file.ReadFile(pipe, 4096)
                full_data += data
                if hr == 0:  # Success: full message received
                    break

        except Exception as e:
            win32file.CloseHandle(pipe)
            print(f"[!] Error handling client: {e}")

        if full_data:              # if the data isnt NULL, activate the investigation
            message = full_data.decode("utf-8")
            self.handle_alert(message)
            win32file.CloseHandle(pipe)



    def handle_alert(self, msg):
        """
        Process an alert from C++ about a suspicious process
        """
        # pid = metadata.get("pid")
        # path = metadata.get("process_name", "<unknown>")
        # orig_ip = metadata.get("orig_ip", "0.0.0.0")
        # orig_port = metadata.get("orig_port", 0)

        # # Get or create investigation context

        # else:
        msg = msg.split("!")
        path = msg[1]
        pid = self.get_pids_by_filename(path) # maybe in the future active analyze about all the pids

        ctx = InvestigationContext(pid, path)

        if path in self.investigations:  # if the investigate in process already
            ctx = self.investigations[path]

        # if the pids empty the sender might be signature scanner and there is no procces running just filepath


        # TO DO: checks for the sender and add the related data e.g the tls cert

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
        # check who send the msg
        if msg[0] == "tlsCert":
            ctx.tlsCheck = True
            print("the deep analyze got tlsCert!\n")
        if msg[0] == "signatureScanner":
            print("the deep analyze got signature scan!\n")
            ctx.signatureScan = True
        if msg[0] == "isolationForest":
            print("the deep analyze got isolationForest!\n")
            ctx.isolationForest = True

        confidence = self.analyzer.analyze_context(ctx)  # make the deepAnalyze
        # verdict = self.analyzer.get_verdict(confidence)

        # Display results
        # self._print_analysis(ctx, confidence, verdict)

        # NOTE: C2 Emulation has been removed.
        # We no longer send fake responses to the malware.

        # Log to database
        # self._log_threat(ctx, confidence, verdict)

        # Check if we should recommend killing the process
        dataBase.insert_threat(confidence, path, "".join(ctx.findings) , ctx.first_seen)
        if confidence >= 70:
            print(f"\n[!] RECOMMENDATION: Terminate PID {pid} (High threat)")
            print(f"[!] C++ should call TerminateProcess() for PID {pid}")
            terminateVirus.show_custom_alert(path)


        self.investigations[path] = ctx  # update the invistigate



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
