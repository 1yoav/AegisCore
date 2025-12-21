import threading
import json
import win32pipe
import win32file
import pywintypes
from typing import Dict
from events import Event, InvestigationContext
from analyzer import Analyzer
from c2_emulator import C2Emulator

DRIVER_PIPE_NAME = r"\\.\pipe\AVDeepScanPipe"

# ---- Pipe Server ----
class DriverContext:
    def __init__(self):
        self.pipe_name = DRIVER_PIPE_NAME
        self.running = False
        self.investigations: Dict[int, InvestigationContext] = {}
        self.analyzer = Analyzer()
        self.emulator = C2Emulator()

    def start_listening(self):
        self.running = True
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()
        print(f"[*] IPC Pipe Server listening on {self.pipe_name}")

    def _server_loop(self):
        while self.running:
            try:
                pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND,
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    0, None
                )
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as e:
                    if e.args[0] == 109:
                        pass

                result, data = win32file.ReadFile(pipe, 4096)
                if result == 0:
                    message = data.decode("utf-8")
                    try:
                        metadata = json.loads(message)
                        self.handle_alert(metadata)
                    except json.JSONDecodeError:
                        print(f"[!] Invalid JSON: {message}")
            except Exception as e:
                print(f"[!] Pipe Error: {e}")
            finally:
                try:
                    win32file.CloseHandle(pipe)
                except:
                    pass

    def handle_alert(self, metadata):
        pid = metadata.get("pid")
        path = metadata.get("process_name", "<unknown>")
        if pid in self.investigations:
            ctx = self.investigations[pid]
        else:
            ctx = InvestigationContext(pid, path)
            ctx.events.append(Event("PROCESS_FLAGGED"))
            self.investigations[pid] = ctx
            print(f"[ALERT] New process flagged: PID {pid}, Path {path}")

        # Example: simulate that process tried network activity
        ctx.events.append(Event("NETWORK_ACTIVITY_ATTEMPT"))

        # Run analyzer
        confidence = self.analyzer.analyze_context(ctx)
        print(f"[ANALYZER] PID {pid} confidence: {confidence}%")

        # Run emulator reaction
        self.emulator.generate_response(ctx)
