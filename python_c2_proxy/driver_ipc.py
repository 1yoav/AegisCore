"""
IPC Communication: Python Pipe Server
Listens for alerts sent by the C++ WFP Engine
"""
import win32pipe
import win32file
import pywintypes
import threading
import json
from typing import Callable
from config import DRIVER_PIPE_NAME

class DriverContext:
    def __init__(self):
        self.pipe_name = DRIVER_PIPE_NAME
        self.running = False

    def start_listening(self, alert_callback: Callable):
        """
        Starts the pipe server thread.
        alert_callback: Function to call when C++ sends data.
        """
        self.running = True
        t = threading.Thread(target=self._server_loop, args=(alert_callback,), daemon=True)
        t.start()
        print(f"[*] IPC Pipe Server listening on {self.pipe_name}")

    def _server_loop(self, callback):
        while self.running:
            try:
                # 1. Create the Named Pipe (Wait for C++ to connect)
                pipe = win32pipe.CreateNamedPipe(
                    self.pipe_name,
                    win32pipe.PIPE_ACCESS_INBOUND, # Read-only for Python
                    win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
                    1, 65536, 65536,
                    0, None
                )

                # 2. Block until C++ connects
                # This will hang here until your C++ code calls CreateFileA
                try:
                    win32pipe.ConnectNamedPipe(pipe, None)
                except pywintypes.error as e:
                    if e.args[0] == 109: # ERROR_BROKEN_PIPE
                        pass

                # 3. Read the Data
                result, data = win32file.ReadFile(pipe, 4096)

                if result == 0:
                    message = data.decode('utf-8')
                    try:
                        metadata = json.loads(message)
                        # Pass the dictionary to main.py
                        callback(metadata)
                    except json.JSONDecodeError:
                        print(f"[!] Invalid JSON received: {message}")

            except Exception as e:
                print(f"[!] Pipe Server Error: {e}")
            finally:
                try:
                    # Clean up the pipe instance so C++ can connect again
                    win32file.CloseHandle(pipe)
                except:
                    pass
