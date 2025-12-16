"""
IPC Communication with C++ WFP Driver
Uses Named Pipes to get process metadata
"""

import json
import time
from typing import Tuple, Optional

# Platform-specific imports
try:
    import win32pipe
    import win32file
    import pywintypes
    WINDOWS_IPC = True
except ImportError:
    WINDOWS_IPC = False
    print("[!] WARNING: pywin32 not installed. Using mock IPC.")

from config import DRIVER_PIPE_NAME

class DriverContext:
    """Communicates with C++ WFP driver via Named Pipe"""
    
    def __init__(self):
        self.pipe_name = DRIVER_PIPE_NAME
        self.mock_mode = not WINDOWS_IPC
        
        if self.mock_mode:
            print(f"[*] Running in MOCK mode (no C++ driver connection)")
    
    def get_process_metadata(self, source_port: int) -> Tuple[int, str, str, int]:
        """
        Query C++ driver for process metadata
        Returns: (pid, process_name, original_dest_ip, original_dest_port)
        """
        if self.mock_mode:
            return self._get_mock_metadata(source_port)
        
        try:
            # Open the pipe
            handle = win32file.CreateFile(
                self.pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            
            # Send query
            query = json.dumps({
                "action": "get_metadata",
                "source_port": source_port
            })
            
            win32file.WriteFile(handle, query.encode('utf-8'))
            
            # Receive response
            result = win32file.ReadFile(handle, 4096)
            response_data = result[1].decode('utf-8')
            
            win32file.CloseHandle(handle)
            
            # Parse response
            metadata = json.loads(response_data)
            
            return (
                metadata.get('pid', 0),
                metadata.get('process_name', 'unknown.exe'),
                metadata.get('original_dest_ip', '0.0.0.0'),
                metadata.get('original_dest_port', 0)
            )
            
        except pywintypes.error as e:
            print(f"[!] Pipe error: {e}. Falling back to mock data.")
            return self._get_mock_metadata(source_port)
        except Exception as e:
            print(f"[!] IPC error: {e}")
            return self._get_mock_metadata(source_port)
    
    def _get_mock_metadata(self, source_port: int) -> Tuple[int, str, str, int]:
        """
        Mock data for testing without C++ driver
        In production, this would never be called
        """
        # Simulate different malware samples
        mock_samples = [
            (1234, "updater.exe", "185.220.101.50", 443),    # Suspicious updater
            (5678, "svchost.exe", "172.67.14.99", 8080),     # Fake svchost
            (9999, "chrome.exe", "104.21.50.222", 443),      # Legitimate chrome
            (4444, "payload.exe", "192.0.78.24", 4444),      # Obvious malware
        ]
        
        # Rotate through samples based on port
        idx = (source_port % len(mock_samples))
        return mock_samples[idx]
    
    def send_kill_command(self, pid: int) -> bool:
        """
        Tell C++ driver to terminate a process
        Returns: True if successful
        """
        if self.mock_mode:
            print(f"[MOCK] Would kill PID {pid}")
            return True
        
        try:
            handle = win32file.CreateFile(
                self.pipe_name,
                win32file.GENERIC_WRITE,
                0, None,
                win32file.OPEN_EXISTING,
                0, None
            )
            
            command = json.dumps({
                "action": "kill_process",
                "pid": pid
            })
            
            win32file.WriteFile(handle, command.encode('utf-8'))
            win32file.CloseHandle(handle)
            
            print(f"[*] Sent kill command for PID {pid}")
            return True
            
        except Exception as e:
            print(f"[!] Failed to send kill command: {e}")
            return False
