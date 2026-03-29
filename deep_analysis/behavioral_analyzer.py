import ctypes
from ctypes import wintypes
import psutil
from typing import Tuple, List

# Windows API Setup
user32 = ctypes.windll.user32

class BehavioralAnalyzer:
    """Analyzes live process behavior: GUI handles and Process Heritage"""

    EXPECTED_GUI_PROCS = ["chrome.exe", "msedge.exe", "notepad.exe", "calc.exe", "explorer.exe", "winword.exe"]
    
    EXPECTED_PARENTS = {
        "services.exe": "wininit.exe",
        "lsass.exe": "wininit.exe",
        "svchost.exe": "services.exe",
        "winlogon.exe": "smss.exe",
        "explorer.exe": "userinit.exe",
        "runtimebroker.exe": "svchost.exe"
    }


    def analyze_running_process(self, pid: int) -> Tuple[float, List[str]]:
        """Perform live checks on PID. Returns (score, findings)"""
        score = 0.0
        findings = []

        proc = psutil.Process(pid)
        name = proc.name().lower()

        # --- 1. Heritage Check ---
        parent_proc = proc.parent()
        parent_name = parent_proc.name().lower() if parent_proc else "orphaned/none"

        if name in self.EXPECTED_PARENTS:
            expected = self.EXPECTED_PARENTS[name]
            if parent_name != expected:
                score += 25.0
                findings.append(f"[BEHAVIOR] Heritage Mismatch: {name} spawned by {parent_name} (Expected: {expected})\n")
        elif parent_name == "orphaned/none":
            # Standard for some, suspicious for unsigned user apps
            score += 5.0
            findings.append(f"[BEHAVIOR] Process is orphaned (no parent)\n")

        # --- 2. GUI Check ---
        is_visible, is_hidden = self._get_window_stats(pid)

        if name in self.EXPECTED_GUI_PROCS and not is_visible:
            score += 20.0
            findings.append(f"[BEHAVIOR] Suspicious Headless State: {name} has no visible GUI\n")

        if is_hidden and not is_visible:
            score += 10.0
            findings.append("[BEHAVIOR] Hidden window handles detected (Potential listener/hook)\n")

        if not is_visible and not is_hidden:
            # Useful context, but not necessarily a penalty unless name mismatch
            findings.append("[BEHAVIOR] Background process (No window handles)\n")


        return min(score, 45.0), findings

    def _get_window_stats(self, pid: int) -> Tuple[bool, bool]:
        """Internal helper to check HWNDs"""
        results = {"v": False, "h": False}
        
        def enum_windows_proc(hwnd, lParam):
            window_pid = wintypes.DWORD()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(window_pid))
            if window_pid.value == pid:
                if user32.IsWindowVisible(hwnd):
                    results["v"] = True
                else:
                    results["h"] = True
            return True

        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)
        user32.EnumWindows(WNDENUMPROC(enum_windows_proc), 0)
        return results["v"], results["h"]
