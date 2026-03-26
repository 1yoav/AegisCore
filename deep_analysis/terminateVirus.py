import tkinter as tk
from tkinter import font as tkfont
import sys
from pathlib import Path
import psutil
import time
import os

def terminate_and_delete(file_path):
    target_path = os.path.normpath(file_path).lower()
    print(f"[*] Starting remediation for: {target_path}")

    killed_count = 0
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            if proc.info['exe'] and os.path.normpath(proc.info['exe']).lower() == target_path:
                print(f"[!] Killing process {proc.info['pid']}...")
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill()
                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    print(f"[*] Terminated {killed_count} process(es).")

    if os.path.exists(file_path):
        try:
            time.sleep(1)
            os.remove(file_path)
            print(f"Successfully deleted the file: {file_path}")
            return True
        except Exception as e:
            print(f"Error deleting file: {e}")
            return False
    else:
        print("File already gone or path not found.")
        return True

# --- לוגיקת ה-UI (ללא שינוי בעיצוב) ---
def show_custom_alert(path):
    icon_name = ""
    if getattr(sys, 'frozen', False):
        icon_name = Path(sys.executable).parent.parent / "AegisCore.ico"
    else:
        icon_name = Path(__file__).resolve().parent / "AegisCore.ico"

    root = tk.Tk()
    root.title("AegisCore AV - Threat Detected")

    current_dir = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(current_dir, icon_name)

    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except:
            pass

    root.attributes("-topmost", True)
    root.geometry("550x280")
    root.configure(bg="#1a1a1a")

    title_font = tkfont.Font(family="Segoe UI", size=18, weight="bold")
    body_font = tkfont.Font(family="Segoe UI", size=11)
    btn_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")

    header = tk.Label(root, text="⚠️ CRITICAL THREAT DETECTED", font=title_font,
                      bg="#1a1a1a", fg="#ff4444", pady=20)
    header.pack()

    info_text = f"The following suspicious process was identified:\n\n{path}"
    info = tk.Label(root, text=info_text, font=body_font,
                    bg="#1a1a1a", fg="#ffffff", wraplength=500, justify="center")
    info.pack(pady=10)

    btn_frame = tk.Frame(root, bg="#1a1a1a")
    btn_frame.pack(pady=25)

    def on_kill():
        print("[DEBUG] 'TERMINATE' button clicked.")
        success = terminate_and_delete(path)
        root.destroy()

    def on_ignore():
        print("[DEBUG] 'IGNORE' button clicked.")
        root.destroy()

    kill_btn = tk.Button(btn_frame, text="TERMINATE PROCESS", command=on_kill,
                         bg="#cc0000", fg="white", font=btn_font,
                         width=20, pady=10, relief="flat", cursor="hand2")
    kill_btn.pack(side="left", padx=15)

    ignore_btn = tk.Button(btn_frame, text="IGNORE (RISKY)", command=on_ignore,
                           bg="#444444", fg="#aaaaaa", font=btn_font,
                           width=15, pady=10, relief="flat", cursor="hand2")
    ignore_btn.pack(side="left", padx=15)

    root.mainloop()

# --- נקודת הכניסה החדשה ---
if __name__ == "__main__":
    # בדיקה האם הועבר נתיב כפרמטר (sys.argv[1])
    if len(sys.argv) > 1:
        suspicious_path = sys.argv[1]
    show_custom_alert(suspicious_path)
