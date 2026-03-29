import tkinter as tk
from tkinter import font as tkfont
import psutil
import time
import os

def terminate_and_delete(file_path):
    """
    Kills all processes associated with the file_path and then deletes the file.
    """
    # 1. נרמול הנתיב כדי למנוע בעיות של סלאשים הפוכים או אותיות גדולות/קטנות
    target_path = os.path.normpath(file_path).lower()

    print(f"[*] Starting remediation for: {target_path}")

    # 2. איתור והריגת כל התהליכים הקשורים לקובץ
    killed_count = 0
    for proc in psutil.process_iter(['pid', 'exe']):
        try:
            # בודקים אם לתהליך יש נתיב הרצה והאם הוא תואם ליעד שלנו
            if proc.info['exe'] and os.path.normpath(proc.info['exe']).lower() == target_path:
                print(f"[!] Killing process {proc.info['pid']}...")
                proc.terminate() # ניסיון סגירה עדין

                # מחכים רגע ומוודאים שהתהליך נסגר, אם לא - הורגים בכוח
                try:
                    proc.wait(timeout=3)
                except psutil.TimeoutExpired:
                    proc.kill() # סגירה כוחנית (SIGKILL)

                killed_count += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    print(f"[*] Terminated {killed_count} process(es).")

    # 3. מחיקת הקובץ מהדיסק
    if os.path.exists(file_path):
        try:
            # לפעמים לוקח למערכת ההפעלה רגע לשחרר את הקובץ אחרי שהתהליך נהרג
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







def show_custom_alert(path):
    root = tk.Tk()
    icon_name="AegisCore.ico"
    root.title("AegisCore AV - Threat Detected")
    
    # Get the directory of the current script to find the icon
    current_dir = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(current_dir, icon_name)

    # 1. Change the window icon (must be a .ico file)
    if os.path.exists(icon_path):
        try:
            root.iconbitmap(icon_path)
        except:
            pass 

    # Keep window on top of everything
    root.attributes("-topmost", True)
    
    # Window size and styling
    root.geometry("550x280")
    root.configure(bg="#1a1a1a") # Darker, more modern background

    # 2. Define Large Fonts
    title_font = tkfont.Font(family="Segoe UI", size=18, weight="bold")
    body_font = tkfont.Font(family="Segoe UI", size=11)
    btn_font = tkfont.Font(family="Segoe UI", size=10, weight="bold")

    # Header section
    header = tk.Label(root, text="⚠️ CRITICAL THREAT DETECTED", font=title_font, 
                      bg="#1a1a1a", fg="#ff4444", pady=20)
    header.pack()

    # Information section
    info_text = f"The following suspicious process was identified:\n\n{path}"
    info = tk.Label(root, text=info_text, font=body_font, 
                    bg="#1a1a1a", fg="#ffffff", wraplength=500, justify="center")
    info.pack(pady=10)

    # Buttons Container
    btn_frame = tk.Frame(root, bg="#1a1a1a")
    btn_frame.pack(pady=25)

    def on_kill():
        print("[DEBUG] 'TERMINATE' button clicked.") # בדיקה שהכפתור עובד

        # קריאה לפונקציית ההריגה והמחיקה שבנינו
        success = terminate_and_delete(path)

        if success:
            print(f"[DEBUG] Cleanup finished for {path}")
        else:
            print(f"[DEBUG] Cleanup failed for {path}")

        root.destroy() # סגירת חלון ההתראה
        terminate_and_delete(path)

    def on_ignore():
        print("[DEBUG] 'IGNORE' button clicked. No action taken.") # בדיקה שהכפתור עובד
        root.destroy()

    # Action Buttons
    kill_btn = tk.Button(btn_frame, text="TERMINATE PROCESS", command=on_kill,
                         bg="#cc0000", fg="white", font=btn_font, 
                         width=20, pady=10, relief="flat", cursor="hand2")
    kill_btn.pack(side="left", padx=15)

    ignore_btn = tk.Button(btn_frame, text="IGNORE (RISKY)", command=on_ignore, 
                           bg="#444444", fg="#aaaaaa", font=btn_font, 
                           width=15, pady=10, relief="flat", cursor="hand2")
    ignore_btn.pack(side="left", padx=15)

    root.mainloop()

