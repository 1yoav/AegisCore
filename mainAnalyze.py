import os
import time
import ctypes
import win32pipe, win32file, pywintypes
# import packingCheck  # וודא שהמודלים האלו קיימים אצלך
# import iatAnalyze

all_reports = []

def analyze_logic(fileName, report):
    """מבצע את הבדיקות הכבדות ומעדכן את הדו"ח הקיים"""
    print(f"[*] Analyzing: {fileName}")
    # כאן אתה קורא למודולים שלך
    if()
    report["packer_info"] = packingCheck.scan(fileName)
    report["iat_issues"] = iatAnalyze.analyze(fileName)
    # ... עדכון שאר השדות ...
    pass

def get_new_report(file_path):
    return {
        "file_path": file_path,
        "packer_info": {"name": "Unknown", "hasPacker": False, "is_detected": False},
        "suspicious_signature": False,
        "suspicious_tls": False,
        "yara_matches": False,
        "anomalies": False,
        "iat_issues": False,
        "threat_score": 0
    }

def get_or_create_report(file_path):
    normalized_path = os.path.abspath(file_path)

    # חיפוש דוח קיים
    report = next((r for r in all_reports if r["file_path"] == normalized_path), None)

    if report is None:
        report = get_new_report(normalized_path)
        all_reports.append(report)
        # ברגע שנוצר דוח חדש - מריצים ניתוח מעמיק
        analyze_logic(normalized_path, report)

    return report

def run_pipe_server():
    pipe_path = r'\\.\pipe\AegisCore'

    while True: # לולאה חיצונית לשמירה על השרת חי
        pipe = win32pipe.CreateNamedPipe(
            pipe_path,
            win32pipe.PIPE_ACCESS_DUPLEX,
            win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_READMODE_MESSAGE | win32pipe.PIPE_WAIT,
            1, 65536, 65536, 0, None
        )

        print(f"Server is listening on {pipe_path}...")

        try:
            win32pipe.ConnectNamedPipe(pipe, None)
            hr, data = win32file.ReadFile(pipe, 4096)

            message_raw = data.decode('utf-8').strip()
            parts = message_raw.split('!')

            if len(parts) < 2:
                continue

            sender = parts[0]
            file_path = parts[1]

            report = get_or_create_report(file_path)

            # עדכון לפי השולח
            if sender == "isolationForest":
                report["anomalies"] = True
            elif sender == "tlsCert":
                report["suspicious_tls"] = True
            elif sender == "signatureScanner":
                report["packer_info"]["is_detected"] = True
            elif sender == "signatureScanner": # שים לב שחזרת על השם פעמיים בקוד המקורי
                report["suspicious_signature"] = True
            else:
                ctypes.windll.user32.MessageBoxW(0, f"Unfamiliar sender: {sender}", "Aegis Alert", 48)

        except Exception as e:
            print(f"Comm Error: {e}")
        finally:
            win32pipe.DisconnectNamedPipe(pipe)
            win32file.CloseHandle(pipe)

if __name__ == '__main__':
    # packingCheck.extract()
    run_pipe_server()
