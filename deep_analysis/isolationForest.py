import os
import win32pipe
import win32file
from pathlib import Path
import joblib
from sklearn.ensemble import IsolationForest
import warnings
import threading
import time
import pandas as pd

warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names"
)

import sys, os
BASE_DIR = os.path.dirname(sys.executable if getattr(sys, 'frozen', False) else os.path.abspath(__file__))
# Navigate up from deep_analysis\dist\ to AegisCore root, then to the data folders
INSTALL_ROOT = os.path.normpath(os.path.join(BASE_DIR, '..', '..'))
CSV_ADDRESS = os.path.join(INSTALL_ROOT, 'MainProcces', 'programs_data_csv') + os.sep
PKL_ADDRESS = os.path.join(BASE_DIR, 'isolationForest_pkl') + os.sep

def training():
    currentDir = Path(
        "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\MainProcces\\programs_data_csv\\"
    )
    csv_files = currentDir.rglob("*.csv")

    for f in csv_files:
        data = pd.read_csv(f)

        model = IsolationForest(
            n_estimators=100,
            max_samples="auto",
            contamination="auto",
            random_state=42
        )

        model.fit(data)
        joblib.dump(model,  "isolationForest_pkl/" + f.stem + ".pkl")



import win32file
import win32pipe
import winerror
import pywintypes

def send_to_pipe(msg):
    pipe_name = r"\\.\pipe\AVDeepScanPipe" # Use 'r' for raw string

    # 1. Add a null-terminator if your C++ or Python logic expects C-strings
    # This prevents 'garbage' characters at the end of the message
    full_msg = msg.encode('utf-8')
    handle = None
    while True:
        try:
            # ניסיון פתיחת ה-Pipe
            handle = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            break

        except win32file.error as e:
            # בודק אם השגיאה היא שהקובץ/Pipe לא נמצא (Error 2)
            if e.winerror == winerror.ERROR_FILE_NOT_FOUND:
                time.sleep(0.5)
                continue
            else:
                # שגיאה אחרת (למשל הרשאות) - כדאי לעצור ולבדוק
                print(f"Unexpected error: {e}")
                break
        # 4. Write the data
    result = win32file.WriteFile(handle, full_msg)
    win32file.CloseHandle(handle)




def predict():


    pipe = win32pipe.CreateNamedPipe(
        r'\\.\pipe\isolationForest' ,
        win32pipe.PIPE_ACCESS_DUPLEX,
        win32pipe.PIPE_TYPE_MESSAGE
        | win32pipe.PIPE_READMODE_MESSAGE
        | win32pipe.PIPE_WAIT,
        1,
        65536,
        65536,
        0,
        None
    )

    try:
        win32pipe.ConnectNamedPipe(pipe, None)

        while True:
            res = win32file.ReadFile(pipe, 200)
            msg = res[1].decode("utf-8")

            newMsg = msg.split(",")
            fileName = PKL_ADDRESS + newMsg[0]

            my_file = Path(fileName)
            if(my_file.exists()):
                model = joblib.load(fileName)
                newMsg.remove(newMsg[0])


                data = list(map(int, newMsg))
                score = model.decision_function([data])
                if score[0] < -0.3: # value of suspicious
                    msg = "isolationForest!" + fileName
                    # send msg to deepAnalyze
                    t = threading.Thread(target=send_to_pipe, args=(msg,))
                    t.start()

            # else:
            #     print(fileName , " ", "not exsist")
    except Exception as e:
        win32pipe.DisconnectNamedPipe(pipe)
        print("error occur:", e)


def main():
    #training()
    predict()


if __name__ == "__main__":
    print("[Init] Initializing isolationForest...")
    main()

