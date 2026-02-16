import os
import win32pipe
import win32file
from pathlib import Path
import joblib
from sklearn.ensemble import IsolationForest
import warnings
import pandas as pd

warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names"
)

csv_dir = "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\MainProcces\\"
pipe_path = "\\\\.\\pipe\\AVDeepScanPipe"


def training():
    currentDir = Path(
        "C:\\Users\\Cyber_User\\Desktop\\magshimim\\aegiscore-av\\MainProcces"
    )
    csv_files = currentDir.rglob("*.csv")

    for f in csv_files:
        print(f)
        data = pd.read_csv(f)

        model = IsolationForest(
            n_estimators=100,
            max_samples="auto",
            contamination="auto",
            random_state=42
        )

        model.fit(data)
        print(f.stem + ".pkl")
        joblib.dump(model, f.stem + ".pkl")



def send_msg_to_deepAnalyze(msg):
    pipe_name = r'\\.\pipe\AegisCore'

    while True:
        try:
            win32pipe.WaitNamedPipe(pipe_name, 5000)

            handle = win32file.CreateFile(
                pipe_name,
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )

            win32file.WriteFile(handle, msg.encode(), None)
            win32file.CloseHandle(handle)
            break

        except pywintypes.error as e:
            print(f"Waiting for pipe {pipe_name}... (Error: {e.strerror})")
            time.sleep(1)




def predict():


    pipe = win32pipe.CreateNamedPipe(
        pipe_path,
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
            fileName = newMsg[0]

            my_file = Path(fileName)
            if(my_file.exists()):
                model = joblib.load(fileName)
                newMsg.remove(newMsg[0])


                data = list(map(int, newMsg))
                score = model.decision_function([data])
                if score[0] < -0.3: # value of suspicious
                    msg = "isolationForest!" + fileName + '!'
                    send_msg_to_deepAnalyze(msg)
                    # send msg to deepAnalyze


            else:
                print(fileName , " ", "not exsist")
    except Exception as e:
        win32pipe.DisconnectNamedPipe(pipe)
        print("error occur:", e)


def main():
    #training()
    predict()


if __name__ == "__main__":
    main()
    #input("Press Enter to exit...")

