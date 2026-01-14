import time
import win32pipe, win32file, pywintypes
from threading import Thread


def pipe_client_hooking():
    print("pipe client")
    quit = False

    while not quit:
        try:
            handle = win32file.CreateFile(
                r"\\.\pipe\hooking",
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            res = win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            if res == 0:
                print(f"SetNamedPipeHandleState return code: {res}")
            while True:
                resp = win32file.ReadFile(handle, 1024)
                print(f"message: {resp}")

        except pywintypes.error as e: #handling errors
            if e.args[0] == 2:
                print("no pipe, trying again in a sec")
                time.sleep(1)
            elif e.args[0] == 109:
                print("broken pipe, bye bye")
                quit = True


def pipe_client_signature_scanner():
    print("pipe client")
    quit = False

    while not quit:
        try:
            handle = win32file.CreateFile(
                r"\\.\pipe\signatureScanner",
                win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                0,
                None,
                win32file.OPEN_EXISTING,
                0,
                None
            )
            res = win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)
            if res == 0:
                print(f"SetNamedPipeHandleState return code: {res}")
            while True:
                resp = win32file.ReadFile(handle, 1024)
                print(f"message: {resp}")

        except pywintypes.error as e: #handling errors
            if e.args[0] == 2:
                print("no pipe, trying again in a sec")
                time.sleep(1)
            elif e.args[0] == 109:
                print("broken pipe, bye bye")
                quit = True


if __name__ == '__main__':
    # create the connection with hooking and signature scanner
    t1 = Thread(pipe_client_hooking())
    t2 = Thread(pipe_client_signature_scanner())
    t1.start()
    t2.start()



    else:
        print(f"no can do: {sys.argv[1]}")
