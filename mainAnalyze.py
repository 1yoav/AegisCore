import time
import win32pipe, win32file, pywintypes
from threading import Thread


hooking_data = {}

def pipe_client_hooking():
    pipe_path = r"\\.\\pipe\\hooking"
    quit = False

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

    while quit == False:
        win32pipe.ConnectNamedPipe(pipe, None)
        res = (win32file.ReadFile(pipe, 200))

        # just to see if working, in real case need to start action
        print(res)
        win32pipe.DisconnectNamedPipe(pipe)



def pipe_client_signature_scanner():
    pipe_path = "\\.\\pipe\\signatureScanner"
    quit = False

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
    win32pipe.ConnectNamedPipe(pipe, None)

    while quit == False:
        res = (win32file.ReadFile(pipe, 200)).decode()

        # just to see if working, in real case need to start action
        print(res)


if __name__ == '__main__':
    # create the connection with hooking and signature scanner
    t1 = Thread(pipe_client_hooking())
    t2 = Thread(pipe_client_signature_scanner())
    t1.start()
    t2.start()



