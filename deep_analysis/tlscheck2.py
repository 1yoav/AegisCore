from scapy.all import *
from scapy.layers.tls.all import *
from cryptography import x509
import win32pipe, win32file, pywintypes
import psutil

from cryptography.hazmat.backends import default_backend
import datetime

load_layer("tls")
# Optional: conf.tls_session_enable = True

collector = {}

def sendMsg(msg):
    pipe_name = r'\\.\pipe\AVDeepScanPipe'

    # print(f"Connecting to pipe: {pipe_name}")

    try:
        # Connect to the named pipe
        handle = win32file.CreateFile(
            pipe_name,
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None
        )

        # Set the pipe mode to message mode
        res = win32pipe.SetNamedPipeHandleState(handle, win32pipe.PIPE_READMODE_MESSAGE, None, None)

        # 1. Send message to Server
        win32file.WriteFile(handle, str.encode(msg))

        # 2. Receive response from Server
        response_data = win32file.ReadFile(handle, 4096)

        # Close the handle
        win32file.CloseHandle(handle)

    except pywintypes.error as e:
        if e.args[0] == 2:  # ERROR_FILE_NOT_FOUND
            time.sleep(1)
        elif e.args[0] == 231:  # ERROR_PIPE_BUSY
            win32pipe.WaitNamedPipe(pipe_name, 5000)

def get_process_path_from_port(port):
    """Finds the file path of the process using a specific local port."""
    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                # Get the process object
                proc = psutil.Process(conn.pid)
                return proc.exe() # This returns the full path
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None
    return None

def tlsCheck(data , port):
    try:
        # extract the cert
        start_idx = data.find(b"\x30\x82")
        if start_idx != -1:
            cert_len_bytes = data[start_idx + 2 : start_idx + 4]
            cert_len = struct.unpack("!H", cert_len_bytes)[0]
            total_size = cert_len + 4
            
            asn1_blob = data[start_idx : start_idx + total_size]
            cert = x509.load_der_x509_certificate(asn1_blob, default_backend())
            
            # check the cert
            # date check
            if cert.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc) or cert.issuer == cert.subject:
                sendMsg("tlsCheck!" + get_process_path_from_port(port))

            # to do: add database for suspicious certs

            return True
    except Exception as e:
        pass
    return False

def filtering(pkt):
    if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
        return

    # Create a unique key for this specific TCP stream
    # Important: From Server to Client
    server_details = (pkt[IP].src, pkt[IP].dst, pkt[TCP].sport, pkt[TCP].dport)

    if pkt.haslayer(TLS) and pkt[TLS].type == 22:
        # If it's a handshake packet, try to get the payload
        payload = b""
        if pkt.haslayer(Padding):
            payload = pkt[Padding].load
        elif pkt.haslayer(Raw):
            payload = pkt[Raw].load

        if payload:
            if server_details not in collector:
                collector[server_details] = b""
            
            collector[server_details] += payload
            
            # Try to parse immediately in case it's not fragmented
            if tlsCheck(collector[server_details] , server_details[3]):
                del collector[server_details] # Clear buffer after success

    # Trigger on Change Cipher Spec (End of handshake)
    elif pkt.haslayer(TLS) and pkt[TLS].type == 20:
        if server_details in collector:
            tlsCheck(collector[server_details])
            del collector[server_details]


if __name__ == '__main__':
    print("[Init] Initializing tlsCert check...\n")
    sniff(filter="tcp port 443", prn=filtering, store=0)
