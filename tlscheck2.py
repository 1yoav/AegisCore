from scapy.all import *
from scapy.layers.tls.all import *
from cryptography import x509
from cryptography.hazmat.backends import default_backend

load_layer("tls")
# Optional: conf.tls_session_enable = True

collector = {}

def tlsCheck(data):
    try:
        start_idx = data.find(b"\x30\x82")
        if start_idx != -1:
            cert_len_bytes = data[start_idx + 2 : start_idx + 4]
            cert_len = struct.unpack("!H", cert_len_bytes)[0]
            total_size = cert_len + 4
            
            asn1_blob = data[start_idx : start_idx + total_size]
            cert = x509.load_der_x509_certificate(asn1_blob, default_backend())
            
            print(f"\n[+] SUCCESS: {cert.subject}")
            print(f"    Issuer: {cert.issuer}")
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
            if tlsCheck(collector[server_details]):
                del collector[server_details] # Clear buffer after success

    # Trigger on Change Cipher Spec (End of handshake)
    elif pkt.haslayer(TLS) and pkt[TLS].type == 20:
        if server_details in collector:
            tlsCheck(collector[server_details])
            del collector[server_details]

print("[*] Monitoring...")
sniff(filter="tcp port 443", prn=filtering, store=0)
