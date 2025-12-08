import socket
import threading
import time
import statistics
import json
from datetime import datetime

# ==========================================
# CONFIGURATION & THRESHOLDS
# ==========================================
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 8080

# Scoring Weights (Total should ideally be ~1.0 or 100)
WEIGHT_BEACONING = 0.50  # 50% Confidence if beaconing is detected
WEIGHT_USER_AGENT = 0.25 # 25% Confidence for bad User-Agents
WEIGHT_PROTOCOL = 0.15   # 15% Confidence for weird protocols
WEIGHT_FREQ = 0.10       # 10% Confidence for high frequency

# Beaconing Settings
BEACON_VARIANCE_THRESHOLD = 5.0 # Seconds (Standard Deviation allowed)
MIN_CONNECTIONS_FOR_BEACON = 3  # Need 3 hits to calculate a pattern

# ==========================================
# MOCKED C++ DRIVER METADATA
#In a real app, this comes from your WFP driver via Pipe/SharedMem
# ==========================================
class DriverContext:
    @staticmethod
    def get_process_metadata(source_port):
        """
        Simulates querying the C++ driver: 'Who owns source port X?'
        Returns: (PID, ProcessName, Original_Dest_IP)
        """
        # MOCK DATA: Simulating a suspicious malware process
        return (9452, "updater.exe", "172.67.14.99")

# ==========================================
# CORE LOGIC CLASSES
# ==========================================

class SessionManager:
    """Tracks connection history per Process ID to detect patterns."""
    def __init__(self):
        # Dictionary: { pid: [timestamp1, timestamp2, ...] }
        self.history = {}

    def log_connection(self, pid):
        if pid not in self.history:
            self.history[pid] = []
        self.history[pid].append(time.time())

    def check_beaconing(self, pid):
        """
        Calculates time deltas between connections.
        Low variance (std_dev) = High probability of automated beaconing.
        """
        timestamps = self.history.get(pid, [])
        if len(timestamps) < MIN_CONNECTIONS_FOR_BEACON:
            return 0.0, "Insufficient Data"

        # Calculate intervals: [t2-t1, t3-t2, ...]
        intervals = [t - s for s, t in zip(timestamps, timestamps[1:])]
        
        if not intervals:
            return 0.0, "No Intervals"

        avg_interval = statistics.mean(intervals)
        try:
            std_dev = statistics.stdev(intervals)
        except:
            std_dev = 0.0 # Perfectly constant

        # Logic: If variance is low (e.g. < 5s jitter), it's automated.
        if std_dev < BEACON_VARIANCE_THRESHOLD:
            # We found a pattern!
            return 1.0, f"Detected Periodic Beacon (~{avg_interval:.1f}s gap)"
        
        return 0.0, f"Random Activity (Var: {std_dev:.1f}s)"

class Analyzer:
    """The 'Brain' that generates the Confidence Score."""
    
    def __init__(self):
        self.sessions = SessionManager()
        self.known_bad_uas = ["python", "curl", "wget", "powershell", "winhttp"]

    def analyze(self, pid, proc_name, raw_data):
        score = 0.0
        findings = []

        # 1. Decode Data (Safe Decode)
        try:
            decoded = raw_data.decode('utf-8', errors='ignore')
        except:
            decoded = ""

        # --- CHECK 1: Protocol & User-Agent Analysis ---
        is_http = "GET " in decoded or "POST " in decoded
        user_agent = "Unknown"
        
        if is_http:
            # Extract User-Agent roughly
            for line in decoded.split('\r\n'):
                if "User-Agent:" in line:
                    user_agent = line.split("User-Agent:")[1].strip()
            
            # Check against suspicious list
            if any(bad in user_agent.lower() for bad in self.known_bad_uas):
                score += WEIGHT_USER_AGENT
                findings.append(f"Suspicious User-Agent: {user_agent}")
            elif user_agent == "Unknown":
                # HTTP with NO User-Agent is also suspicious
                score += WEIGHT_USER_AGENT
                findings.append("Missing User-Agent")
        else:
            # Non-HTTP (Unknown Binary) is inherently suspicious in this context
            score += WEIGHT_PROTOCOL
            findings.append("Unknown/Binary Protocol Detected")

        # --- CHECK 2: Beaconing Analysis ---
        # Log this hit and calculate time patterns
        self.sessions.log_connection(pid)
        beacon_conf, beacon_msg = self.sessions.check_beaconing(pid)
        
        if beacon_conf > 0.0:
            score += WEIGHT_BEACONING
            findings.append(beacon_msg)

        # --- CHECK 3: Heuristics (Process Name) ---
        # Example: 'updater.exe' running from Temp (simulated check)
        if "updater" in proc_name.lower(): 
            score += 0.05
            findings.append("Suspicious Process Name")

        return min(score, 1.0), findings

# ==========================================
# SERVER IMPLEMENTATION
# ==========================================

def handle_client(conn, addr, analyzer):
    """Handles a single redirected connection."""
    
    # 1. Get Metadata (Simulating WFP Integration)
    # In reality, you match addr[1] (source port) to your driver's list
    pid, proc_name, orig_ip = DriverContext.get_process_metadata(addr[1])
    
    print(f"\n[+] REDIRECTED: {proc_name} (PID: {pid}) -> Intended for {orig_ip}")
    
    try:
        # 2. Receive the 'Beacon' (First packet)
        raw_data = conn.recv(4096)
        if not raw_data:
            return

        # 3. Analyze & Score
        confidence, findings = analyzer.analyze(pid, proc_name, raw_data)
        
        # 4. Log Verdict
        verdict = {
            "timestamp": datetime.now().isoformat(),
            "process": proc_name,
            "pid": pid,
            "original_destination": orig_ip,
            "confidence_score": round(confidence * 100, 2), # 0-100%
            "findings": findings
        }
        print(json.dumps(verdict, indent=2))

        # 5. Take Action (Simulate Response)
        # If High Confidence (>80%), your AV would Kill Process here.
        # For now, we simulate the C2 to keep it talking.
        
        if b"GET" in raw_data or b"POST" in raw_data:
            # HTTP Response: "Ready:100" as requested
            http_response = (
                b"HTTP/1.1 200 OK\r\n"
                b"Server: Apache/2.4\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: 9\r\n"
                b"Connection: close\r\n"
                b"\r\n"
                b"Ready:100"
            )
            conn.sendall(http_response)
        else:
            # Binary Response (Echo or simple Ack)
            conn.sendall(b"\x00\x00\x00\x01OK")

    except Exception as e:
        print(f"[-] Error: {e}")
    finally:
        conn.close()

def start_server():
    analyzer = Analyzer()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((LISTEN_IP, LISTEN_PORT))
    server.listen(5)
    
    print(f"[*] AV Deep Scan Proxy Listening on {LISTEN_IP}:{LISTEN_PORT}")
    print(f"[*] Waiting for WFP redirected traffic...")
    
    while True:
        client, addr = server.accept()
        # Spawn thread per connection so we don't block
        client_handler = threading.Thread(target=handle_client, args=(client, addr, analyzer))
        client_handler.start()

if __name__ == "__main__":
    start_server()