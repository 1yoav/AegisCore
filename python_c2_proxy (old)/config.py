"""
Configuration for C2 Proxy
"""

# Network Settings
LISTEN_IP = "127.0.0.1"
LISTEN_PORT = 8080

# Scoring Weights (Total = 1.0)
WEIGHT_BEACONING = 0.40      # 40% - Periodic connections
WEIGHT_KNOWN_C2_IP = 0.60    # 60% - Known malicious IP (HUGE red flag)
WEIGHT_USER_AGENT = 0.20     # 20% - Suspicious UA
WEIGHT_PROTOCOL = 0.15       # 15% - Non-HTTP protocols
WEIGHT_PORT = 0.10           # 10% - Suspicious ports
WEIGHT_ENTROPY = 0.25        # 25% - High entropy (encrypted)
WEIGHT_PROCESS_NAME = 0.10   # 10% - Suspicious process names
WEIGHT_DNS_TUNNEL = 0.50     # 50% - DNS tunneling detected
WEIGHT_LARGE_PAYLOAD = 0.20  # 20% - Data exfiltration

# Beaconing Detection
BEACON_VARIANCE_THRESHOLD = 5.0  # seconds
MIN_CONNECTIONS_FOR_BEACON = 3

# Suspicious Ports
SUSPICIOUS_PORTS = [
    4444,   # Metasploit default
    3333,   # Crypto mining
    6666,   # IRC bots
    9999,   # Common backdoor
    31337,  # Elite/leet port
    1337,   # Leet
    8888,   # Alternative HTTP
    5555,   # Android ADB (sometimes malware)
]

# Known Bad User-Agents (automation tools)
BAD_USER_AGENTS = [
    "python-requests",
    "python-urllib",
    "curl",
    "wget",
    "powershell",
    "winhttp",
    "go-http-client",
]

# Entropy Threshold (0-8, where 8 is max randomness)
HIGH_ENTROPY_THRESHOLD = 7.5

# Database
DATABASE_PATH = "c2_threats.db"

# Threat Intel (you'll load from your SQLDatabase CIDR_IPS table)
KNOWN_C2_IPS = set()  # Populated at runtime

# IPC Pipe Name (must match C++ side)
DRIVER_PIPE_NAME = r'\\.\pipe\AVDeepScanPipe'

# Action Thresholds
KILL_THRESHOLD = 0.85        # 85%+ confidence = terminate process
ALERT_THRESHOLD = 0.60       # 60%+ confidence = alert user
LOG_THRESHOLD = 0.30         # 30%+ confidence = log for review