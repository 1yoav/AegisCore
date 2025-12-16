"""
Main Threat Analysis Engine
Analyzes network traffic and generates confidence scores
"""

import time
import statistics
from typing import Tuple, List, Dict
from protocol_detector import ProtocolDetector
from config_extractor import ConfigExtractor
import config as cfg
class SessionManager:
    """Tracks connection history to detect beaconing patterns"""
    def __init__(self):
        self.history = {}  # {pid: [timestamp1, timestamp2, ...]}

    def log_connection(self, pid: int):
        """Record a new connection attempt"""
        if pid not in self.history:
            self.history[pid] = []
        self.history[pid].append(time.time())

    def check_beaconing(self, pid: int) -> Tuple[float, str]:
        """
        Detect periodic beaconing behavior
        Returns: (confidence, description)
        """
        timestamps = self.history.get(pid, [])

        if len(timestamps) < cfg.MIN_CONNECTIONS_FOR_BEACON:
            return 0.0, f"Insufficient data ({len(timestamps)} connections)"

        # Calculate time intervals between connections
        intervals = [t2 - t1 for t1, t2 in zip(timestamps, timestamps[1:])]

        if not intervals:
            return 0.0, "No intervals"

        avg_interval = statistics.mean(intervals)

        try:
            std_dev = statistics.stdev(intervals)
        except statistics.StatisticsError:
            std_dev = 0.0  # All intervals identical (perfect beaconing!)

        # Low variance = highly regular = automated beaconing
        if std_dev < cfg.BEACON_VARIANCE_THRESHOLD:
            jitter_pct = (std_dev / avg_interval * 100) if avg_interval > 0 else 0
            return 1.0, f"Periodic beacon detected (~{avg_interval:.1f}s interval, {jitter_pct:.1f}% jitter)"

        return 0.0, f"Irregular timing (σ={std_dev:.1f}s)"
class Analyzer:
    """Main analysis engine - the 'brain' of the C2 proxy"""
    def __init__(self, known_c2_ips: set = None):
        self.sessions = SessionManager()
        self.protocol_detector = ProtocolDetector()
        self.config_extractor = ConfigExtractor()
        self.known_c2_ips = known_c2_ips or cfg.KNOWN_C2_IPS

    def analyze(self, pid: int, proc_name: str, raw_data: bytes,
                dest_ip: str, dest_port: int) -> Tuple[float, List[str], Dict]:
        """
        Main analysis function
        Returns: (confidence_score, findings, metadata)
        """
        score = 0.0
        findings = []
        metadata = {}

        # --- STAGE 1: Protocol Detection ---
        protocol, parsed_data = self.protocol_detector.detect(raw_data)
        metadata['protocol'] = protocol
        metadata['parsed'] = parsed_data

        # --- STAGE 2: Beaconing Analysis ---
        self.sessions.log_connection(pid)
        beacon_conf, beacon_msg = self.sessions.check_beaconing(pid)

        if beacon_conf > 0:
            score += cfg.WEIGHT_BEACONING * beacon_conf
            findings.append(f"[BEACONING] {beacon_msg}")

        # --- STAGE 3: Known C2 IP Check ---
        if dest_ip in self.known_c2_ips:
            score += cfg.WEIGHT_KNOWN_C2_IP
            findings.append(f"[KNOWN C2] Destination IP {dest_ip} in threat database")

        # --- STAGE 4: Port Analysis ---
        if dest_port in cfg.SUSPICIOUS_PORTS:
            score += cfg.WEIGHT_PORT
            findings.append(f"[SUSPICIOUS PORT] Port {dest_port} commonly used by malware")

        # --- STAGE 5: Protocol-Specific Analysis ---
        if protocol == 'HTTP' and parsed_data:
            http_score, http_findings = self._analyze_http(parsed_data)
            score += http_score
            findings.extend(http_findings)

        elif protocol == 'ENCRYPTED' or protocol == 'BINARY':
            entropy = parsed_data.get('entropy', 0) if parsed_data else 0
            if entropy > cfg.HIGH_ENTROPY_THRESHOLD:
                score += cfg.WEIGHT_ENTROPY
                findings.append(f"[HIGH ENTROPY] Data entropy {entropy:.2f}/8.0 (likely encrypted)")

        elif protocol == 'DNS':
            # DNS C2 is highly suspicious
            score += cfg.WEIGHT_DNS_TUNNEL
            findings.append("[DNS TUNNELING] Possible DNS-based C2 detected")

        elif protocol == 'TLS':
            findings.append("[TLS] Encrypted traffic (cannot inspect without MITM)")

        # --- STAGE 6: Process Name Heuristics ---
        suspicious_names = ['updater', 'svchost', 'system32', 'temp', 'download']
        if any(name in proc_name.lower() for name in suspicious_names):
            score += cfg.WEIGHT_PROCESS_NAME
            findings.append(f"[SUSPICIOUS PROCESS] Process name '{proc_name}' matches malware pattern")

        # --- STAGE 7: Payload Size Analysis ---
        if len(raw_data) > 10000:  # Large payload = possible exfiltration
            score += cfg.WEIGHT_LARGE_PAYLOAD
            findings.append(f"[LARGE PAYLOAD] {len(raw_data)} bytes (possible data exfiltration)")

        # --- STAGE 8: IOC Extraction ---
        iocs = self.config_extractor.extract_iocs(raw_data)
        metadata['iocs'] = iocs

        # Check if extracted IOCs match known threats
        for ip in iocs.get('ips', []):
            if ip in self.known_c2_ips:
                score += 0.1
                findings.append(f"[IOC] Embedded C2 IP found: {ip}")

        if iocs.get('suspicious_strings'):
            score += 0.15
            findings.append(f"[COMMANDS] Suspicious commands detected: {len(iocs['suspicious_strings'])}")

        # --- STAGE 9: Config Extraction ---
        config_data = self.config_extractor.extract_config(raw_data)
        if any(config_data.values()):
            metadata['config'] = config_data
            score += 0.2
            findings.append(f"[CONFIG] Malware configuration extracted")

        # Cap score at 1.0
        final_score = min(score, 1.0)

        return final_score, findings, metadata

def _analyze_http(self, parsed_data: Dict) -> Tuple[float, List[str]]:
    """HTTP-specific analysis"""
    score = 0.0
    findings = []

    user_agent = parsed_data.get('user_agent', '').lower()
    path = parsed_data.get('path', '')
    method = parsed_data.get('method', '')

    # Check 1: Missing or suspicious User-Agent
    if user_agent == 'missing':
        score += cfg.WEIGHT_USER_AGENT
        findings.append("[HTTP] Missing User-Agent header")
    elif any(bad_ua in user_agent for bad_ua in cfg.BAD_USER_AGENTS):
        score += cfg.WEIGHT_USER_AGENT
        findings.append(f"[HTTP] Automation tool User-Agent: {user_agent}")

    # Check 2: Suspicious paths
    suspicious_paths = ['/admin', '/upload', '/cmd', '/shell', '/beacon', '/c2']
    if any(sp in path.lower() for sp in suspicious_paths):
        score += 0.15
        findings.append(f"[HTTP] Suspicious path: {path}")

    # Check 3: Non-standard methods
    if method not in ['GET', 'POST', 'HEAD']:
        score += 0.10
        findings.append(f"[HTTP] Unusual method: {method}")

    # Check 4: Host header analysis
    host = parsed_data.get('host', '').lower()
    if host and (host.endswith('.tk') or host.endswith('.ml') or
                 host.endswith('.ga') or '.onion' in host):
        score += 0.20
        findings.append(f"[HTTP] Suspicious TLD in Host: {host}")

    return score, findings

def load_threat_intel(self, c2_ips: set):
    """Update known C2 IPs from threat intelligence"""
    self.known_c2_ips.update(c2_ips)
    print(f"[*] Loaded {len(c2_ips)} known C2 IPs into analyzer")
