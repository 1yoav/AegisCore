"""
Enhanced Analyzer - Combines event tracking with deep analysis
Updated: Integrated Static Analysis + YARA + Dynamic Analysis
"""
from typing import Tuple, List
from events import InvestigationContext
from static_analyzer import StaticAnalyzer
from yara_analyzer import YaraAnalyzer
from behavioral_analyzer import BehavioralAnalyzer

class Analyzer:
    """Enhanced analyzer with multiple detection methods"""

    # Suspicious process name patterns
    SUSPICIOUS_NAMES = [
        'updater', 'svchost', 'system32', 'temp', 'download',
        'payload', 'shell', 'backdoor', 'rat', 'agent', 'bot'
    ]

    def __init__(self):
        self.process_cache = {}
        self.static_analyzer = StaticAnalyzer()
        self.yara_analyzer = YaraAnalyzer()
        self.behavioral_analyzer = BehavioralAnalyzer()

    def analyze_context(self, ctx: InvestigationContext) -> float:
        """
        Main analysis function
        Formula: 50% Static (Heuristics + YARA) + 50% Dynamic
        """
        findings = []

        # --- PART A: Static Analysis (50% Weight) ---

        # 1. Run Heuristic Analysis (PE headers, Entropy, Strings)
        heuristic_score, heuristic_findings, _ = self.static_analyzer.analyze_file(ctx.process_path)

        # 2. Run YARA Analysis (Signatures)
        yara_score, yara_findings, _ = self.yara_analyzer.scan_file(ctx.process_path)

        # Merge findings
        findings.extend(heuristic_findings)
        findings.extend(yara_findings)

        # Calculate Final Static Score
        # If YARA matches, it overrides heuristics because it's a precise match.
        final_static_score = max(heuristic_score, yara_score)

        if yara_score > 0:
            findings.append(f"[SCORE] YARA detection boosted static score to {final_static_score:.0f}")

        # --- PART B: Dynamic Analysis (50% Weight) ---
        dynamic_raw_score = 0.0

        # 1. Process Name Heuristics (Max 20 pts)
        name_score, name_findings = self._analyze_process_name(ctx.process_path)
        dynamic_raw_score += name_score
        findings.extend(name_findings)

        # 2. Event Pattern Analysis (Max 30 pts)
        event_score, event_findings = self._analyze_events(ctx)
        dynamic_raw_score += event_score
        findings.extend(event_findings)

        # 3. Network Indicators (Max 10 pts)
        network_score, network_findings = self._analyze_network_patterns(ctx)
        dynamic_raw_score += network_score
        findings.extend(network_findings)

        # 4. NEW: Behavioral / Live Process Analysis (Max 40 pts)
        # Assuming ctx.pid exists (it should if you are listening to a driver)
        beh_score, beh_findings = self.behavioral_analyzer.analyze_running_process(ctx.pid)
        dynamic_raw_score += beh_score
        findings.extend(beh_findings)

        # Normalize Dynamic Score: New Max Raw is 100 (20+30+10+40)
        dynamic_score_normalized = min(dynamic_raw_score, 100.0)

        # --- PART C: Final Calculation ---
        final_score = (final_static_score * 0.5) + (dynamic_score_normalized * 0.5)

        ctx.findings = findings
        ctx.confidence = min(final_score, 100.0)
        ctx.findings.append(f"[SCORE] Static: {final_static_score:.1f}% | Dynamic: {dynamic_score_normalized:.1f}%")

        return ctx.confidence

    def _analyze_process_name(self, process_path: str) -> Tuple[float, List[str]]:
        """Check if process name matches malware patterns"""
        score = 0.0
        findings = []
        path_lower = process_path.lower()

        for suspicious in self.SUSPICIOUS_NAMES:
            if suspicious in path_lower:
                score += 10.0
                findings.append(f"[PROCESS] Suspicious name pattern: '{suspicious}'")
                break

        suspicious_locations = ['temp', 'downloads', 'appdata\\local\\temp', 'users\\public']
        for location in suspicious_locations:
            if location in path_lower:
                score += 10.0
                findings.append(f"[PROCESS] Suspicious location: '{location}'")
                break

        return min(score, 20.0), findings

    def _analyze_events(self, ctx: InvestigationContext) -> Tuple[float, List[str]]:
        """Analyze the sequence and types of events"""
        score = 0.0
        findings = []
        event_counts = {}
        for event in ctx.events:
            event_counts[event.type] = event_counts.get(event.type, 0) + 1

        if event_counts.get("PROCESS_FLAGGED", 0) > 0:
            score += 15.0
            findings.append("[EVENT] Process flagged as unsigned")

        network_attempts = event_counts.get("NETWORK_ACTIVITY_ATTEMPT", 0)
        if network_attempts > 3:
            score += 15.0
            findings.append(f"[EVENT] Multiple connection attempts ({network_attempts})")
        elif network_attempts > 0:
            score += 5.0
            findings.append(f"[EVENT] Network activity detected ({network_attempts} attempts)")

        return min(score, 30.0), findings

    def _analyze_network_patterns(self, ctx: InvestigationContext) -> Tuple[float, List[str]]:
        """Analyze network-related patterns from events"""
        score = 0.0
        findings = []
        event_types = [e.type for e in ctx.events]

        if event_types.count("NETWORK_ACTIVITY_ATTEMPT") > 5:
            score += 10.0
            findings.append("[NETWORK] Persistent connection attempts")

        return score, findings

    def get_verdict(self, confidence: float) -> str:
        """Convert confidence score to verdict string"""
        if confidence >= 85:
            return "MALICIOUS"
        elif confidence >= 60:
            return "SUSPICIOUS"
        elif confidence >= 30:
            return "QUESTIONABLE"
        else:
            return "BENIGN"
