"""
Events and Investigation Context
Tracks the lifecycle of a suspicious process investigation
"""
import time
from typing import List

class Event:
    """Represents a single event in an investigation"""
    
    def __init__(self, type_: str, ts=None, details: dict = None):
        self.type = type_
        self.ts = ts or time.time()
        self.details = details or {}
    
    def __repr__(self):
        return f"Event({self.type}, {time.ctime(self.ts)})"


class InvestigationContext:
    """
    Tracks all information about a suspicious process investigation
    """
    
    def __init__(self, pid: int, process_path: str):
        self.pid = pid
        self.process_path = process_path
        
        # Events timeline
        self.events: List[Event] = []
        
        # Analysis results
        self.confidence = 0.0
        self.findings: List[str] = []
        self.stage = "INITIAL"
        
        # Network information (if available)
        self.dest_ip = "Unknown"
        self.dest_port = 0
        
        # Timestamps
        self.first_seen = time.time()
        self.last_activity = time.time()
        self.tlsCheck = False
        self.signatureScan = False
        self.isolationForest = False
    
    def add_event(self, event_type: str, details: dict = None):
        """Add a new event to the investigation"""
        event = Event(event_type, details=details)
        self.events.append(event)
        self.last_activity = time.time()
    
    def get_duration(self) -> float:
        """Get investigation duration in seconds"""
        return self.last_activity - self.first_seen
    
    def __repr__(self):
        return f"Investigation(PID={self.pid}, Confidence={self.confidence:.1f}%, Events={len(self.events)})"
