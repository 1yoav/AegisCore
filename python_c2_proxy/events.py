import time

# ---- Event & InvestigationContext ----
class Event:
    def __init__(self, type_: str, ts=None):
        self.type = type_
        self.ts = ts or time.time()

class InvestigationContext:
    def __init__(self, pid: int, process_path: str):
        self.pid = pid
        self.process_path = process_path
        self.events = []
        self.confidence = 0.0
        self.stage = "INITIAL"
