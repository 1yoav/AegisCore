"""
C2 Emulator - Generates fake C2 responses to trigger malware behavior
"""
from events import Event, InvestigationContext

class C2Emulator:
    """Emulates C2 server responses to extract more intel"""
    
    def __init__(self):
        self.interaction_counts = {}  # Track interactions per PID
    
    def generate_response(self, ctx: InvestigationContext) -> bytes:
        """
        Generate appropriate C2 response based on investigation stage
        
        Returns:
            Fake C2 response bytes (for future use)
        """
        pid = ctx.pid
        
        # Track interaction number
        self.interaction_counts[pid] = self.interaction_counts.get(pid, 0) + 1
        interaction_num = self.interaction_counts[pid]
        
        # Progressive emulation strategy
        if interaction_num == 1:
            response = self._emulate_initial_beacon(ctx)
        elif interaction_num == 2:
            response = self._emulate_sysinfo_request(ctx)
        elif interaction_num == 3:
            response = self._emulate_command_request(ctx)
        else:
            response = self._emulate_idle(ctx)
        
        # Log emulation event
        ctx.events.append(Event("EMULATOR_RESPONSE_SENT"))
        ctx.stage = f"INTERACTION_{interaction_num}"
        
        return response
    
    def _emulate_initial_beacon(self, ctx: InvestigationContext) -> bytes:
        """First contact - send simple acknowledgment"""
        print(f"[EMULATOR] Sending initial 'idle' command to PID {ctx.pid}")
        
        # HTTP-style response
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: text/plain\r\n"
        response += b"Content-Length: 10\r\n"
        response += b"\r\n"
        response += b"Ready:idle"
        
        return response
    
    def _emulate_sysinfo_request(self, ctx: InvestigationContext) -> bytes:
        """Second contact - request system info"""
        print(f"[EMULATOR] Requesting sysinfo from PID {ctx.pid}")
        
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: application/json\r\n"
        response += b"Content-Length: 45\r\n"
        response += b"\r\n"
        response += b'{"command":"sysinfo","params":["hostname"]}'
        
        # If process responds, it's likely malware
        ctx.events.append(Event("SYSINFO_REQUESTED"))
        
        return response
    
    def _emulate_command_request(self, ctx: InvestigationContext) -> bytes:
        """Third contact - send fake download command"""
        print(f"[EMULATOR] Sending fake download command to PID {ctx.pid}")
        
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Type: application/json\r\n"
        response += b"Content-Length: 58\r\n"
        response += b"\r\n"
        response += b'{"command":"download","url":"http://fake.local/payload.exe"}'
        
        # If process tries to download, big red flag
        ctx.events.append(Event("DOWNLOAD_COMMAND_SENT"))
        
        return response
    
    def _emulate_idle(self, ctx: InvestigationContext) -> bytes:
        """Ongoing contact - keep process alive"""
        print(f"[EMULATOR] Keeping PID {ctx.pid} in idle state")
        
        response = b"HTTP/1.1 200 OK\r\n"
        response += b"Content-Length: 2\r\n"
        response += b"\r\n"
        response += b"OK"
        
        return response
    
    def should_escalate(self, ctx: InvestigationContext) -> bool:
        """
        Determine if we should escalate response complexity
        Returns True if process is responding to our commands
        """
        # Check if process reacted to our emulation
        event_types = [e.type for e in ctx.events]
        
        reactions = [
            "PROCESS_REACTED",
            "DOWNLOAD_ATTEMPT",
            "COMMAND_EXECUTED"
        ]
        
        return any(reaction in event_types for reaction in reactions)
