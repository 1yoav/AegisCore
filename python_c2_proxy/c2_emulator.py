from events import Event, InvestigationContext

# ---- C2 Emulator (minimal reaction probe) ----
class C2Emulator:
    def generate_response(self, ctx: InvestigationContext):
        # Send a dummy "idle" command
        ctx.events.append(Event("EMULATOR_RESPONSE_SENT"))
        print(f"[EMULATOR] Sent fake response to PID {ctx.pid}")
        return b"OK"
