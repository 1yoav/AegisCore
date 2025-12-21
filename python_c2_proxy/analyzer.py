from events import Event, InvestigationContext

# ---- Analyzer ----
class Analyzer:
    def analyze_context(self, ctx: InvestigationContext):
        # Simple example scoring
        score = 0
        for e in ctx.events:
            if e.type == "PROCESS_FLAGGED":
                score += 20
            if e.type == "NETWORK_ACTIVITY_ATTEMPT":
                score += 30
            if e.type == "PROCESS_REACTED":
                score += 25
        ctx.confidence = min(score, 100)
        return ctx.confidence
