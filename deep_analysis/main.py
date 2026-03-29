"""
Main Entry Point - C2 Proxy Analysis System
"""
import time
from driver_context import DriverContext


def print_banner():
    """Display startup banner"""
    # print("""
    # ╔═══════════════════════════════════════════════════════════╗
    # ║                                                           ║
    # ║         DEEP SCAN - Malware Analysis System v2.0          ║
    # ║                                                           ║
    # ║    Detects unsigned processes and analyzes C2 behavior    ║
    # ║                                                           ║
    # ╚═══════════════════════════════════════════════════════════╝
    # """)


def main():
    print("[Init] deep Analyze...\n")
    print_banner()
    
    # Initialize driver context
    driver_ctx = DriverContext()
    driver_ctx.start_listening()
    
    # print("[*] System ready. Waiting for alerts from C++ AV...")
    # print("[*] Press Ctrl+C to stop and view summary.\n")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n\n[*] Shutting down...")
        
        # Print summary
        summary = driver_ctx.get_summary()
        # threat_summary = driver_ctx.logger.get_threat_summary(limit=10)
        
        # print("\n" + "="*60)
        # print("SESSION SUMMARY")
        # print("="*60)
        # print(f"Total Investigations: {summary['total_investigations']}")
        # print(f"  • Malicious: {summary['malicious']}")
        # print(f"  • Suspicious: {summary['suspicious']}")
        # print(f"  • Benign: {summary['benign']}")
        
        # if threat_summary:
        #     print("\n" + "="*60)
        #     print("TOP 10 THREATS")
        #     print("="*60)
        #     print(f"{'PID':<8} {'Process':<30} {'Conf':<8} {'Verdict':<12} {'Events'}")
        #     print("-"*60)
        #     for threat in threat_summary:
        #         print(f"{threat['pid']:<8} "
        #               f"{threat['process'][-28:]:<30} "
        #               f"{threat['max_confidence']:<8.1f} "
        #               f"{threat['verdict']:<12} "
        #               f"{threat['connections']}")
        #
        # print("="*60)
        # print("\n[*] Database saved to: c2_threats.db")
        # print("[*] Goodbye!\n")


if __name__ == "__main__":
    main()
