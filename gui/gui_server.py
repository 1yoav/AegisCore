from flask import Flask, request, jsonify
from flask_cors import CORS
import time
import random
import os

app = Flask(__name__)
CORS(app)  # Enable CORS for Electron to connect


@app.route('/scan-file', methods=['POST'])
def scan_file():
    """
    Dummy file scanner - waits 5 seconds and returns fake results
    TODO: Replace with actual C++ engine integration
    """
    file_path = request.json.get('path', '')
    
    if not file_path:
        return jsonify({"error": "No file path provided"}), 400
    
    filename = os.path.basename(file_path)
    print(f"[*] Scanning file: {file_path}")
    
    # Simulate 5-second scan
    time.sleep(5)
    
    # Generate fake results based on filename
    is_malicious = any(word in filename.lower() for word in ['malware', 'virus', 'trojan', 'ransomware'])
    
    if is_malicious:
        score = random.randint(85, 98)
        verdict = "MALICIOUS"
        findings = [
            "Suspicious PE header detected",
            "Known malware signature: Trojan.Generic.KD.12345",
            "Network communication to suspicious IP: 192.168.1.100",
            "Attempts to modify system registry",
            "Code injection techniques detected"
        ]
    else:
        score = random.randint(0, 25)
        verdict = "CLEAN"
        findings = []
    
    result = {
        "success": True,
        "score": score,
        "verdict": verdict,
        "findings": findings
    }
    
    print(f"[+] Scan complete: {verdict} (score: {score})")
    return jsonify(result)


@app.route('/toggle-protection', methods=['POST'])
def toggle_protection():
    """
    Toggle real-time protection on/off
    TODO: Send command to C++ engine via named pipe
    """
    enabled = request.json.get('enabled', False)
    command = "START_MONITORING" if enabled else "STOP_MONITORING"
    
    print(f"[*] Protection command: {command}")
    
    # TODO: Send to C++ via pipe
    # send_to_cpp({"command": command})
    
    return jsonify({"success": True, "enabled": enabled})


@app.route('/get-threats', methods=['GET'])
def get_threats():
    """
    Get recent threats from database
    TODO: Query actual c2_threats.db
    """

    
    # Dummy threat data
    threats = [
        {
            "id": 1,
            "timestamp": "2026-03-14 15:30:00",
            "process": "malware.exe",
            "verdict": "MALICIOUS",
            "score": 95,
            "blocked": True
        },
        {
            "id": 2,
            "timestamp": "2026-03-14 14:15:00",
            "process": "suspicious.dll",
            "verdict": "SUSPICIOUS",
            "score": 72,
            "blocked": False
        }
    ]
    
    return jsonify({"threats": threats})


@app.route('/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "message": "AegisCore Flask server running"})


if __name__ == '__main__':
    print("=" * 50)
    print("  AegisCore Flask GUI Server")
    print("  Listening on: http://127.0.0.1:5000")
    print("=" * 50)
    print("\n[*] Endpoints:")
    print("  POST /scan-file      - Scan a file (dummy 5s delay)")
    print("  POST /toggle-protection - Toggle monitoring")
    print("  GET  /get-threats    - Get recent threats")
    print("  GET  /health         - Health check")
    print("\n[!] This is a DUMMY server. Replace with real C++ integration.\n")
    
    app.run(host='127.0.0.1', port=5000, debug=True)
