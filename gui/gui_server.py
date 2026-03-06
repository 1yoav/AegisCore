import win32file
import win32pipe
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route('/scan-file', methods=['POST'])
def scan_file():
    file_path = request.json['path']
    # Run your existing static analysis
    result = analyzer.scan_file(file_path)
    return jsonify(result)


@app.route('/toggle-protection', methods=['POST'])
def toggle_protection():
    enabled = request.json['enabled']
    # Send command to C++ via pipe
    send_to_cpp({"command": "STOP_MONITORING" if not enabled else "START_MONITORING"})
    return jsonify({"success": True})


@app.route('/get-threats', methods=['GET'])
def get_threats():
    # Query your c2_threats.db
    threats = logger.get_recent_threats()
    return jsonify(threats)


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
