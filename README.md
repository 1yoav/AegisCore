# AegisCore

**AegisCore** is a lightweight, modular, open-source antivirus framework for Windows — developed by **Iftach Rabinowitz** and **Yoav Schmidt** as the final-year project for the Magshimim Cyber Education Program.

Built from the ground up with extensibility in mind, AegisCore is designed to be understood, modified, and built upon — not just run.

---

## Overview

AegisCore is a multi-layered threat detection and response system for Windows. It combines real-time monitoring, static analysis, behavioral detection, and network inspection into a single cohesive antivirus framework, distributed as a native Windows installer.

---

## Architecture

AegisCore is split across five tightly integrated components:

### 1. Core Engine (`aegiscore`)
The central C++ process that orchestrates all scanning activity. It manages the named pipe interface with the Electron GUI, launches and controls the deep analysis pipeline, and runs the real-time file monitors on Downloads, Desktop, and Temp directories.

### 2. API Hooking Engine (`MainProcces`)
Injects a hooking DLL into running processes to intercept and log suspicious API calls — process creation, memory manipulation, token privilege escalation, thread injection, and more. Feeds behavioral data into the Isolation Forest anomaly detector.

### 3. Deep Analysis Pipeline (`deep_analysis`)
A Python-based analysis pipeline compiled to standalone executables:
- **main.exe** — Central dispatcher. Receives alerts from all scanners via named pipe and runs full multi-stage analysis using static PE inspection, YARA signatures, and behavioral scoring.
- **isolationForest.exe** — Machine learning anomaly detector. Trained on known-good API call sequences per process, flags deviations in real time.
- **tlscheck2.exe** — Network-level TLS certificate inspector. Sniffs HTTPS traffic and flags expired, self-signed, or otherwise suspicious certificates.

### 4. Windows Service (`AegisService`)
A persistent background service that starts with Windows, launches the core engine and tray icon in the correct user session, and ensures the AV is always running even without user interaction.

### 5. GUI (`gui`)
An Electron-based desktop application providing:
- **Dashboard** — Live protection status and quick controls
- **Fine Tuning** — Per-module toggle controls (hooking, signature scanner, TLS checker)
- **Manual Scan** — Drag-and-drop file scanner with VirusTotal integration and system-wide scan (startup locations, scheduled tasks, installed services)
- **Threat History** — SQLite-backed log of all flagged processes with confidence scores and per-finding detail

---

## Key Features

- Real-time monitoring of Downloads, Desktop, and Temp directories
- MD5 hash-based VirusTotal cloud scanning
- Digital certificate validation via WinTrust API
- API hooking with ML-based behavioral anomaly detection (Isolation Forest)
- YARA signature matching
- Static PE analysis (entropy, headers, strings, packing detection)
- IAT (Import Address Table) analysis
- TLS certificate inspection via live packet sniffing
- System scan — startup registry keys, scheduled tasks, installed services
- Named pipe IPC between C++ engine and Electron GUI
- WFP-based network blocking of known malicious IPs (FireHOL Level 1 blocklist)
- Persistent threat database (SQLite)
- Native Windows MSI installer (WiX)
- Fully open-source and modular — every component can be swapped, extended, or replaced independently

---

## Technology Stack

| Layer | Technology |
|---|---|
| Core Engine | C++ (WinAPI, filesystem, threading) |
| API Hooking | C++ DLL injection, MinHook |
| ML Detection | Python — scikit-learn (Isolation Forest) |
| Static Analysis | Python — YARA, pefile |
| Network Inspection | Python — Scapy |
| GUI | Electron (Node.js, HTML/CSS/JS) |
| Database | SQLite |
| Installer | WiX Toolset v3 |
| Network Blocking | Windows Filtering Platform (WFP) |

---

## Authors

- **Iftach Rabinowitz**
- **Yoav Schmidt**

---

## License

MIT License — free to use, modify, and distribute. See `LICENSE` for details.