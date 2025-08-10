# AegisCore



\*\*AegisCore\*\* is a full-fledged antimalware system developed by \*\*Iftach Rabinowitz\*\* and \*\*Yoav Schmidt\*\* as the final-year project for the Magshimim Cyber Education Program.



> \*\*Status:\*\* Proof of Concept (PoC) in active development.



\## Overview

AegisCore is designed to detect, analyze, and neutralize malware on Windows systems.  

The system (will) consists of four main components:



1\. \*\*Pre-Download Scanner\*\*  

&nbsp;  Checks new downloads on a remote server \*before\* they finish downloading to the local machine.  

&nbsp;  This allows early detection and blocking of malicious files before execution.



2\. \*\*Signature Checker\*\*  

&nbsp;  Scans files and processes using a database of known malware signatures (hash-based or pattern-based). (Maybe add checks to file metadata too?)



3\. \*\*Sandbox\*\*  

&nbsp;  Executes suspicious files in an isolated environment to monitor their behavior safely.



4\. \*\*Tranquilization Engine\*\*  

&nbsp;  Terminates malicious processes, removes infected files, and cleans up applications or artifacts created by the malware.



\## Key Features (Planned)

\- Real-time process and file monitoring

\- Cloud-assisted scanning

\- Behavior-based analysis in sandbox mode

\- Kernel-level process creation logging

\- Automatic quarantine and removal



\## Technology Stack

\- \*\*Language:\*\* C++ (core scanning engine), C (kernel driver), Python (optional helper scripts)

\- \*\*Windows APIs:\*\* WinAPI, Windows Driver Kit (WDK)

\- \*\*Security Tools \& Libraries:\*\*  

&nbsp; - Hashing (SHA256/MD5)

&nbsp; - MinHook / Microsoft Detours (for API hooking in sandbox)

&nbsp; - Sysinternals Suite (testing \& analysis)

\- \*\*Test Environment:\*\* VirtualBox VM snapshots



\## Authors

\- \*\*Iftach Rabinowitz\*\*

\- \*\*Yoav Schmidt\*\*



\## License

TBD (likely MIT for PoC stage)



---



\### Development Notes

This repository currently focuses on building a \*\*Proof of Concept\*\* that demonstrates:

\- File scanning

\- Process detection

\- Basic sandbox behavior logging

\- Initial kernel driver setup



The final product will integrate these modules into a cohesive antivirus framework.



