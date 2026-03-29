"""
Threat Logging and Database Storage
Stores all C2 traffic analysis results
"""

import sqlite3
import json
from datetime import datetime
from typing import Dict, List
import threading

class ThreatLogger:
    """Logs threat data to SQLite database"""

    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.Lock()
        self._initialize_db()

    def _initialize_db(self):
        """Create tables if they don't exist"""
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS c2_traffic (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    pid INTEGER NOT NULL,
                    process_name TEXT NOT NULL,
                    dest_ip TEXT NOT NULL,
                    dest_port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    verdict TEXT NOT NULL,
                    findings TEXT NOT NULL,
                    iocs TEXT,
                    raw_data BLOB,
                    response_sent BLOB
                )
            ''')

            conn.execute('''
                CREATE TABLE IF NOT EXISTS threat_summary (
                    pid INTEGER PRIMARY KEY,
                    process_name TEXT NOT NULL,
                    first_seen TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    connection_count INTEGER DEFAULT 1,
                    max_confidence REAL NOT NULL,
                    final_verdict TEXT NOT NULL,
                    killed BOOLEAN DEFAULT 0
                )
            ''')

            conn.commit()

    def log_traffic(self, verdict: Dict, raw_data: bytes, response: bytes = b''):
        """Log a single traffic analysis event"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO c2_traffic (
                        timestamp, pid, process_name, dest_ip, dest_port,
                        protocol, confidence_score, verdict, findings, iocs,
                        raw_data, response_sent
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    verdict['timestamp'],
                    verdict['pid'],
                    verdict['process'],
                    verdict['dest_ip'],
                    verdict['dest_port'],
                    verdict.get('protocol', 'unknown'),
                    verdict['confidence'],
                    verdict['verdict'],
                    json.dumps(verdict['findings']),
                    json.dumps(verdict.get('iocs', {})),
                    raw_data,
                    response
                ))

                # Update summary table
                self._update_summary(conn, verdict)

                conn.commit()

    def _update_summary(self, conn, verdict: Dict):
        """Update or insert threat summary"""
        pid = verdict['pid']

        # Check if PID already exists
        cursor = conn.execute(
            'SELECT connection_count, max_confidence FROM threat_summary WHERE pid = ?',
            (pid,)
        )
        row = cursor.fetchone()

        if row:
            # Update existing
            new_count = row[0] + 1
            new_max_conf = max(row[1], verdict['confidence'])

            conn.execute('''
                UPDATE threat_summary 
                SET last_seen = ?, 
                    connection_count = ?,
                    max_confidence = ?,
                    final_verdict = ?
                WHERE pid = ?
            ''', (
                verdict['timestamp'],
                new_count,
                new_max_conf,
                verdict['verdict'],
                pid
            ))
        else:
            # Insert new
            conn.execute('''
                INSERT INTO threat_summary (
                    pid, process_name, first_seen, last_seen,
                    connection_count, max_confidence, final_verdict
                ) VALUES (?, ?, ?, ?, 1, ?, ?)
            ''', (
                pid,
                verdict['process'],
                verdict['timestamp'],
                verdict['timestamp'],
                verdict['confidence'],
                verdict['verdict']
            ))

    def mark_killed(self, pid: int):
        """Mark a process as terminated"""
        with self.lock:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    'UPDATE threat_summary SET killed = 1 WHERE pid = ?',
                    (pid,)
                )
                conn.commit()

    def get_threat_summary(self, limit: int = 100) -> List[Dict]:
        """Retrieve recent threat summaries"""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.execute('''
                SELECT pid, process_name, first_seen, last_seen,
                       connection_count, max_confidence, final_verdict, killed
                FROM threat_summary
                ORDER BY last_seen DESC
                LIMIT ?
            ''', (limit,))

            results = []
            for row in cursor.fetchall():
                results.append({
                    'pid': row[0],
                    'process': row[1],
                    'first_seen': row[2],
                    'last_seen': row[3],
                    'connections': row[4],
                    'max_confidence': row[5],
                    'verdict': row[6],
                    'killed': bool(row[7])
                })

            return results
