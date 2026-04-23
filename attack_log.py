"""
Attack Logger — Ghi log chi tiet tung cuoc tan cong vao SQLite.

Schema theo thiet ke cua user:
- attack_logs: log tung payload, mutation, ket qua
- Query san: bypass_rate, mutation hieu qua nhat
"""

import sqlite3
import os
import json
from datetime import datetime


class AttackLogger:
    """SQLite-based attack logger for security analysis."""

    def __init__(self, db_path=None):
        if db_path is None:
            db_path = os.path.join(
                os.path.dirname(os.path.abspath(__file__)), "attack_log.db"
            )
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Tao bang neu chua ton tai."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS attack_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                
                original_payload TEXT,
                mutated_payload TEXT,
                
                mutation_type TEXT,
                attempt_number INTEGER,
                
                detected_by TEXT,
                result TEXT,
                
                response_time REAL
            )
        """)
        conn.commit()
        conn.close()

    def log(self, original_payload, mutated_payload, mutation_type,
            attempt_number, detected_by, result, response_time):
        """Ghi 1 record attack vao DB.
        
        Args:
            original_payload: payload goc truoc mutation
            mutated_payload: payload sau mutation (hoac giong original neu khong mutate)
            mutation_type: ten strategy mutation (VD: case_swap, url_encode, original)
            attempt_number: so thu tu attempt (0 = original, 1+ = mutation round)
            detected_by: 'rule' | 'ai' | 'none'
            result: 'blocked' | 'bypass'
            response_time: thoi gian response (giay)
        """
        conn = sqlite3.connect(self.db_path)
        conn.execute(
            """INSERT INTO attack_logs 
               (original_payload, mutated_payload, mutation_type, 
                attempt_number, detected_by, result, response_time)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (str(original_payload), str(mutated_payload), str(mutation_type),
             int(attempt_number), str(detected_by), str(result),
             float(response_time))
        )
        conn.commit()
        conn.close()

    def get_bypass_rate(self):
        """Bypass rate = so bypass / tong so attack."""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("""
            SELECT 
                COUNT(CASE WHEN result='bypass' THEN 1 END) * 1.0 / COUNT(*)
            FROM attack_logs
        """).fetchone()
        conn.close()
        return row[0] if row and row[0] else 0.0

    def get_top_mutations(self, limit=5):
        """Mutation hieu qua nhat (chi tinh bypass)."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT mutation_type, COUNT(*) as success
            FROM attack_logs
            WHERE result='bypass'
            GROUP BY mutation_type
            ORDER BY success DESC
            LIMIT ?
        """, (limit,)).fetchall()
        conn.close()
        return rows  # [(mutation_type, count), ...]

    def get_detection_breakdown(self):
        """Phan tich: bao nhieu bi rule bat, bao nhieu bi AI bat, bao nhieu lot."""
        conn = sqlite3.connect(self.db_path)
        rows = conn.execute("""
            SELECT detected_by, COUNT(*) as cnt
            FROM attack_logs
            GROUP BY detected_by
        """).fetchall()
        conn.close()
        return dict(rows)  # {'rule': N, 'ai': M, 'none': K}

    def get_avg_response_time(self):
        """Thoi gian response trung binh."""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("""
            SELECT AVG(response_time) FROM attack_logs
        """).fetchone()
        conn.close()
        return row[0] if row and row[0] else 0.0

    def get_total_stats(self):
        """Thong ke tong hop."""
        conn = sqlite3.connect(self.db_path)
        row = conn.execute("""
            SELECT 
                COUNT(*) as total,
                COUNT(CASE WHEN result='bypass' THEN 1 END) as bypassed,
                COUNT(CASE WHEN result='blocked' THEN 1 END) as blocked,
                AVG(response_time) as avg_time
            FROM attack_logs
        """).fetchone()
        conn.close()
        return {
            'total': row[0],
            'bypassed': row[1],
            'blocked': row[2],
            'avg_response_time': round(row[3], 4) if row[3] else 0.0,
            'bypass_rate': round(row[1] / max(row[0], 1) * 100, 2),
        }

    def export_json(self, output_path=None):
        """Xuat toan bo log ra JSON."""
        if output_path is None:
            output_path = os.path.join(
                os.path.dirname(self.db_path),
                f"attack_log_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            )
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        rows = conn.execute("SELECT * FROM attack_logs ORDER BY id").fetchall()
        conn.close()

        data = {
            'exported_at': datetime.now().isoformat(),
            'total_records': len(rows),
            'stats': self.get_total_stats(),
            'top_mutations': self.get_top_mutations(),
            'detection_breakdown': self.get_detection_breakdown(),
            'logs': [dict(r) for r in rows],
        }

        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2, default=str)

        return output_path

    def clear(self):
        """Xoa toan bo log (dung khi chay test moi)."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("DELETE FROM attack_logs")
        conn.commit()
        conn.close()
