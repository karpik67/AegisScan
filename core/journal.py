"""
Журнал событий — история проверок и действий.
Хранится в SQLite рядом с .exe или в корне проекта.
"""
import os
import sys
import sqlite3
import datetime


def _db_path() -> str:
    if getattr(sys, "frozen", False):
        base = os.path.dirname(sys.executable)
    else:
        base = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, "journal.db")


def _connect():
    conn = sqlite3.connect(_db_path())
    conn.execute("""
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event_type TEXT NOT NULL,
            object_name TEXT,
            object_path TEXT,
            verdict TEXT,
            source TEXT,
            details TEXT
        )
    """)
    conn.commit()
    return conn


def add_event(event_type: str, object_name: str = "",
              object_path: str = "", verdict: str = "",
              source: str = "", details: str = "") -> int:
    try:
        conn = _connect()
        ts = datetime.datetime.now().isoformat(timespec="seconds")
        cur = conn.execute(
            "INSERT INTO events "
            "(timestamp, event_type, object_name, object_path, verdict, source, details) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (ts, event_type, object_name, object_path, verdict, source, details),
        )
        conn.commit()
        eid = cur.lastrowid
        conn.close()
        return eid
    except Exception as e:
        print(f"[Journal] Ошибка записи: {e}")
        return -1


def get_events(limit: int = 200, event_type: str = None,
               verdict: str = None) -> list:
    try:
        conn = _connect()
        query = ("SELECT id, timestamp, event_type, object_name, "
                 "object_path, verdict, source, details FROM events")
        params = []
        conditions = []
        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if verdict:
            conditions.append("verdict = ?")
            params.append(verdict)
        if conditions:
            query += " WHERE " + " AND ".join(conditions)
        query += " ORDER BY id DESC LIMIT ?"
        params.append(limit)

        cur = conn.execute(query, params)
        rows = cur.fetchall()
        conn.close()

        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "event_type": r[2],
                "object_name": r[3],
                "object_path": r[4],
                "verdict": r[5],
                "source": r[6],
                "details": r[7],
            }
            for r in rows
        ]
    except Exception as e:
        print(f"[Journal] Ошибка чтения: {e}")
        return []


def clear() -> int:
    try:
        conn = _connect()
        cur = conn.execute("SELECT COUNT(*) FROM events")
        count = cur.fetchone()[0]
        conn.execute("DELETE FROM events")
        conn.commit()
        conn.close()
        return count
    except Exception as e:
        print(f"[Journal] Ошибка очистки: {e}")
        return 0


def stats() -> dict:
    try:
        conn = _connect()
        total = conn.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        threats = conn.execute(
            "SELECT COUNT(*) FROM events WHERE verdict = 'malware'"
        ).fetchone()[0]
        clean = conn.execute(
            "SELECT COUNT(*) FROM events WHERE verdict = 'clean'"
        ).fetchone()[0]
        conn.close()
        return {"total": total, "threats": threats, "clean": clean}
    except Exception as e:
        print(f"[Journal] Ошибка статистики: {e}")
        return {"total": 0, "threats": 0, "clean": 0}


def export_csv(path: str) -> dict:
    try:
        import csv
        events = get_events(limit=100000)
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow([
                "ID", "Дата", "Тип", "Объект", "Путь", "Вердикт",
                "Источник", "Детали"
            ])
            for e in events:
                writer.writerow([
                    e["id"], e["timestamp"], e["event_type"],
                    e["object_name"], e["object_path"], e["verdict"],
                    e["source"], e["details"],
                ])
        return {"status": "ok", "count": len(events), "path": path}
    except Exception as e:
        return {"status": "error", "message": str(e)}