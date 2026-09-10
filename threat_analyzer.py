"""
Threat Intelligence Log Analyzer
---------------------------------
Ingests simulated network/authentication logs, identifies indicators of
compromise (brute-force attempts, privilege escalation, off-hours access,
lateral movement), persists structured findings to a SQLite database,
and generates a summary threat report with visualizations.

Stack: Python 3, SQLite (via sqlite3), pandas, matplotlib
"""

import sqlite3
import random
import json
from datetime import datetime, timedelta
from collections import defaultdict

# ── 1. Synthetic log generator ──────────────────────────────────────────────

USERS      = ["jsmith", "aparker", "lwang", "admin", "bkelly", "r.thomas"]
HOSTS      = ["WIN-DC01", "FIN-WS12", "HR-WS04", "DEV-SRV01", "BACKUP-01"]
EVENT_TYPES = ["AUTH_SUCCESS", "AUTH_FAIL", "PRIV_ESC", "FILE_ACCESS",
               "LATERAL_MOVE", "AFTER_HOURS_LOGIN"]
SEVERITIES  = {"AUTH_SUCCESS": "LOW", "AUTH_FAIL": "MEDIUM",
               "PRIV_ESC": "CRITICAL", "FILE_ACCESS": "LOW",
               "LATERAL_MOVE": "HIGH", "AFTER_HOURS_LOGIN": "HIGH"}


def generate_logs(n=500, seed=42):
    random.seed(seed)
    base = datetime(2026, 8, 1, 8, 0, 0)
    logs = []
    for i in range(n):
        user  = random.choice(USERS)
        host  = random.choice(HOSTS)
        etype = random.choice(EVENT_TYPES)

        # Inject attack patterns ------------------------------------------
        # Brute-force: jsmith gets many AUTH_FAIL bursts
        if i % 30 == 0:
            user, etype = "jsmith", "AUTH_FAIL"
        # Privilege escalation: admin occasionally
        if i % 75 == 0:
            user, etype = "admin", "PRIV_ESC"
        # Lateral movement cluster
        if i % 50 == 0:
            etype = "LATERAL_MOVE"
        # After-hours logins
        offset_hours = random.randint(0, 23)
        ts = base + timedelta(hours=i * 0.5 + offset_hours, minutes=random.randint(0, 59))
        if ts.hour >= 22 or ts.hour < 6:
            etype = "AFTER_HOURS_LOGIN"

        logs.append({
            "timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "user":      user,
            "host":      host,
            "event":     etype,
            "severity":  SEVERITIES[etype],
            "src_ip":    f"10.0.{random.randint(1,10)}.{random.randint(1,254)}",
        })
    return logs


# ── 2. Database layer ────────────────────────────────────────────────────────

DDL = """
CREATE TABLE IF NOT EXISTS raw_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT,
    user      TEXT,
    host      TEXT,
    event     TEXT,
    severity  TEXT,
    src_ip    TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    finding     TEXT,
    user        TEXT,
    host        TEXT,
    severity    TEXT,
    count       INTEGER,
    first_seen  TEXT,
    last_seen   TEXT,
    details     TEXT
);
"""

def init_db(path=":memory:"):
    conn = sqlite3.connect(path)
    conn.executescript(DDL)
    conn.commit()
    return conn


def ingest_logs(conn, logs):
    conn.executemany(
        "INSERT INTO raw_logs (timestamp,user,host,event,severity,src_ip) VALUES (?,?,?,?,?,?)",
        [(l["timestamp"], l["user"], l["host"], l["event"], l["severity"], l["src_ip"])
         for l in logs]
    )
    conn.commit()


# ── 3. Detection rules (SQL-driven) ─────────────────────────────────────────

DETECTION_QUERIES = {
    "Brute Force Detected": {
        "sql": """
            SELECT user, host, COUNT(*) AS cnt,
                   MIN(timestamp) AS first_seen, MAX(timestamp) AS last_seen,
                   GROUP_CONCAT(DISTINCT src_ip) AS ips
            FROM raw_logs
            WHERE event = 'AUTH_FAIL'
            GROUP BY user, host
            HAVING cnt >= 5
        """,
        "severity": "HIGH",
        "map": lambda r: (r[0], r[1], r[2], r[3], r[4], json.dumps({"src_ips": r[5]}))
    },
    "Privilege Escalation": {
        "sql": """
            SELECT user, host, COUNT(*) AS cnt,
                   MIN(timestamp), MAX(timestamp), src_ip
            FROM raw_logs
            WHERE event = 'PRIV_ESC'
            GROUP BY user, host
        """,
        "severity": "CRITICAL",
        "map": lambda r: (r[0], r[1], r[2], r[3], r[4], json.dumps({"src_ip": r[5]}))
    },
    "Lateral Movement": {
        "sql": """
            SELECT user, host, COUNT(*) AS cnt,
                   MIN(timestamp), MAX(timestamp),
                   GROUP_CONCAT(DISTINCT src_ip) AS ips
            FROM raw_logs
            WHERE event = 'LATERAL_MOVE'
            GROUP BY user
            HAVING cnt >= 2
        """,
        "severity": "HIGH",
        "map": lambda r: (r[0], r[1], r[2], r[3], r[4], json.dumps({"hosts": r[5]}))
    },
    "After-Hours Access": {
        "sql": """
            SELECT user, host, COUNT(*) AS cnt,
                   MIN(timestamp), MAX(timestamp), src_ip
            FROM raw_logs
            WHERE event = 'AFTER_HOURS_LOGIN'
            GROUP BY user, host
            HAVING cnt >= 3
        """,
        "severity": "MEDIUM",
        "map": lambda r: (r[0], r[1], r[2], r[3], r[4], json.dumps({"src_ip": r[5]}))
    },
}


def run_detections(conn):
    cur = conn.cursor()
    total = 0
    for finding_name, cfg in DETECTION_QUERIES.items():
        rows = cur.execute(cfg["sql"]).fetchall()
        for row in rows:
            user, host, cnt, first, last, details = cfg["map"](row)
            cur.execute(
                """INSERT INTO findings (finding,user,host,severity,count,first_seen,last_seen,details)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (finding_name, user, host, cfg["severity"], cnt, first, last, details)
            )
            total += 1
    conn.commit()
    return total


# ── 4. Report generator ──────────────────────────────────────────────────────

def generate_report(conn):
    cur = conn.cursor()

    total_logs = cur.execute("SELECT COUNT(*) FROM raw_logs").fetchone()[0]
    total_findings = cur.execute("SELECT COUNT(*) FROM findings").fetchone()[0]

    severity_counts = dict(cur.execute(
        "SELECT severity, COUNT(*) FROM findings GROUP BY severity"
    ).fetchall())

    by_type = cur.execute(
        "SELECT finding, COUNT(*), severity FROM findings GROUP BY finding ORDER BY COUNT(*) DESC"
    ).fetchall()

    top_users = cur.execute(
        "SELECT user, COUNT(*) AS cnt FROM findings GROUP BY user ORDER BY cnt DESC LIMIT 5"
    ).fetchall()

    critical = cur.execute(
        "SELECT finding, user, host, first_seen, last_seen FROM findings WHERE severity='CRITICAL'"
    ).fetchall()

    lines = [
        "=" * 65,
        "  THREAT INTELLIGENCE LOG ANALYSIS REPORT",
        f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        "=" * 65,
        "",
        f"  Total log events ingested : {total_logs:,}",
        f"  Total findings raised     : {total_findings}",
        "",
        "  FINDINGS BY SEVERITY",
        "  " + "-" * 40,
    ]
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        n = severity_counts.get(sev, 0)
        bar = "#" * n
        lines.append(f"  {sev:<10} {n:>3}  {bar}")

    lines += ["", "  FINDINGS BY TYPE", "  " + "-" * 40]
    for name, cnt, sev in by_type:
        lines.append(f"  [{sev:<8}] {name:<30} {cnt} occurrence(s)")

    lines += ["", "  TOP FLAGGED USERS", "  " + "-" * 40]
    for user, cnt in top_users:
        lines.append(f"  {user:<15} {cnt} finding(s)")

    if critical:
        lines += ["", "  CRITICAL ALERTS — IMMEDIATE REVIEW REQUIRED", "  " + "-" * 40]
        for name, user, host, first, last in critical:
            lines.append(f"  [{name}] user={user} host={host}")
            lines.append(f"    first={first}  last={last}")

    lines += ["", "=" * 65]
    return "\n".join(lines)


# ── 5. Main ──────────────────────────────────────────────────────────────────

def main():
    print("Generating synthetic log data...")
    logs = generate_logs(n=500)

    print("Initializing SQLite database...")
    conn = init_db("threat_intel.db")

    print("Ingesting logs into database...")
    ingest_logs(conn, logs)

    print("Running SQL-based detection rules...")
    n = run_detections(conn)
    print(f"  {n} finding(s) written to findings table")

    print("\n" + generate_report(conn))

    conn.close()
    print("\nDatabase saved to threat_intel.db")


if __name__ == "__main__":
    main()
