# Threat Intelligence Log Analyzer

A Python and SQL tool that generates simulated enterprise authentication and network event logs, identifies indicators of compromise using SQL-driven detection rules, persists structured findings to a SQLite database, and outputs a severity-ranked threat report.

---

## How It Works

### 1. Log Generation

Produces 500 synthetic log events across a realistic set of users, hosts, and event types, with attack patterns deliberately injected at regular intervals:

| Pattern | Trigger |
|---------|---------|
| Brute force | `jsmith` receives repeated `AUTH_FAIL` events in bursts |
| Privilege escalation | `admin` account generates `PRIV_ESC` events periodically |
| Lateral movement | `LATERAL_MOVE` events injected across the host pool |
| After-hours access | Any event falling between 22:00–06:00 is reclassified as `AFTER_HOURS_LOGIN` |

Each log record contains: timestamp, user, host, event type, severity, and source IP.

### 2. Database Layer

Log records are inserted into a SQLite database (`threat_intel.db`) with two tables:

```
raw_logs   — all ingested log events
findings   — structured output from detection rules
```

### 3. Detection Rules

Four SQL queries run against `raw_logs` using `GROUP BY`, `HAVING`, and aggregation to surface findings:

| Rule | Severity | Logic |
|------|----------|-------|
| Brute Force | HIGH | Same user fails authentication 5+ times against the same host |
| Privilege Escalation | CRITICAL | Any `PRIV_ESC` event grouped by user and host |
| Lateral Movement | HIGH | Same user generates 2+ `LATERAL_MOVE` events |
| After-Hours Access | MEDIUM | Same user logs in outside business hours 3+ times from the same host |

Each finding is written to the `findings` table with severity, user, host, event count, first/last seen timestamps, and a JSON detail field.

### 4. Report

A plaintext threat report is printed to the terminal containing:

- Total log events ingested and findings raised
- Severity distribution with bar visualization
- Finding counts by detection rule
- Top 5 flagged users
- Critical alerts with user, host, and time window

---

## Requirements

- Python 3.7 or later
- No external libraries — uses only the Python standard library (`sqlite3`, `random`, `json`, `datetime`, `collections`)

---

## Installation

```bash
git clone https://github.com/danielsinensky/threat-log-analyzer.git
cd threat-log-analyzer
```

No pip install needed.

---

## Usage

```bash
python threat_analyzer.py
```

The script runs end-to-end with no arguments. On completion, `threat_intel.db` is written to the current working directory.

---

## Output

**Terminal — threat report printed on every run:**

```
=================================================================
  THREAT INTELLIGENCE LOG ANALYSIS REPORT
  Generated: 2026-06-14 09:22:11
=================================================================

  Total log events ingested :   500
  Total findings raised     :    65

  FINDINGS BY SEVERITY
  ----------------------------------------
  CRITICAL    7  #######
  HIGH       38  ######################################
  MEDIUM     20  ####################

  FINDINGS BY TYPE
  ----------------------------------------
  [HIGH    ] Brute Force Detected          24 occurrence(s)
  [MEDIUM  ] After-Hours Access            20 occurrence(s)
  [HIGH    ] Lateral Movement              14 occurrence(s)
  [CRITICAL] Privilege Escalation           7 occurrence(s)

  TOP FLAGGED USERS
  ----------------------------------------
  jsmith          18 finding(s)
  admin            7 finding(s)
  lwang            6 finding(s)

  CRITICAL ALERTS — IMMEDIATE REVIEW REQUIRED
  ----------------------------------------
  [Privilege Escalation] user=admin host=WIN-DC01
    first=2026-08-01 09:30:00  last=2026-08-29 14:15:00
=================================================================
```

**Database — `threat_intel.db` written to current directory:**

Query it directly with any SQLite client or the Python `sqlite3` shell:

```bash
sqlite3 threat_intel.db "SELECT * FROM findings WHERE severity='CRITICAL';"
```
