#!/usr/bin/env python3
"""
METATRON - db.py
MariaDB connection + all read/write/edit/delete operations
Database: metatron
"""

import mysql.connector
from datetime import datetime
from config import DB_HOST, DB_USER, DB_PASSWORD, DB_NAME


# ─────────────────────────────────────────────
# CONNECTION
# ─────────────────────────────────────────────

def get_connection():
    """Returns a MariaDB connection."""
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )


# ─────────────────────────────────────────────
# WRITE FUNCTIONS
# ─────────────────────────────────────────────

def create_session(target: str) -> int:
    """Insert new row into history. Returns sl_no."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute(
        "INSERT INTO history (target, scan_date, status) VALUES (%s, %s, %s)",
        (target, now, "active")
    )
    conn.commit()
    sl_no = c.lastrowid
    conn.close()
    return sl_no


def save_vulnerability(sl_no: int, vuln_name: str, severity: str,
                       port: str, service: str, description: str,
                       confidence: str = "possible") -> int:
    """Insert a vulnerability. Returns its id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO vulnerabilities (sl_no, vuln_name, severity, confidence, port, service, description)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (sl_no, vuln_name, severity, confidence, port, service, description))
    conn.commit()
    vuln_id = c.lastrowid
    conn.close()
    return vuln_id


def save_fix(sl_no: int, vuln_id: int, fix_text: str, source: str = "ai"):
    """Insert a fix linked to a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO fixes (sl_no, vuln_id, fix_text, source)
        VALUES (%s, %s, %s, %s)
    """, (sl_no, vuln_id, fix_text, source))
    conn.commit()
    conn.close()


def save_exploit(sl_no, exploit_name, tool_used, payload, result, notes):
    conn = get_connection()
    c = conn.cursor()
    c.execute("""
        INSERT INTO exploits_attempted 
        (sl_no, exploit_name, tool_used, payload, result, notes)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (
        sl_no,
        str(exploit_name or "")[:1000],
        str(tool_used  or "")[:500],
        str(payload    or ""),
        str(result     or "")[:2000],
        str(notes      or "")
    ))
    conn.commit()
    conn.close()


def save_summary(sl_no: int, raw_scan: str, ai_analysis: str, risk_level: str,
                  model_name: str = ""):
    """Insert the full session summary."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO summary (sl_no, raw_scan, ai_analysis, risk_level, model_name, generated_at)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (sl_no, raw_scan, ai_analysis, risk_level, model_name, now))
    conn.commit()
    conn.close()


def save_correction(sl_no: int, vuln_id: int, status: str,
                    original_text: str, corrected_text: str, reason: str) -> int:
    """
    Save a correction/hallucination record for a vulnerability.
    status: 'hallucination', 'corrected', 'verified', 'downgraded', 'reclassified'
    """
    allowed = {"hallucination", "corrected", "verified", "downgraded", "reclassified"}
    if status not in allowed:
        print(f"[!] Invalid status: {status}. Allowed: {allowed}")
        return -1
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO corrections
        (sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (sl_no, vuln_id, status, original_text, corrected_text, reason, now))
    conn.commit()
    cid = c.lastrowid
    conn.close()
    print(f"[+] Correction id={cid} saved for vuln id={vuln_id} [{status}]")
    return cid


# ─────────────────────────────────────────────
# READ FUNCTIONS
# ─────────────────────────────────────────────

def get_all_history():
    """Return all rows from history ordered by newest first."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT sl_no, target, scan_date, status FROM history ORDER BY sl_no DESC")
    rows = c.fetchall()
    conn.close()
    return rows


def get_session(sl_no: int) -> dict:
    """Return everything linked to a sl_no across all tables."""
    conn = get_connection()
    c = conn.cursor()

    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    exploits = c.fetchall()

    c.execute("SELECT * FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()

    c.execute("SELECT * FROM corrections WHERE sl_no = %s ORDER BY corrected_at", (sl_no,))
    corrections = c.fetchall()

    c.execute("SELECT * FROM evaluations WHERE sl_no = %s ORDER BY evaluated_at", (sl_no,))
    evaluations = c.fetchall()

    conn.close()

    return {
        "history":     history,
        "vulns":       vulns,
        "fixes":       fixes,
        "exploits":    exploits,
        "summary":     summary,
        "corrections": corrections,
        "evaluations": evaluations
    }


def get_vulnerabilities(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_fixes(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_exploits(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def get_corrections(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM corrections WHERE sl_no = %s ORDER BY corrected_at", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


# ─────────────────────────────────────────────
# EDIT FUNCTIONS
# ─────────────────────────────────────────────

def edit_vulnerability(vuln_id: int, field: str, value: str):
    """Edit a single field in vulnerabilities by id."""
    allowed = {"vuln_name", "severity", "confidence", "port", "service", "description"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE vulnerabilities SET {field} = %s WHERE id = %s",
        (value, vuln_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] vulnerabilities.{field} updated for id={vuln_id}")


def edit_fix(fix_id: int, fix_text: str):
    """Edit the fix_text of a fix by id."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE fixes SET fix_text = %s WHERE id = %s", (fix_text, fix_id))
    conn.commit()
    conn.close()
    print(f"[+] fix id={fix_id} updated.")


def edit_exploit(exploit_id: int, field: str, value: str):
    """Edit a single field in exploits_attempted by id."""
    allowed = {"exploit_name", "tool_used", "payload", "result", "notes"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE exploits_attempted SET {field} = %s WHERE id = %s",
        (value, exploit_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] exploits_attempted.{field} updated for id={exploit_id}")


def edit_summary_risk(sl_no: int, risk_level: str):
    """Update the risk level on a summary."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("UPDATE summary SET risk_level = %s WHERE sl_no = %s", (risk_level, sl_no))
    conn.commit()
    conn.close()
    print(f"[+] Summary risk_level updated for SL#{sl_no}")


def edit_correction(correction_id: int, field: str, value: str):
    """Edit a single field in corrections by id."""
    allowed = {"status", "original_text", "corrected_text", "reason"}
    if field not in allowed:
        print(f"[!] Invalid field: {field}. Allowed: {allowed}")
        return
    conn = get_connection()
    c = conn.cursor()
    c.execute(
        f"UPDATE corrections SET {field} = %s WHERE id = %s",
        (value, correction_id)
    )
    conn.commit()
    conn.close()
    print(f"[+] corrections.{field} updated for id={correction_id}")


# ─────────────────────────────────────────────
# DELETE FUNCTIONS
# ─────────────────────────────────────────────

def delete_vulnerability(vuln_id: int):
    """Delete a single vulnerability and its linked fixes."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE vuln_id = %s", (vuln_id,))
    c.execute("DELETE FROM vulnerabilities WHERE id = %s", (vuln_id,))
    conn.commit()
    conn.close()
    print(f"[+] Vulnerability id={vuln_id} and its fixes deleted.")


def delete_exploit(exploit_id: int):
    """Delete a single exploit attempt."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM exploits_attempted WHERE id = %s", (exploit_id,))
    conn.commit()
    conn.close()
    print(f"[+] Exploit id={exploit_id} deleted.")


def delete_fix(fix_id: int):
    """Delete a single fix."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM fixes WHERE id = %s", (fix_id,))
    conn.commit()
    conn.close()
    print(f"[+] Fix id={fix_id} deleted.")


def delete_correction(correction_id: int):
    """Delete a single correction record."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM corrections WHERE id = %s", (correction_id,))
    conn.commit()
    conn.close()
    print(f"[+] Correction id={correction_id} deleted.")


def delete_full_session(sl_no: int):
    """
    Wipe everything linked to a sl_no across all 6 tables.
    Order matters — delete children before parent (FK constraints).
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM evaluations        WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM corrections       WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM fixes             WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM exploits_attempted WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM vulnerabilities   WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM summary           WHERE sl_no = %s", (sl_no,))
    c.execute("DELETE FROM history           WHERE sl_no = %s", (sl_no,))
    conn.commit()
    conn.close()
    print(f"[+] Full session SL#{sl_no} deleted from all tables.")


# ─────────────────────────────────────────────
# RE-EXPORTS — split modules, same import paths
# ─────────────────────────────────────────────

from db_training import export_training_data
from db_evals import (save_evaluation, get_evaluations, delete_evaluation,
                      export_eval_package, parse_evaluation_response)
from db_display import print_history, print_session


# ─────────────────────────────────────────────
# QUICK CONNECTION TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    try:
        conn = get_connection()
        print("[+] MariaDB connection successful.")
        print("[+] Database: metatron")
        conn.close()
    except Exception as e:
        print(f"[!] Connection failed: {e}")
