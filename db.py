#!/usr/bin/env python3
"""
METATRON - db.py
MariaDB connection + all read/write/edit/delete operations
Database: metatron
"""

import mysql.connector
import json
import os
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
# TRAINING DATA EXPORT
# ─────────────────────────────────────────────

def export_training_data(output_dir: str = None) -> str:
    """
    Export all sessions that have corrections as JSONL training pairs.
    Each line is a JSON object with:
      - system: the system prompt
      - user: raw scan data (input)
      - assistant: corrected analysis (ideal output)
      - metadata: session info, corrections applied

    Only exports sessions with at least one correction (these are
    the sessions where we know what the right answer should have been).
    Returns the output file path.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "training")
    os.makedirs(output_dir, exist_ok=True)

    conn = get_connection()
    c = conn.cursor()

    # Find all sessions that have corrections
    c.execute("""
        SELECT DISTINCT c.sl_no
        FROM corrections c
        ORDER BY c.sl_no
    """)
    session_ids = [row[0] for row in c.fetchall()]

    if not session_ids:
        conn.close()
        print("[!] No corrected sessions found. Nothing to export.")
        return ""

    training_pairs = []

    for sl_no in session_ids:
        # Get session data
        c.execute("SELECT target FROM history WHERE sl_no = %s", (sl_no,))
        hist = c.fetchone()
        if not hist:
            continue
        target = hist[0]

        # Get raw scan
        c.execute("SELECT raw_scan, ai_analysis, risk_level FROM summary WHERE sl_no = %s", (sl_no,))
        summary = c.fetchone()
        if not summary:
            continue
        raw_scan, ai_analysis, risk_level = summary

        # Get all vulns
        c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
        vulns = c.fetchall()

        # Get all corrections
        c.execute("""
            SELECT c.vuln_id, c.status, c.original_text, c.corrected_text, c.reason
            FROM corrections c
            WHERE c.sl_no = %s
        """, (sl_no,))
        corrections = c.fetchall()

        # Build the corrected output — what the AI SHOULD have said
        correction_map = {}
        for vuln_id, status, original, corrected, reason in corrections:
            correction_map[vuln_id] = {
                "status": status, "original": original,
                "corrected": corrected, "reason": reason
            }

        corrected_vulns = []
        for v in vulns:
            vid = v[0]
            vuln_name, severity, port, service, description = v[2], v[3], v[4], v[5], v[6]

            if vid in correction_map:
                corr = correction_map[vid]
                if corr["status"] == "hallucination":
                    # This vuln should NOT have been reported
                    continue
                elif corr["status"] in ("corrected", "downgraded", "reclassified"):
                    # Use the corrected text
                    corrected_vulns.append({
                        "vuln_name": vuln_name,
                        "severity": severity,
                        "port": port,
                        "service": service,
                        "description": corr["corrected"] or description,
                        "correction_applied": corr["status"],
                        "correction_reason": corr["reason"]
                    })
                else:
                    # verified — keep as-is
                    corrected_vulns.append({
                        "vuln_name": vuln_name,
                        "severity": severity,
                        "port": port,
                        "service": service,
                        "description": description,
                        "correction_applied": "verified"
                    })
            else:
                # No correction — keep as-is
                corrected_vulns.append({
                    "vuln_name": vuln_name,
                    "severity": severity,
                    "port": port,
                    "service": service,
                    "description": description
                })

        # Build the ideal assistant response
        ideal_output_lines = []
        for cv in corrected_vulns:
            ideal_output_lines.append(
                f"VULN: {cv['vuln_name']} | SEVERITY: {cv['severity']} "
                f"| PORT: {cv['port']} | SERVICE: {cv['service']}"
            )
            ideal_output_lines.append(f"DESC: {cv['description']}")
            ideal_output_lines.append("")

        # Determine corrected risk level
        corrected_risk = risk_level
        severities = [cv["severity"] for cv in corrected_vulns]
        if not severities:
            corrected_risk = "LOW"
        elif "critical" in severities:
            corrected_risk = "CRITICAL"
        elif "high" in severities:
            corrected_risk = "HIGH"
        elif "medium" in severities:
            corrected_risk = "MEDIUM"
        else:
            corrected_risk = "LOW"

        ideal_output_lines.append(f"RISK_LEVEL: {corrected_risk}")

        training_pair = {
            "messages": [
                {"role": "user", "content": f"TARGET: {target}\n\nRECON DATA:\n{raw_scan}"},
                {"role": "assistant", "content": "\n".join(ideal_output_lines)}
            ],
            "metadata": {
                "sl_no": sl_no,
                "target": target,
                "original_risk": risk_level,
                "corrected_risk": corrected_risk,
                "corrections_applied": len(corrections),
                "hallucinations_removed": sum(
                    1 for _, s, _, _, _ in corrections if s == "hallucination"
                ),
                "vulns_after_correction": len(corrected_vulns)
            }
        }
        training_pairs.append(training_pair)

    conn.close()

    # Write JSONL
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"metatron_training_{timestamp}.jsonl")
    with open(filename, "w") as f:
        for pair in training_pairs:
            f.write(json.dumps(pair, ensure_ascii=False) + "\n")

    print(f"[+] Exported {len(training_pairs)} training pair(s) to {filename}")

    # Also write a stats summary
    stats_file = os.path.join(output_dir, f"metatron_training_{timestamp}_stats.json")
    stats = {
        "exported_at": timestamp,
        "total_pairs": len(training_pairs),
        "sessions": [p["metadata"] for p in training_pairs],
        "total_hallucinations_removed": sum(
            p["metadata"]["hallucinations_removed"] for p in training_pairs
        ),
        "total_corrections": sum(
            p["metadata"]["corrections_applied"] for p in training_pairs
        )
    }
    with open(stats_file, "w") as f:
        json.dump(stats, f, indent=2)
    print(f"[+] Stats written to {stats_file}")

    return filename


# ─────────────────────────────────────────────
# EVALUATIONS — external LLM review storage
# ─────────────────────────────────────────────

def save_evaluation(sl_no: int, vuln_id: int, evaluator: str,
                    evidence_cited: str, verdict: str, confidence: str,
                    severity_correct: bool, cve_correct: bool,
                    software_correct: bool, fix_correct: bool,
                    notes: str) -> int:
    """Save an external evaluation record for a vulnerability."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO evaluations
        (sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence,
         severity_correct, cve_correct, software_correct, fix_correct,
         notes, evaluated_at)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
    """, (sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence,
          severity_correct, cve_correct, software_correct, fix_correct,
          notes, now))
    conn.commit()
    eid = c.lastrowid
    conn.close()
    return eid


def get_evaluations(sl_no: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT * FROM evaluations WHERE sl_no = %s ORDER BY evaluated_at", (sl_no,))
    rows = c.fetchall()
    conn.close()
    return rows


def delete_evaluation(eval_id: int):
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM evaluations WHERE id = %s", (eval_id,))
    conn.commit()
    conn.close()
    print(f"[+] Evaluation id={eval_id} deleted.")


# ─────────────────────────────────────────────
# EVAL PACKAGE — export for external review
# ─────────────────────────────────────────────

EVAL_RUBRIC = """## Evaluation Instructions

You are reviewing an AI-generated penetration testing report. Your job is to evaluate
the accuracy and quality of each vulnerability finding against the raw scan evidence.

### For EACH vulnerability finding, evaluate:

1. **Evidence Basis** — Is there direct evidence in the raw scan data? Quote it.
2. **CVE Accuracy** — Are the cited CVEs correct for the detected software version?
3. **Severity Justification** — Is the severity level justified by the evidence?
4. **Software Identification** — Is the software correctly identified? (e.g., Apache httpd vs Apache Log4j are DIFFERENT software)
5. **Fix Quality** — Is the recommended fix appropriate and actionable?

### Confidence Levels
Rate your confidence in each verdict: high, medium, low

### Output Format

For EACH vulnerability, output this exact format:

```
EVAL: <vuln_name>
VERDICT: <valid | hallucination | corrected | downgraded | reclassified>
CONFIDENCE: <high | medium | low>
EVIDENCE: <quote from raw scan data, or "none found">
SEVERITY_CORRECT: <yes | no>
CVE_CORRECT: <yes | no | not_applicable>
SOFTWARE_CORRECT: <yes | no>
FIX_CORRECT: <yes | no>
NOTES: <explanation of your reasoning>
```

After reviewing all findings:

```
OVERALL_RISK_LEVEL: <CRITICAL | HIGH | MEDIUM | LOW>
HALLUCINATION_COUNT: <number>
ACCURACY_SUMMARY: <2-3 sentence summary of the AI's overall accuracy>
```

Be thorough and cite specific evidence. If there is no scan evidence for a finding, it is likely a hallucination."""


def export_eval_package(sl_no: int, output_dir: str = None) -> str:
    """
    Export a self-contained evaluation package for external LLM review.
    Returns the output file path.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evals")
    os.makedirs(output_dir, exist_ok=True)

    conn = get_connection()
    c = conn.cursor()

    # Get session
    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()
    if not history:
        conn.close()
        print(f"[!] Session SL#{sl_no} not found.")
        return ""

    target = history[1]
    scan_date = str(history[2])

    # Get summary
    c.execute("SELECT raw_scan, ai_analysis, risk_level, model_name FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()
    if not summary:
        conn.close()
        print(f"[!] No summary found for SL#{sl_no}.")
        return ""

    raw_scan, ai_analysis, risk_level, model_name = summary

    # Get vulns
    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    # Get fixes
    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    # Get existing corrections
    c.execute("SELECT * FROM corrections WHERE sl_no = %s", (sl_no,))
    corrections = c.fetchall()

    # Get existing evaluations
    c.execute("SELECT * FROM evaluations WHERE sl_no = %s", (sl_no,))
    evaluations = c.fetchall()

    conn.close()

    # Build fix lookup
    fix_map = {}
    for f in fixes:
        fix_map.setdefault(f[2], []).append(f[3])  # vuln_id -> [fix_text]

    # Build the package
    lines = []
    lines.append(f"# METATRON Evaluation Package — SL#{sl_no}")
    lines.append(f"")
    lines.append(f"**Target:** {target}")
    lines.append(f"**Scan Date:** {scan_date}")
    lines.append(f"**AI Model:** {model_name or 'unknown'}")
    lines.append(f"**AI Risk Assessment:** {risk_level}")
    lines.append(f"**Vulnerabilities Found:** {len(vulns)}")
    lines.append(f"")

    # Section 1: Raw scan data
    lines.append(f"---")
    lines.append(f"## 1. RAW SCAN DATA")
    lines.append(f"")
    lines.append(f"This is the unmodified output from the recon tools (nmap, whatweb, curl, etc.).")
    lines.append(f"This is the ONLY ground truth. Findings must be supported by this data.")
    lines.append(f"")
    lines.append(f"```")
    lines.append(raw_scan or "(no scan data)")
    lines.append(f"```")
    lines.append(f"")

    # Section 2: AI findings
    lines.append(f"---")
    lines.append(f"## 2. AI VULNERABILITY FINDINGS")
    lines.append(f"")
    for v in vulns:
        # v: id, sl_no, vuln_name, severity, confidence, port, service, description
        vid = v[0]
        vuln_name, severity, confidence = v[2], v[3], v[4] or "possible"
        port, service, description = v[5], v[6], v[7]
        lines.append(f"### Finding #{vid}: {vuln_name}")
        lines.append(f"- **Severity:** {severity}")
        lines.append(f"- **Confidence:** {confidence}")
        lines.append(f"- **Port:** {port}")
        lines.append(f"- **Service:** {service}")
        lines.append(f"- **Description:** {description}")
        if vid in fix_map:
            for fix in fix_map[vid]:
                lines.append(f"- **Recommended Fix:** {fix}")
        lines.append(f"")

    # Section 3: Existing corrections (if any)
    if corrections:
        lines.append(f"---")
        lines.append(f"## 3. EXISTING CORRECTIONS (from prior review)")
        lines.append(f"")
        for cr in corrections:
            lines.append(f"- **Vuln #{cr[2]}** — Status: **{cr[3]}**")
            lines.append(f"  - Original: {cr[4]}")
            if cr[5]:
                lines.append(f"  - Corrected: {cr[5]}")
            lines.append(f"  - Reason: {cr[6]}")
            lines.append(f"")

    # Section 4: Existing evaluations (if any)
    if evaluations:
        lines.append(f"---")
        lines.append(f"## 4. PRIOR EVALUATIONS")
        lines.append(f"")
        for ev in evaluations:
            lines.append(f"- **Vuln #{ev[2]}** — Evaluator: {ev[3]} | Verdict: {ev[5]} | Confidence: {ev[6]}")
            lines.append(f"  - Evidence: {ev[4]}")
            lines.append(f"  - Notes: {ev[11]}")
            lines.append(f"")

    # Section 5: Rubric
    lines.append(f"---")
    lines.append(EVAL_RUBRIC)

    # Write file
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"eval_SL{sl_no}_{safe_target}_{timestamp}.md")
    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Eval package exported: {filename}")
    return filename


def parse_evaluation_response(sl_no: int, evaluator: str, response_text: str) -> list:
    """
    Parse an external evaluator's response and save evaluations to the database.
    Returns list of saved evaluation IDs.

    Expected format per finding:
    EVAL: <vuln_name>
    VERDICT: <valid|hallucination|corrected|downgraded|reclassified>
    CONFIDENCE: <high|medium|low>
    EVIDENCE: <text>
    SEVERITY_CORRECT: <yes|no>
    CVE_CORRECT: <yes|no|not_applicable>
    SOFTWARE_CORRECT: <yes|no>
    FIX_CORRECT: <yes|no>
    NOTES: <text>
    """
    import re

    # Get vulns for this session to match names to IDs
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, vuln_name FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = {row[1].lower().strip(): row[0] for row in c.fetchall()}
    conn.close()

    saved_ids = []

    # Split into eval blocks
    blocks = re.split(r'(?=EVAL:)', response_text, flags=re.IGNORECASE)

    for block in blocks:
        block = block.strip()
        if not block.upper().startswith("EVAL:"):
            continue

        # Parse fields
        def extract(pattern, text, default=""):
            m = re.search(pattern, text, re.IGNORECASE)
            return m.group(1).strip() if m else default

        vuln_name = extract(r'EVAL:\s*(.+?)(?:\n|$)', block)
        verdict = extract(r'VERDICT:\s*(.+?)(?:\n|$)', block, "unknown").lower()
        confidence = extract(r'CONFIDENCE:\s*(.+?)(?:\n|$)', block, "medium").lower()
        evidence = extract(r'EVIDENCE:\s*(.+?)(?=\n[A-Z_]+:|$)', block, "none cited")
        severity_ok = extract(r'SEVERITY_CORRECT:\s*(.+?)(?:\n|$)', block, "unknown").lower()
        cve_ok = extract(r'CVE_CORRECT:\s*(.+?)(?:\n|$)', block, "unknown").lower()
        software_ok = extract(r'SOFTWARE_CORRECT:\s*(.+?)(?:\n|$)', block, "unknown").lower()
        fix_ok = extract(r'FIX_CORRECT:\s*(.+?)(?:\n|$)', block, "unknown").lower()
        notes = extract(r'NOTES:\s*(.+?)(?=\n(?:EVAL:|OVERALL_|HALLUCINATION_|ACCURACY_)|$)', block, "")

        # Match vuln name to ID
        vuln_id = None
        vuln_name_lower = vuln_name.lower().strip()
        for db_name, db_id in vulns.items():
            if vuln_name_lower in db_name or db_name in vuln_name_lower:
                vuln_id = db_id
                break

        if vuln_id is None:
            print(f"  [!] Could not match '{vuln_name}' to a vulnerability in SL#{sl_no}")
            continue

        eid = save_evaluation(
            sl_no=sl_no,
            vuln_id=vuln_id,
            evaluator=evaluator,
            evidence_cited=evidence,
            verdict=verdict,
            confidence=confidence,
            severity_correct=(severity_ok == "yes"),
            cve_correct=(cve_ok == "yes"),
            software_correct=(software_ok == "yes"),
            fix_correct=(fix_ok == "yes"),
            notes=notes
        )
        saved_ids.append(eid)
        print(f"  [+] Saved eval for '{vuln_name}' (vuln #{vuln_id}): {verdict} [{confidence}]")

    # Parse overall summary
    overall_risk = re.search(r'OVERALL_RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response_text, re.IGNORECASE)
    halluc_count = re.search(r'HALLUCINATION_COUNT:\s*(\d+)', response_text, re.IGNORECASE)
    accuracy_summary = re.search(r'ACCURACY_SUMMARY:\s*(.+?)(?:\n|$)', response_text, re.IGNORECASE)

    if overall_risk:
        print(f"  [*] Evaluator risk assessment: {overall_risk.group(1).upper()}")
    if halluc_count:
        print(f"  [*] Hallucinations found: {halluc_count.group(1)}")
    if accuracy_summary:
        print(f"  [*] Accuracy summary: {accuracy_summary.group(1).strip()}")

    return saved_ids


# ─────────────────────────────────────────────
# DISPLAY HELPERS
# ─────────────────────────────────────────────

def print_history(rows):
    print("\n" + "─"*65)
    print(f"{'SL#':<6} {'TARGET':<28} {'DATE':<22} {'STATUS'}")
    print("─"*65)
    for row in rows:
        print(f"{row[0]:<6} {row[1]:<28} {str(row[2]):<22} {row[3]}")
    print()


def print_session(data: dict):
    h = data["history"]
    print(f"\n{'═'*60}")
    print(f"  SL# {h[0]} | Target: {h[1]} | {h[2]} | {h[3]}")
    print(f"{'═'*60}")

    print("\n[ VULNERABILITIES ]")
    CONF_COLORS = {
        "confirmed":      "\033[91m",   # red — high certainty
        "likely":         "\033[93m",   # yellow
        "possible":       "\033[90m",   # gray
        "recommendation": "\033[36m",   # cyan
    }
    RESET = "\033[0m"
    if data["vulns"]:
        for v in data["vulns"]:
            # v: id, sl_no, vuln_name, severity, confidence, port, service, description
            conf = v[4] or "possible"
            cc = CONF_COLORS.get(conf, "")
            sev_label = f"Severity: {v[3]}" if v[3] != "info" else "INFO"
            print(f"  id={v[0]} | {v[2]} | {sev_label} | {cc}{conf}{RESET} | Port: {v[5]} | Service: {v[6]}")
            print(f"           {v[7]}")
    else:
        print("  None recorded.")

    print("\n[ FIXES ]")
    if data["fixes"]:
        for f in data["fixes"]:
            print(f"  id={f[0]} | vuln_id={f[2]} | [{f[4]}] {f[3]}")
    else:
        print("  None recorded.")

    print("\n[ EXPLOITS ATTEMPTED ]")
    if data["exploits"]:
        for e in data["exploits"]:
            print(f"  id={e[0]} | {e[2]} | Tool: {e[3]} | Result: {e[5]}")
            print(f"           Payload: {e[4]}")
            print(f"           Notes:   {e[6]}")
    else:
        print("  None recorded.")

    print("\n[ CORRECTIONS / HALLUCINATIONS ]")
    if data.get("corrections"):
        STATUS_COLORS = {
            "hallucination": "\033[91m",   # red
            "corrected":     "\033[93m",   # yellow
            "verified":      "\033[92m",   # green
            "downgraded":    "\033[33m",   # dark yellow
            "reclassified":  "\033[36m",   # cyan
        }
        RESET = "\033[0m"
        for cr in data["corrections"]:
            # cr: id, sl_no, vuln_id, status, original_text, corrected_text, reason, corrected_at
            sc = STATUS_COLORS.get(cr[3], "")
            print(f"  id={cr[0]} | vuln_id={cr[2]} | {sc}{cr[3].upper()}{RESET} | {cr[7]}")
            print(f"           Original : {cr[4]}")
            if cr[5]:
                print(f"           Corrected: {cr[5]}")
            print(f"           Reason   : {cr[6]}")
    else:
        print("  None recorded.")

    print("\n[ EVALUATIONS ]")
    if data.get("evaluations"):
        VERDICT_COLORS = {
            "valid":         "\033[92m",   # green
            "hallucination": "\033[91m",   # red
            "corrected":     "\033[93m",   # yellow
            "downgraded":    "\033[33m",   # dark yellow
            "reclassified":  "\033[36m",   # cyan
        }
        RESET = "\033[0m"
        for ev in data["evaluations"]:
            # ev: id, sl_no, vuln_id, evaluator, evidence_cited, verdict, confidence,
            #     severity_correct, cve_correct, software_correct, fix_correct, notes, evaluated_at
            vc = VERDICT_COLORS.get(ev[5], "")
            checks = []
            if ev[7]:  checks.append("sev")
            if ev[8]:  checks.append("cve")
            if ev[9]:  checks.append("sw")
            if ev[10]: checks.append("fix")
            check_str = ",".join(checks) if checks else "none"
            print(f"  id={ev[0]} | vuln_id={ev[2]} | {vc}{ev[5].upper()}{RESET} [{ev[6]}] | by: {ev[3]}")
            print(f"           Correct: {check_str} | {ev[12]}")
            if ev[11]:
                print(f"           Notes: {ev[11][:120]}")
    else:
        print("  None recorded.")

    print("\n[ SUMMARY ]")
    if data["summary"]:
        s = data["summary"]
        print(f"  Risk Level : {s[4]}")
        print(f"  Generated  : {s[5]}")
        print(f"\n  AI Analysis:\n  {s[3][:500]}{'...' if len(str(s[3])) > 500 else ''}")
    else:
        print("  None recorded.")
    print()


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
