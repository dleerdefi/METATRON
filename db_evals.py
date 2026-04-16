#!/usr/bin/env python3
"""
METATRON - db_evals.py
Evaluation CRUD, eval package export, and evaluation response parser.
"""

import re
import os
from datetime import datetime
from db import get_connection, save_correction
from prompts import EVAL_RUBRIC, DISTILLATION_PROMPT


# ─────────────────────────────────────────────
# EVALUATIONS CRUD
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
# EVAL PACKAGE EXPORT
# ─────────────────────────────────────────────

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

    c.execute("SELECT * FROM history WHERE sl_no = %s", (sl_no,))
    history = c.fetchone()
    if not history:
        conn.close()
        print(f"[!] Session SL#{sl_no} not found.")
        return ""

    target = history[1]
    scan_date = str(history[2])

    c.execute("SELECT raw_scan, ai_analysis, risk_level, model_name FROM summary WHERE sl_no = %s", (sl_no,))
    summary = c.fetchone()
    if not summary:
        conn.close()
        print(f"[!] No summary found for SL#{sl_no}.")
        return ""

    raw_scan, ai_analysis, risk_level, model_name = summary

    c.execute("SELECT * FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vulns = c.fetchall()

    c.execute("SELECT * FROM fixes WHERE sl_no = %s", (sl_no,))
    fixes = c.fetchall()

    c.execute("SELECT * FROM corrections WHERE sl_no = %s", (sl_no,))
    corrections = c.fetchall()

    c.execute("SELECT * FROM evaluations WHERE sl_no = %s", (sl_no,))
    evaluations = c.fetchall()

    conn.close()

    # Build fix lookup
    fix_map = {}
    for f in fixes:
        fix_map.setdefault(f[2], []).append(f[3])

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

    lines.append(f"---")
    lines.append(f"## 2. AI VULNERABILITY FINDINGS")
    lines.append(f"")
    for v in vulns:
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

    if evaluations:
        lines.append(f"---")
        lines.append(f"## 4. PRIOR EVALUATIONS")
        lines.append(f"")
        for ev in evaluations:
            lines.append(f"- **Vuln #{ev[2]}** — Evaluator: {ev[3]} | Verdict: {ev[5]} | Confidence: {ev[6]}")
            lines.append(f"  - Evidence: {ev[4]}")
            lines.append(f"  - Notes: {ev[11]}")
            lines.append(f"")

    lines.append(f"---")
    lines.append(EVAL_RUBRIC)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    safe_target = target.replace("https://","").replace("http://","").replace("/","_").replace(".","_")
    filename = os.path.join(output_dir, f"eval_SL{sl_no}_{safe_target}_{timestamp}.md")
    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Eval package exported: {filename}")
    return filename


# ─────────────────────────────────────────────
# EVAL RESPONSE PARSER
# ─────────────────────────────────────────────

def parse_evaluation_response(sl_no: int, evaluator: str, response_text: str) -> list:
    """
    Parse an external evaluator's response and save evaluations to the database.
    Returns list of saved evaluation IDs.
    """
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, vuln_name, severity, confidence, description FROM vulnerabilities WHERE sl_no = %s", (sl_no,))
    vuln_rows = c.fetchall()
    conn.close()

    # Build lookup maps
    vulns = {row[1].lower().strip(): row[0] for row in vuln_rows}
    vuln_details = {row[0]: row for row in vuln_rows}  # id -> (id, name, severity, confidence, desc)

    saved_ids = []
    corrections_created = 0
    blocks = re.split(r'(?=EVAL:)', response_text, flags=re.IGNORECASE)

    for block in blocks:
        block = block.strip()
        if not block.upper().startswith("EVAL:"):
            continue

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
            sl_no=sl_no, vuln_id=vuln_id, evaluator=evaluator,
            evidence_cited=evidence, verdict=verdict, confidence=confidence,
            severity_correct=(severity_ok == "yes"), cve_correct=(cve_ok == "yes"),
            software_correct=(software_ok == "yes"), fix_correct=(fix_ok == "yes"),
            notes=notes
        )
        saved_ids.append(eid)
        print(f"  [+] Saved eval for '{vuln_name}' (vuln #{vuln_id}): {verdict} [{confidence}]")

        # Auto-generate correction from non-valid verdicts
        # This bridges evaluations → corrections → future prompt injection
        if verdict in ("hallucination", "corrected", "downgraded", "reclassified"):
            vd = vuln_details.get(vuln_id)
            if vd:
                original = f"[{vd[2]}] {vd[1]}: {vd[4][:200] if vd[4] else ''}"
                reason_parts = [f"External eval by {evaluator} [{confidence} confidence]"]
                if notes:
                    reason_parts.append(notes[:300])
                if evidence:
                    reason_parts.append(f"Evidence: {evidence[:200]}")
                reason = " | ".join(reason_parts)
                save_correction(sl_no, vuln_id, verdict, original, "", reason)
                corrections_created += 1

    if corrections_created:
        print(f"  [+] Auto-created {corrections_created} correction(s) from evaluation verdicts")

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
# LEARNED RULES — distilled from corrections
# ─────────────────────────────────────────────

def save_learned_rule(rule_text: str, source: str) -> int:
    """Save a single distilled rule."""
    conn = get_connection()
    c = conn.cursor()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    c.execute("""
        INSERT INTO learned_rules (rule_text, source, created_at)
        VALUES (%s, %s, %s)
    """, (rule_text, source, now))
    conn.commit()
    rid = c.lastrowid
    conn.close()
    return rid


def get_learned_rules():
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT id, rule_text, source, created_at FROM learned_rules ORDER BY id")
    rows = c.fetchall()
    conn.close()
    return rows


def clear_learned_rules():
    """Remove all learned rules (before importing a fresh distillation)."""
    conn = get_connection()
    c = conn.cursor()
    c.execute("DELETE FROM learned_rules")
    conn.commit()
    conn.close()


def export_distillation_package(output_dir: str = None) -> str:
    """
    Export all raw corrections as a distillation package for an external LLM.
    The external LLM reads this and outputs compact RULE: lines.
    Returns the output file path.
    """
    if output_dir is None:
        output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "evals")
    os.makedirs(output_dir, exist_ok=True)

    conn = get_connection()
    c = conn.cursor()

    c.execute("""
        SELECT c.status, c.reason, v.vuln_name, v.severity, h.target, c.corrected_at
        FROM corrections c
        JOIN vulnerabilities v ON c.vuln_id = v.id
        JOIN history h ON c.sl_no = h.sl_no
        ORDER BY c.corrected_at DESC
    """)
    corrections = c.fetchall()

    c.execute("SELECT id, rule_text, source, created_at FROM learned_rules ORDER BY id")
    existing_rules = c.fetchall()

    conn.close()

    if not corrections:
        print("[!] No corrections in database. Nothing to distill.")
        return ""

    lines = []
    lines.append("# METATRON Rule Distillation Package")
    lines.append("")
    lines.append(f"**Total corrections to distill:** {len(corrections)}")
    lines.append(f"**Existing learned rules:** {len(existing_rules)}")
    lines.append("")

    # Section 1: Existing rules (so the reviewer can update/refine them)
    if existing_rules:
        lines.append("---")
        lines.append("## CURRENT LEARNED RULES")
        lines.append("These rules were distilled from a previous review. Update, refine, or replace as needed.")
        lines.append("")
        for r in existing_rules:
            lines.append(f"RULE: {r[1]}  (source: {r[2]}, {r[3]})")
        lines.append("")

    # Section 2: Raw corrections
    lines.append("---")
    lines.append("## RAW CORRECTIONS")
    lines.append("")
    for status, reason, vuln_name, severity, target, corrected_at in corrections:
        lines.append(f"[{status.upper()}] {vuln_name} ({severity}) — target: {target}")
        lines.append(f"  Reason: {reason}")
        lines.append("")

    # Section 3: Distillation instructions
    lines.append("---")
    lines.append(DISTILLATION_PROMPT)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = os.path.join(output_dir, f"distill_{timestamp}.md")
    with open(filename, "w") as f:
        f.write("\n".join(lines))

    print(f"[+] Distillation package exported: {filename}")
    return filename


def import_distilled_rules(source: str, response_text: str) -> list:
    """
    Parse RULE: lines from an external LLM's distillation response.
    Replaces all existing learned rules with the new set.
    Returns list of saved rule IDs.
    """
    rules = re.findall(r'RULE:\s*(.+?)(?:\n|$)', response_text, re.IGNORECASE)

    if not rules:
        print("[!] No RULE: lines found in response.")
        return []

    # Replace existing rules with the fresh distillation
    clear_learned_rules()
    print(f"[*] Cleared previous learned rules.")

    saved_ids = []
    for rule_text in rules:
        rule_text = rule_text.strip()
        if not rule_text or len(rule_text) < 10:
            continue
        rid = save_learned_rule(rule_text, source)
        saved_ids.append(rid)
        print(f"  [+] Rule #{rid}: {rule_text[:80]}")

    print(f"[+] Imported {len(saved_ids)} learned rule(s) from {source}")
    return saved_ids
