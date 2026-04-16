#!/usr/bin/env python3
"""
METATRON - db_training.py
Training data export for fine-tuning from corrected sessions.
"""

import json
import os
from datetime import datetime
from db import get_connection


def export_training_data(output_dir: str = None) -> str:
    """
    Export all sessions that have corrections as JSONL training pairs.
    Each line is a JSON object with:
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
                    continue
                elif corr["status"] in ("corrected", "downgraded", "reclassified"):
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
                    corrected_vulns.append({
                        "vuln_name": vuln_name,
                        "severity": severity,
                        "port": port,
                        "service": service,
                        "description": description,
                        "correction_applied": "verified"
                    })
            else:
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
