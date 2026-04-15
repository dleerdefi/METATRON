#!/usr/bin/env python3
"""
METATRON - metatron.py
Main CLI entry point. Wires db.py + tools.py + search.py + llm.py together.
Run with: python metatron.py
"""
from export import export_menu
import os
import sys
from db import (
    get_connection,
    create_session,
    save_vulnerability,
    save_fix,
    save_exploit,
    save_summary,
    save_correction,
    get_all_history,
    get_session,
    get_vulnerabilities,
    get_fixes,
    get_exploits,
    get_corrections,
    get_evaluations,
    edit_vulnerability,
    edit_fix,
    edit_exploit,
    edit_summary_risk,
    edit_correction,
    delete_vulnerability,
    delete_exploit,
    delete_fix,
    delete_correction,
    delete_evaluation,
    delete_full_session,
    export_training_data,
    export_eval_package,
    parse_evaluation_response,
    print_history,
    print_session
)
from tools import interactive_tool_run, format_recon_for_llm, run_default_recon
from llm import analyse_target


# ─────────────────────────────────────────────
# BANNER
# ─────────────────────────────────────────────

def banner():
    os.system("clear")
    print("""
\033[91m
    ███╗   ███╗███████╗████████╗ █████╗ ████████╗██████╗  ██████╗ ███╗   ██╗
    ████╗ ████║██╔════╝╚══██╔══╝██╔══██╗╚══██╔══╝██╔══██╗██╔═══██╗████╗  ██║
    ██╔████╔██║█████╗     ██║   ███████║   ██║   ██████╔╝██║   ██║██╔██╗ ██║
    ██║╚██╔╝██║██╔══╝     ██║   ██╔══██║   ██║   ██╔══██╗██║   ██║██║╚██╗██║
    ██║ ╚═╝ ██║███████╗   ██║   ██║  ██║   ██║   ██║  ██║╚██████╔╝██║ ╚████║
    ╚═╝     ╚═╝╚══════╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝
\033[0m
    \033[90mAI Penetration Testing Assistant  |  LM Studio  |  Kali Linux\033[0m
    \033[90m─────────────────────────────────────────────────────────────────────\033[0m
""")


# ─────────────────────────────────────────────
# HELPERS
# ─────────────────────────────────────────────

def divider(label=""):
    if label:
        print(f"\n\033[33m{'─'*20} {label} {'─'*20}\033[0m")
    else:
        print(f"\033[90m{'─'*60}\033[0m")


def prompt(text):
    return input(f"\033[36m{text}\033[0m").strip()


def success(text):
    print(f"\033[92m[+] {text}\033[0m")


def warn(text):
    print(f"\033[93m[!] {text}\033[0m")


def error(text):
    print(f"\033[91m[✗] {text}\033[0m")


def info(text):
    print(f"\033[94m[*] {text}\033[0m")


def confirm(question: str) -> bool:
    ans = prompt(f"{question} [y/N]: ").lower()
    return ans == "y"


# ─────────────────────────────────────────────
# NEW SCAN
# ─────────────────────────────────────────────

def new_scan():
    divider("NEW SCAN")
    target = prompt("[?] Enter target IP or domain: ")
    if not target:
        warn("No target entered.")
        return

    # check if target was scanned before
    history = get_all_history()
    past = [row for row in history if row[1] == target]
    if past:
        warn(f"Target '{target}' has been scanned before ({len(past)} time(s)).")
        if not confirm("Continue with a new scan?"):
            return

    # create session in history table first
    sl_no = create_session(target)
    success(f"Session created — SL# {sl_no}")

    # run recon tools
    divider("RECON")
    info("Choose recon tools to run:")
    raw_scan = interactive_tool_run(target)

    if not raw_scan.strip():
        warn("No scan data collected. Aborting.")
        delete_full_session(sl_no)
        return

    # send to AI
    divider("AI ANALYSIS")
    result = analyse_target(target, raw_scan)

    # ── save everything to DB ──────────────────
    divider("SAVING TO DATABASE")

    # save vulnerabilities and their fixes
    vuln_id_map = {}  # vuln_name -> db id, for linking review flags
    for vuln in result["vulnerabilities"]:
        vuln_id = save_vulnerability(
            sl_no,
            vuln["vuln_name"],
            vuln["severity"],
            vuln["port"],
            vuln["service"],
            vuln["description"],
            confidence=vuln.get("confidence", "possible")
        )
        vuln_id_map[vuln["vuln_name"]] = vuln_id
        if vuln.get("fix"):
            save_fix(sl_no, vuln_id, vuln["fix"], source="ai")
        success(f"Saved vuln: {vuln['vuln_name']} [{vuln['severity']}] [{vuln.get('confidence', 'possible')}]")

    # save recommendations (as info-severity entries)
    for rec in result.get("recommendations", []):
        rec_id = save_vulnerability(
            sl_no,
            rec["vuln_name"],
            "info",
            rec.get("port", ""),
            rec.get("service", ""),
            rec["description"],
            confidence="recommendation"
        )
        success(f"Saved rec: {rec['vuln_name']}")

    # auto-save self-review flags as corrections (with evidence)
    for vuln in result["vulnerabilities"]:
        flag = vuln.get("_review_flag")
        if flag and flag != "valid" and vuln["vuln_name"] in vuln_id_map:
            vid = vuln_id_map[vuln["vuln_name"]]
            original = f"[{vuln['severity']}] {vuln['vuln_name']}: {vuln['description']}"
            corrected = vuln.get("_review_corrected", "")
            issue = vuln.get("_review_issue", "")
            evidence = vuln.get("_review_evidence", "")
            reason_parts = ["Auto-flagged by self-review"]
            if issue:
                reason_parts.append(f"Issue: {issue}")
            if evidence:
                reason_parts.append(f"Evidence: {evidence}")
            reason = " | ".join(reason_parts)
            save_correction(
                sl_no, vid, flag, original, corrected, reason
            )
            warn(f"Self-review flagged: {vuln['vuln_name']} [{flag}]")

    # save exploits
    for exp in result["exploits"]:
        save_exploit(
            sl_no,
            exp["exploit_name"],
            exp["tool_used"],
            exp["payload"],
            exp["result"],
            exp["notes"]
        )
        success(f"Saved exploit: {exp['exploit_name']}")

    # save summary
    from config import MODEL_NAME
    save_summary(
        sl_no,
        result["raw_scan"],
        result["full_response"],
        result["risk_level"],
        model_name=MODEL_NAME
    )

    success(f"All data saved. SL# {sl_no} | Risk: {result['risk_level']}")
    divider()

    # show results and offer edit/delete
    data = get_session(sl_no)
    print_session(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# VIEW HISTORY
# ─────────────────────────────────────────────

def view_history():
    divider("SCAN HISTORY")
    rows = get_all_history()

    if not rows:
        warn("No scans in database yet.")
        return

    print_history(rows)

    sl_no_str = prompt("Enter SL# to view details (or press Enter to go back): ")
    if not sl_no_str:
        return

    try:
        sl_no = int(sl_no_str)
    except ValueError:
        error("Invalid SL#.")
        return

    data = get_session(sl_no)
    if not data["history"]:
        error(f"SL# {sl_no} not found.")
        return

    print_session(data)

    if confirm("Export this session?"):
        export_menu(data)

    if confirm("Edit or delete anything in this session?"):
        edit_delete_menu(sl_no)


# ─────────────────────────────────────────────
# EDIT / DELETE MENU
# ─────────────────────────────────────────────

def edit_delete_menu(sl_no: int):
    while True:
        divider(f"EDIT / DELETE — SL# {sl_no}")
        print("  [1]  Edit a vulnerability")
        print("  [2]  Edit a fix")
        print("  [3]  Edit an exploit")
        print("  [4]  Edit risk level")
        print("  [5]  Delete a vulnerability")
        print("  [6]  Delete a fix")
        print("  [7]  Delete an exploit")
        print("  [8]  Add a correction / hallucination record")
        print("  [9]  Edit a correction")
        print("  [10] Delete a correction")
        print("  [11] Delete FULL session (all tables)")
        print("  [12] Back")
        divider()

        choice = prompt("Choice: ")

        # ── EDIT VULNERABILITY ─────────────────
        if choice == "1":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities recorded for this session.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to edit: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: vuln_name / severity / confidence / port / service / description")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_vulnerability(int(vid), field, value)

        # ── EDIT FIX ──────────────────────────
        elif choice == "2":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes recorded for this session.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to edit: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            new_text = prompt("New fix text: ")
            edit_fix(int(fid), new_text)

        # ── EDIT EXPLOIT ──────────────────────
        elif choice == "3":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits recorded for this session.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | tool: {e[3]} | result: {e[5]}")

            eid = prompt("Enter exploit id to edit: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: exploit_name / tool_used / payload / result / notes")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_exploit(int(eid), field, value)

        # ── EDIT RISK LEVEL ───────────────────
        elif choice == "4":
            print("  Options: CRITICAL / HIGH / MEDIUM / LOW")
            risk = prompt("New risk level: ").upper()
            if risk not in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                error("Invalid risk level.")
                continue
            edit_summary_risk(sl_no, risk)

        # ── DELETE VULNERABILITY ──────────────
        elif choice == "5":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to delete.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]}")

            vid = prompt("Enter vulnerability id to delete: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete vulnerability id={vid} and its linked fixes?"):
                delete_vulnerability(int(vid))

        # ── DELETE FIX ────────────────────────
        elif choice == "6":
            fixes = get_fixes(sl_no)
            if not fixes:
                warn("No fixes to delete.")
                continue

            print("\n[ FIXES ]")
            for f in fixes:
                print(f"  id={f[0]} | vuln_id={f[2]} | {f[3][:80]}")

            fid = prompt("Enter fix id to delete: ")
            if not fid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete fix id={fid}?"):
                delete_fix(int(fid))

        # ── DELETE EXPLOIT ────────────────────
        elif choice == "7":
            exploits = get_exploits(sl_no)
            if not exploits:
                warn("No exploits to delete.")
                continue

            print("\n[ EXPLOITS ]")
            for e in exploits:
                print(f"  id={e[0]} | {e[2]} | result: {e[5]}")

            eid = prompt("Enter exploit id to delete: ")
            if not eid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete exploit id={eid}?"):
                delete_exploit(int(eid))

        # ── ADD CORRECTION ────────────────────
        elif choice == "8":
            vulns = get_vulnerabilities(sl_no)
            if not vulns:
                warn("No vulnerabilities to correct.")
                continue

            print("\n[ VULNERABILITIES ]")
            for v in vulns:
                print(f"  id={v[0]} | {v[2]} | {v[3]} | port {v[4]} | {v[5]}")

            vid = prompt("Enter vulnerability id to correct: ")
            if not vid.isdigit():
                error("Invalid id.")
                continue

            # find the vuln for original text
            target_vuln = None
            for v in vulns:
                if v[0] == int(vid):
                    target_vuln = v
                    break
            if not target_vuln:
                error(f"Vulnerability id={vid} not found.")
                continue

            print("  Status options: hallucination / corrected / verified / downgraded / reclassified")
            status = prompt("Correction status: ").strip().lower()
            if status not in ("hallucination", "corrected", "verified", "downgraded", "reclassified"):
                error("Invalid status.")
                continue

            original = f"[{target_vuln[3]}] {target_vuln[2]}: {target_vuln[6]}"
            corrected = ""
            if status != "hallucination":
                corrected = prompt("Corrected finding (leave blank if N/A): ")
            reason = prompt("Reason / evidence: ")

            save_correction(sl_no, int(vid), status, original, corrected, reason)

        # ── EDIT CORRECTION ──────────────────
        elif choice == "9":
            corrections = get_corrections(sl_no)
            if not corrections:
                warn("No corrections recorded for this session.")
                continue

            print("\n[ CORRECTIONS ]")
            for cr in corrections:
                print(f"  id={cr[0]} | vuln_id={cr[2]} | {cr[3]} | {cr[6][:60]}")

            cid = prompt("Enter correction id to edit: ")
            if not cid.isdigit():
                error("Invalid id.")
                continue

            print("  Fields: status / original_text / corrected_text / reason")
            field = prompt("Field to edit: ").strip()
            value = prompt(f"New value for '{field}': ")
            edit_correction(int(cid), field, value)

        # ── DELETE CORRECTION ────────────────
        elif choice == "10":
            corrections = get_corrections(sl_no)
            if not corrections:
                warn("No corrections to delete.")
                continue

            print("\n[ CORRECTIONS ]")
            for cr in corrections:
                print(f"  id={cr[0]} | vuln_id={cr[2]} | {cr[3]} | {cr[6][:60]}")

            cid = prompt("Enter correction id to delete: ")
            if not cid.isdigit():
                error("Invalid id.")
                continue

            if confirm(f"Delete correction id={cid}?"):
                delete_correction(int(cid))

        # ── DELETE FULL SESSION ───────────────
        elif choice == "11":
            if confirm(f"\n\033[91mPermanently delete ENTIRE session SL# {sl_no} from all tables?\033[0m"):
                delete_full_session(sl_no)
                success(f"Session SL# {sl_no} wiped.")
                return   # go back to main menu

        # ── BACK ──────────────────────────────
        elif choice == "12":
            break

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# DB CONNECTION CHECK
# ─────────────────────────────────────────────

def check_db():
    try:
        conn = get_connection()
        conn.close()
        return True
    except Exception as e:
        error(f"MariaDB connection failed: {e}")
        error("Make sure MariaDB is running: sudo systemctl start mariadb")
        return False


# ─────────────────────────────────────────────
# MAIN MENU
# ─────────────────────────────────────────────

def main_menu():
    while True:
        banner()
        print("  \033[92m[1]\033[0m  New Scan")
        print("  \033[92m[2]\033[0m  View History")
        print("  \033[92m[3]\033[0m  Export Eval Package")
        print("  \033[92m[4]\033[0m  Import Evaluation")
        print("  \033[92m[5]\033[0m  Export Training Data")
        print("  \033[92m[6]\033[0m  Exit")
        divider()

        choice = prompt("metatron> ")

        if choice == "1":
            new_scan()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "2":
            view_history()
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "3":
            divider("EXPORT EVAL PACKAGE")
            info("Exports a scan session as a review package for external LLM evaluation.")
            rows = get_all_history()
            if not rows:
                warn("No scans in database yet.")
            else:
                print_history(rows)
                sl_str = prompt("Enter SL# to export: ")
                if sl_str.isdigit():
                    path = export_eval_package(int(sl_str))
                    if path:
                        success(f"Eval package ready: {path}")
                        info("Paste the contents into Claude Code or another LLM for review.")
                        info("Then use [4] Import Evaluation to store the response.")
                else:
                    error("Invalid SL#.")
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "4":
            divider("IMPORT EVALUATION")
            info("Paste an external LLM's evaluation response to store it.")
            sl_str = prompt("Enter SL# this evaluation is for: ")
            if not sl_str.isdigit():
                error("Invalid SL#.")
            else:
                sl_no = int(sl_str)
                evaluator = prompt("Evaluator name (e.g., claude-opus-4-6, gpt-5-4): ")
                if not evaluator:
                    evaluator = "unknown"
                print("\nPaste the evaluation response below.")
                print("When done, enter a line with just 'END' to finish.\n")
                response_lines = []
                while True:
                    line = input()
                    if line.strip() == "END":
                        break
                    response_lines.append(line)
                response_text = "\n".join(response_lines)
                if response_text.strip():
                    saved = parse_evaluation_response(sl_no, evaluator, response_text)
                    if saved:
                        success(f"Saved {len(saved)} evaluation(s) for SL#{sl_no}")
                    else:
                        warn("No evaluations could be parsed from the response.")
                else:
                    warn("Empty response. Nothing saved.")
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "5":
            divider("EXPORT TRAINING DATA")
            info("Exports corrected sessions as JSONL for fine-tuning.")
            info("Only sessions with corrections are included.")
            path = export_training_data()
            if path:
                success(f"Training data ready: {path}")
            input("\n\033[90mPress Enter to continue...\033[0m")

        elif choice == "6":
            print("\n\033[91m[*] Shutting down Metatron. Stay legal.\033[0m\n")
            sys.exit(0)

        else:
            warn("Invalid choice.")


# ─────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────

if __name__ == "__main__":
    if not check_db():
        sys.exit(1)
    main_menu()
