#!/usr/bin/env python3
"""
METATRON - llm.py
LM Studio interface (OpenAI-compatible API).
Builds prompts, handles AI responses, runs tool dispatch loop.
"""

import re
import requests
import json
import os
from datetime import datetime
from tools import run_tool_by_command, run_nmap, run_curl_headers
from search import handle_search_dispatch
from config import LLM_URL, LLM_MODELS_URL, LLM_BASE_URL, MODEL_NAME, MAX_TOKENS, TOP_K, MAX_TOOL_LOOPS, LLM_TIMEOUT
from prompts import SYSTEM_PROMPT, REVIEW_PROMPT, STATUS_LABELS

# ─────────────────────────────────────────────
# CORRECTION FEEDBACK LOOP
# ─────────────────────────────────────────────

def load_correction_rules() -> str:
    """
    Load learned rules for injection into the system prompt.

    Priority: learned_rules table (distilled by external LLM) > raw corrections.
    If distilled rules exist, use those — they're compact and fit in context.
    If no distilled rules exist, fall back to a lightweight summary of raw corrections.
    """
    try:
        from db import get_connection
        conn = get_connection()
        c = conn.cursor()

        # Try learned rules first (distilled by external LLM)
        c.execute("SELECT rule_text FROM learned_rules ORDER BY id")
        rules = c.fetchall()

        if rules:
            conn.close()
            lines = [
                "",
                "LEARNED RULES (distilled from past correction reviews):",
                "These rules are verified. Follow them strictly.",
                ""
            ]
            for (rule_text,) in rules:
                lines.append(f"  - {rule_text}")
            return "\n".join(lines)

        # Fallback: lightweight summary from raw corrections
        c.execute("""
            SELECT c.status, COUNT(*) as cnt,
                   GROUP_CONCAT(DISTINCT LEFT(c.reason, 80) SEPARATOR ' | ')
            FROM corrections c
            GROUP BY c.status
            HAVING c.status != 'verified'
            ORDER BY cnt DESC
        """)
        summaries = c.fetchall()
        conn.close()

        if not summaries:
            return ""

        lines = [
            "",
            "PAST ERRORS (no distilled rules yet — run Distill Rules for better results):",
            ""
        ]
        for status, count, reasons in summaries:
            label = STATUS_LABELS.get(status, status.upper())
            # Take just the first reason as an example
            example = reasons.split(" | ")[0] if reasons else ""
            lines.append(f"  [{label}] ({count}x) e.g.: {example[:100]}")

        return "\n".join(lines)

    except Exception:
        return ""


def build_system_prompt() -> str:
    """
    Build the full system prompt by combining the base prompt
    with any learned corrections from the database.
    """
    correction_rules = load_correction_rules()
    if correction_rules:
        return SYSTEM_PROMPT + "\n" + correction_rules
    return SYSTEM_PROMPT


# ─────────────────────────────────────────────
# SELF-REVIEW PASS
# ─────────────────────────────────────────────

def self_review(raw_scan: str, ai_analysis: str, correction_rules: str) -> dict:
    """
    Run a self-review pass on the AI analysis to catch errors
    before they get saved to the database.
    Returns dict with reviews and adjusted risk level.
    """
    messages = [
        {"role": "system", "content": REVIEW_PROMPT},
        {"role": "user", "content": f"""RAW SCAN DATA:
{raw_scan[:8000]}

AI ANALYSIS TO REVIEW:
{ai_analysis[:6000]}

{correction_rules if correction_rules else "No prior correction history available."}

Review each vulnerability finding. Be thorough."""}
    ]

    print("\n[*] Running self-review pass...")
    response = ask_llm(messages)

    if response.startswith("[!]"):
        print(f"  [!] Self-review failed: {response}")
        return {"review": "", "adjusted_risk": "", "flags": []}

    print(f"\n{'─'*60}")
    print("[METATRON - Self-Review]")
    print(f"{'─'*60}")
    print(response)

    # Parse review verdicts with evidence and issue details
    flags = []

    # Split response into blocks per REVIEW: line
    blocks = re.split(r'(?=REVIEW:)', response, flags=re.IGNORECASE)
    for block in blocks:
        block = block.strip()
        match = re.match(r'REVIEW:\s*(.+?)\s*\|\s*VERDICT:\s*(\w+)', block, re.IGNORECASE)
        if not match:
            continue

        vuln_name = match.group(1).strip()
        verdict = match.group(2).strip().lower()

        # Extract EVIDENCE and ISSUE fields from the block
        evidence_match = re.search(r'EVIDENCE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        issue_match = re.search(r'ISSUE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        corrected_match = re.search(r'CORRECTED:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)

        evidence = evidence_match.group(1).strip() if evidence_match else ""
        issue = issue_match.group(1).strip() if issue_match else ""
        corrected = corrected_match.group(1).strip() if corrected_match else ""

        flag = {
            "vuln_name": vuln_name,
            "verdict": verdict,
            "evidence": evidence,
            "issue": issue,
            "corrected": corrected
        }
        flags.append(flag)

    adjusted_risk = ""
    risk_match = re.search(
        r'ADJUSTED_RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)',
        response, re.IGNORECASE
    )
    if risk_match:
        adjusted_risk = risk_match.group(1).upper()

    flagged = [f for f in flags if f["verdict"] != "valid"]
    if flagged:
        print(f"\n[!] Self-review flagged {len(flagged)} finding(s):")
        for f in flagged:
            print(f"    - {f['vuln_name']}: {f['verdict']}")
            if f["issue"]:
                print(f"      Issue: {f['issue'][:100]}")
    else:
        print("\n[+] Self-review: all findings appear valid.")

    if adjusted_risk:
        print(f"[*] Adjusted risk level: {adjusted_risk}")

    return {
        "review": response,
        "adjusted_risk": adjusted_risk,
        "flags": flags
    }


# ─────────────────────────────────────────────
# OLLAMA API CALL
# ─────────────────────────────────────────────

def ask_llm(messages: list) -> str:
    try:
        payload = {
            "model":  MODEL_NAME,
            "messages": messages,
            "stream": False,
            "max_tokens": MAX_TOKENS,
            "temperature": 0.7,
            "top_k": TOP_K,
            "top_p": 0.9,
        }
        headers = {"Content-Type": "application/json"}
        print(f"\n[*] Sending to {MODEL_NAME}...")
        resp = requests.post(LLM_URL, json=payload, headers=headers, timeout=LLM_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        msg = data["choices"][0]["message"]
        response = (msg.get("content") or "").strip()
        if not response:
            # Qwen 3.5 thinking models may put all output in reasoning_content
            response = (msg.get("reasoning_content") or "").strip()
        if not response:
            return "[!] Model returned empty response."
        return response
    except requests.exceptions.ConnectionError:
        return f"[!] Cannot connect to LM Studio at {LLM_BASE_URL}. Is it running?"
    except requests.exceptions.Timeout:
        return f"[!] LLM timed out. Model may be loading, try again."
    except requests.exceptions.HTTPError as e:
        return f"[!] LLM HTTP error: {e}"
    except Exception as e:
        return f"[!] Unexpected error: {e}"


# ─────────────────────────────────────────────
# TOOL DISPATCH
# ─────────────────────────────────────────────

def extract_tool_calls(response: str) -> list:
    """
    Extract all [TOOL: ...] and [SEARCH: ...] tags from AI response.
    Returns list of tuples: [("TOOL", "nmap -sV x.x.x.x"), ("SEARCH", "CVE...")]
    """
    calls = []

    tool_matches   = re.findall(r'\[TOOL:\s*(.+?)\]',   response)
    search_matches = re.findall(r'\[SEARCH:\s*(.+?)\]', response)

    for m in tool_matches:
        calls.append(("TOOL", m.strip()))
    for m in search_matches:
        calls.append(("SEARCH", m.strip()))

    return calls

def summarize_tool_output(raw_output: str) -> str:
    """
    Compress raw tool output into security-relevant bullet points
    before injecting into the LLM context.
    Keeps context size manageable across rounds.
    """
    if len(raw_output) < 500:
        return raw_output

    try:
        payload = {
            "model":  MODEL_NAME,
            "messages": [
    {"role": "system", "content": "You are a security data compressor. Extract only security-relevant facts. Return maximum 15 bullet points. Plain text only. No markdown."},
    {"role": "user", "content": f"Compress this tool output:\n{raw_output[:6000]}"} ],
            "stream": False,
            "max_tokens": 512,
            "temperature": 0.2,
            "top_k": TOP_K,
            "top_p": 0.9,
        }
        headers = {"Content-Type": "application/json"}
        resp = requests.post(LLM_URL, json=payload, headers=headers, timeout=120)
        resp.raise_for_status()
        msg = resp.json()["choices"][0]["message"]
        summary = (msg.get("content") or msg.get("reasoning_content") or "").strip()
        return summary if summary else raw_output
    except Exception:
        return raw_output
def run_tool_calls(calls: list) -> str:
    """
    Execute all tool/search calls and return combined results string.
    """
    if not calls:
        return ""

    results = ""
    for call_type, call_content in calls:
        print(f"\n  [DISPATCH] {call_type}: {call_content}")

        if call_type == "TOOL":
            output = run_tool_by_command(call_content)
        elif call_type == "SEARCH":
            output = handle_search_dispatch(call_content)
        else:
            output = f"[!] Unknown call type: {call_type}"

        compressed = summarize_tool_output(output.strip())
        results += f"\n[{call_type} RESULT: {call_content}]\n"
        results += "─" * 40 + "\n"
        results += compressed + "\n"

    return results


# ─────────────────────────────────────────────
# PARSER — imported from parsers.py
# ─────────────────────────────────────────────
from parsers import (parse_vulnerabilities, parse_recommendations,
                     parse_exploits, parse_risk_level, parse_summary)


# ─────────────────────────────────────────────
# MAIN ANALYSIS FUNCTION
# ─────────────────────────────────────────────

def analyse_target(target: str, raw_scan: str) -> dict:
    # Build system prompt with learned corrections injected
    system_prompt = build_system_prompt()
    correction_rules = load_correction_rules()

    if correction_rules:
        print(f"[+] Loaded correction history into system prompt.")

    messages = [
        {
            "role": "system",
            "content": system_prompt
        },
        {
            "role": "user",
            "content": f"""TARGET: {target}

RECON DATA:
{raw_scan}

Analyze this target completely. Use [TOOL:] or [SEARCH:] if you need more information.
List all vulnerabilities, fixes, and suggest exploits where applicable."""
        }
    ]

    final_response = ""

    for loop in range(MAX_TOOL_LOOPS):
        response = ask_llm(messages)

        print(f"\n{'─'*60}")
        print(f"[METATRON - Round {loop + 1}]")
        print(f"{'─'*60}")
        print(response)

        final_response = response

        tool_calls = extract_tool_calls(response)
        if not tool_calls:
            print("\n[*] No tool calls. Analysis complete.")
            break

        tool_results = run_tool_calls(tool_calls)

        # add assistant response and tool results as new messages
        messages.append({
            "role": "assistant",
            "content": response
        })
        messages.append({
            "role": "user",
            "content": f"""[TOOL RESULTS]
{tool_results}

Continue your analysis with this new information.
If analysis is complete, give the final RISK_LEVEL and SUMMARY."""
        })

    # ── SELF-REVIEW PASS ──────────────────────
    review_result = self_review(raw_scan, final_response, correction_rules)

    vulnerabilities    = parse_vulnerabilities(final_response)
    recommendations    = parse_recommendations(final_response)
    exploits           = parse_exploits(final_response)
    risk_level         = parse_risk_level(final_response)
    summary            = parse_summary(final_response)

    # If self-review adjusted the risk level, use it
    if review_result["adjusted_risk"]:
        original_risk = risk_level
        risk_level = review_result["adjusted_risk"]
        if original_risk != risk_level:
            print(f"[*] Risk adjusted by self-review: {original_risk} → {risk_level}")

    print(f"\n[+] Parsed: {len(vulnerabilities)} vulns, {len(recommendations)} recs, {len(exploits)} exploits | Risk: {risk_level}")

    # Tag flagged findings (vulns AND recommendations) for database marking
    flagged_map = {}
    for f in review_result["flags"]:
        flagged_map[f["vuln_name"].lower()] = f
    for finding in vulnerabilities + recommendations:
        name_lower = finding["vuln_name"].lower()
        for flagged_name, flag_data in flagged_map.items():
            if flagged_name in name_lower or name_lower in flagged_name:
                finding["_review_flag"] = flag_data["verdict"]
                finding["_review_evidence"] = flag_data.get("evidence", "")
                finding["_review_issue"] = flag_data.get("issue", "")
                finding["_review_corrected"] = flag_data.get("corrected", "")
                break

    return {
        "full_response":    final_response,
        "vulnerabilities":  vulnerabilities,
        "recommendations":  recommendations,
        "exploits":         exploits,
        "risk_level":       risk_level,
        "summary":          summary,
        "raw_scan":         raw_scan,
        "review":           review_result
    }
# ─────────────────────────────────────────────
# QUICK TEST
# ─────────────────────────────────────────────

if __name__ == "__main__":
    print("[ llm.py test — direct AI query ]\n")

    # test if LM Studio is reachable
    try:
        r = requests.get(LLM_MODELS_URL, timeout=5)
        r.raise_for_status()
        models = r.json().get("data", [])
        if models:
            print(f"[+] LM Studio is running. Models: {', '.join(m['id'] for m in models)}")
        else:
            print("[!] LM Studio is running but no models are loaded.")
            exit(1)
    except Exception:
        print(f"[!] LM Studio not reachable at {LLM_BASE_URL}. Is it running?")
        exit(1)

    target = input("Test target: ").strip()
    test_scan = f"Test recon for {target} — nmap and whois data would appear here."
    result = analyse_target(target, test_scan)

    print(f"\nRisk Level : {result['risk_level']}")
    print(f"Summary    : {result['summary']}")
    print(f"Vulns found: {len(result['vulnerabilities'])}")
    print(f"Exploits   : {len(result['exploits'])}")
