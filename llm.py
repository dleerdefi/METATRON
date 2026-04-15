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

# ─────────────────────────────────────────────
# SYSTEM PROMPT
# ─────────────────────────────────────────────

SYSTEM_PROMPT = """You are METATRON, an experienced penetration testing analyst running on Kali Linux.
You think like a senior pentester with 15 years of experience. You are skeptical by default.

YOUR DEFAULT ASSUMPTION: The target is NOT vulnerable. You need concrete scan evidence to
override this assumption. Most services are patched. Most version strings are misleading.
Most scan results are noise. Your job is to separate signal from noise.

CORE PRINCIPLES:
- Your credibility depends on ACCURACY, not volume. 3 real findings beat 10 speculative ones.
- It is BETTER to miss a real vulnerability than to fabricate a false one.
- If you cannot quote specific scan output supporting a finding, DO NOT report it.
- Finding zero vulnerabilities is a valid and respectable outcome. Say so honestly.
- Never chain assumptions (detected Apache does NOT mean mod_proxy is present does NOT mean RCE exists).
- Detecting a version number does NOT mean it is exploitable. Distro backports patch CVEs without changing version strings.
- Never associate software from different ecosystems based on shared names (Apache httpd is C-based. Apache Log4j is a Java library. They are UNRELATED.)
- Generic security recommendations (enable HSTS, use TLS 1.3) are NOT vulnerabilities.

You have access to real tools. To use them, write tags in your response:

  [TOOL: nmap -sV 192.168.1.1]       → runs nmap or any CLI tool
  [SEARCH: CVE-2021-44228 exploit]   → searches the web via DuckDuckGo

ANALYSIS RULES:
- Read ALL scan data carefully before writing any findings
- For every finding you report, you MUST quote the exact scan output that supports it
- Only cite CVEs if you can confirm the exact version is affected (search if unsure)
- If you need more information to be certain, use [SEARCH:] or [TOOL:] — do not guess
- Severity must be justified by the evidence, not by theoretical worst-case scenarios

CONFIDENCE LEVELS (you MUST assign one to every finding):
- confirmed: Direct evidence in scan output. Version banner matches a known vulnerable version exactly.
- likely: Version detected and CVE exists for that specific version, but exploitability not proven by scan.
- possible: Indirect indicator only. Version range, behavioral clue, or requires further verification.

OUTPUT FORMAT FOR VULNERABILITIES (use this exactly):
VULN: <name> | SEVERITY: <critical/high/medium/low> | CONFIDENCE: <confirmed/likely/possible> | PORT: <port> | SERVICE: <service>
EVIDENCE: <exact text quoted from scan output that supports this finding>
DESC: <description — only what the evidence supports, nothing more>
FIX: <fix recommendation>

OUTPUT FORMAT FOR RECOMMENDATIONS (security hardening, NOT vulnerabilities):
REC: <recommendation name>
DESC: <what should be improved and why>

OUTPUT FORMAT FOR EXPLOITS (only for confirmed or likely findings):
EXPLOIT: <name> | TOOL: <tool> | PAYLOAD: <payload or description>
RESULT: <expected result>
NOTES: <any notes>

End your analysis with:
RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>
SUMMARY: <2-3 sentence overall summary>

IMPORTANT: Never use markdown bold (**text**) or headers (## text). Plain text only.

ACCURACY RULES:
- nmap filtered or no-response means INCONCLUSIVE — do not report as a finding
- Never assert a server version without seeing it in scan output
- Never infer CVEs from guessed or assumed versions — search to verify
- curl timeouts and HTTP_CODE=000 mean the host is unreachable, not exploitable
- Only assign CRITICAL if there is direct, confirmed evidence of exploitability
- Only assign confirmed confidence if you can point to a specific scan output line
- If evidence is weak, either downgrade to possible confidence or do not report at all"""


# ─────────────────────────────────────────────
# CORRECTION FEEDBACK LOOP
# ─────────────────────────────────────────────

STATUS_LABELS = {
    "hallucination": "HALLUCINATION (fabricated finding)",
    "corrected":     "WRONG DETAIL (finding existed but details were wrong)",
    "downgraded":    "OVER-SEVERITY (severity was inflated without evidence)",
    "reclassified":  "MISCLASSIFIED (not a vulnerability, reclassified)",
    "verified":      "VERIFIED CORRECT",
}


def load_correction_rules() -> str:
    """
    Query all corrections from the database and distill them into
    concise rules that get injected into the system prompt.
    Groups by error type to create generalizable lessons, not just
    a list of past-target-specific mistakes.
    """
    try:
        from db import get_connection
        conn = get_connection()
        c = conn.cursor()
        c.execute("""
            SELECT c.status, c.original_text, c.corrected_text, c.reason,
                   v.vuln_name, v.severity, h.target
            FROM corrections c
            JOIN vulnerabilities v ON c.vuln_id = v.id
            JOIN history h ON c.sl_no = h.sl_no
            ORDER BY c.corrected_at DESC
            LIMIT 50
        """)
        rows = c.fetchall()
        conn.close()
    except Exception:
        return ""

    if not rows:
        return ""

    # Group corrections by status for cleaner rules
    by_status = {}
    for status, original, corrected, reason, vuln_name, severity, target in rows:
        by_status.setdefault(status, []).append({
            "original": original, "corrected": corrected,
            "reason": reason, "vuln_name": vuln_name,
            "severity": severity, "target": target
        })

    lines = [
        "",
        "LEARNED CORRECTIONS FROM PAST SCANS:",
        "These are verified mistakes from previous analyses. DO NOT repeat them.",
        ""
    ]

    for status, items in by_status.items():
        label = STATUS_LABELS.get(status, status.upper())
        lines.append(f"[{label}]")
        for item in items:
            lines.append(f"  - {item['reason']}")
        lines.append("")

    # Add generalized rules extracted from patterns
    hallucinations = by_status.get("hallucination", [])
    if hallucinations:
        lines.append("ANTI-HALLUCINATION RULES (derived from above):")
        for h in hallucinations:
            # Extract the core lesson from each hallucination reason
            lines.append(f"  - NEVER: {h['reason'][:200]}")
        lines.append("")

    corrected = by_status.get("corrected", [])
    if corrected:
        lines.append("CVE ACCURACY RULES (derived from above):")
        for c in corrected:
            lines.append(f"  - {c['reason'][:200]}")
        lines.append("")

    return "\n".join(lines)


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

REVIEW_PROMPT = """You are a hostile QA reviewer for an AI penetration testing system. Your job is to
REJECT weak findings. You are paid to find errors, not to agree. Assume every finding is wrong
until proven otherwise.

Given:
1. RAW SCAN DATA (what the tools actually detected — this is ground truth)
2. AI ANALYSIS (what the AI concluded — this is what you are auditing)
3. KNOWN ERROR PATTERNS (mistakes this system has made before — watch for repeats)

For each vulnerability in the AI analysis, apply these checks IN ORDER:

CHECK 1 — EVIDENCE GATE: Does the EVIDENCE field quote actual text from the raw scan data?
  - Search the raw scan data for the quoted text. If the quote is not found verbatim or
    closely paraphrased, the finding FAILS this check and is a hallucination.
  - If the EVIDENCE field is vague (e.g., "version detected", "service running") without
    quoting specific output, the finding FAILS.

CHECK 2 — SOFTWARE IDENTITY: Is the software correctly identified?
  - Apache httpd (C) is NOT Apache Log4j (Java). OpenSSH is NOT OpenSSL.
  - Check that the identified software matches what the scan tools actually detected.
  - Cross-ecosystem attribution (Java CVEs against C software) is an automatic hallucination.

CHECK 3 — CVE ACCURACY: Are cited CVEs correct for the EXACT detected version?
  - A CVE for version 1.0.1 does NOT apply to version 1.1.1k.
  - Distro packages often backport security fixes without changing version strings.
  - If unsure, mark CVE attribution as unverified, not confirmed.

CHECK 4 — SEVERITY PROPORTIONALITY: Is the severity justified by the evidence?
  - CRITICAL requires confirmed remote exploitability with direct evidence.
  - Version-only findings should be MEDIUM at most unless exploitation is demonstrated.
  - Possible findings should never be rated higher than MEDIUM.

CHECK 5 — CONFIDENCE ACCURACY: Is the confidence level appropriate?
  - confirmed requires verbatim scan evidence + verified CVE match.
  - likely requires version detection + plausible CVE (not just same software family).
  - possible is for indirect indicators only.
  - If confidence is too high for the evidence, downgrade it.

Output your review in this exact format for each finding:

REVIEW: <vuln name> | VERDICT: <valid|hallucination|corrected|downgraded|reclassified>
EVIDENCE: <quote from raw scan data that supports OR refutes, or "none found in scan data">
ISSUE: <what specifically is wrong, referencing which check failed>
CORRECTED: <what the finding should say instead, if applicable>

End with:
ADJUSTED_RISK_LEVEL: <CRITICAL|HIGH|MEDIUM|LOW>

DEFAULT TO REJECTION. If evidence is borderline, reject the finding. False negatives
(missing a real vuln) are recoverable. False positives (hallucinated vulns) destroy credibility.
IMPORTANT: Never use markdown bold or headers. Plain text only."""


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
# PARSER — extract structured data from AI output
# ─────────────────────────────────────────────
def _clean(line: str) -> str:
    return re.sub(r'\*+', '', line).strip()
def parse_vulnerabilities(response: str) -> list:
    """
    Parse VULN: lines from AI response into dicts.
    Returns list of vulnerability dicts ready for db.save_vulnerability()
    """
    vulns = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("VULN:"):
            vuln = {
                "vuln_name":   "",
                "severity":    "medium",
                "confidence":  "possible",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            # parse header line: VULN: name | SEVERITY: x | CONFIDENCE: x | PORT: x | SERVICE: x
            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("VULN:"):
                    vuln["vuln_name"] = part.replace("VULN:", "").strip()
                elif part.startswith("SEVERITY:"):
                    vuln["severity"] = part.replace("SEVERITY:", "").strip().lower()
                elif part.startswith("CONFIDENCE:"):
                    vuln["confidence"] = part.replace("CONFIDENCE:", "").strip().lower()
                elif part.startswith("PORT:"):
                    vuln["port"] = part.replace("PORT:", "").strip()
                elif part.startswith("SERVICE:"):
                    vuln["service"] = part.replace("SERVICE:", "").strip()

            # Validate confidence value
            if vuln["confidence"] not in ("confirmed", "likely", "possible"):
                vuln["confidence"] = "possible"

            # look ahead for EVIDENCE:, DESC: and FIX: lines
            j = i + 1
            while j < len(lines) and j <= i + 6:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "REC:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("EVIDENCE:"):
                    vuln["evidence"] = next_line.replace("EVIDENCE:", "").strip()
                elif next_line.startswith("DESC:"):
                    vuln["description"] = next_line.replace("DESC:", "").strip()
                elif next_line.startswith("FIX:"):
                    vuln["fix"] = next_line.replace("FIX:", "").strip()
                j += 1

            if vuln["vuln_name"]:
                vulns.append(vuln)

        i += 1

    return vulns


def parse_recommendations(response: str) -> list:
    """
    Parse REC: lines from AI response into dicts.
    Stored as vulns with severity='info' and confidence='recommendation'.
    """
    recs = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("REC:"):
            rec = {
                "vuln_name":   line.replace("REC:", "").strip(),
                "severity":    "info",
                "confidence":  "recommendation",
                "port":        "",
                "service":     "",
                "description": "",
                "fix":         ""
            }

            j = i + 1
            while j < len(lines) and j <= i + 3:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "REC:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("DESC:"):
                    rec["description"] = next_line.replace("DESC:", "").strip()
                j += 1

            if rec["vuln_name"]:
                recs.append(rec)

        i += 1

    return recs


def parse_exploits(response: str) -> list:
    """
    Parse EXPLOIT: lines from AI response into dicts.
    Returns list of exploit dicts ready for db.save_exploit()
    """
    exploits = []
    lines = response.splitlines()

    i = 0
    while i < len(lines):
        line = _clean(lines[i])
        if line.startswith("EXPLOIT:"):
            exploit = {
                "exploit_name": "",
                "tool_used":    "",
                "payload":      "",
                "result":       "unknown",
                "notes":        ""
            }

            parts = line.split("|")
            for part in parts:
                part = part.strip()
                if part.startswith("EXPLOIT:"):
                    exploit["exploit_name"] = part.replace("EXPLOIT:", "").strip()
                elif part.startswith("TOOL:"):
                    exploit["tool_used"] = part.replace("TOOL:", "").strip()
                elif part.startswith("PAYLOAD:"):
                    exploit["payload"] = part.replace("PAYLOAD:", "").strip()

            j = i + 1
            while j < len(lines) and j <= i + 4:
                next_line = _clean(lines[j])
                if next_line.startswith(("VULN:", "EXPLOIT:", "RISK_LEVEL:", "SUMMARY:")):
                    break
                if next_line.startswith("RESULT:"):
                    exploit["result"] = next_line.replace("RESULT:", "").strip()
                elif next_line.startswith("NOTES:"):
                    exploit["notes"] = next_line.replace("NOTES:", "").strip()
                j += 1

            if exploit["exploit_name"]:
                exploits.append(exploit)

        i += 1

    return exploits


def parse_risk_level(response: str) -> str:
    """Extract RISK_LEVEL from AI response."""
    match = re.search(r'RISK_LEVEL:\s*(CRITICAL|HIGH|MEDIUM|LOW)', response, re.IGNORECASE)
    return match.group(1).upper() if match else "UNKNOWN"


def parse_summary(response: str) -> str:
    match = re.search(r'SUMMARY:\s*(.+)', response, re.IGNORECASE)
    return match.group(1).strip() if match else ""


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

    # Tag flagged vulns so they can be marked in the database
    flagged_map = {}
    for f in review_result["flags"]:
        flagged_map[f["vuln_name"].lower()] = f
    for vuln in vulnerabilities:
        name_lower = vuln["vuln_name"].lower()
        for flagged_name, flag_data in flagged_map.items():
            if flagged_name in name_lower or name_lower in flagged_name:
                vuln["_review_flag"] = flag_data["verdict"]
                vuln["_review_evidence"] = flag_data.get("evidence", "")
                vuln["_review_issue"] = flag_data.get("issue", "")
                vuln["_review_corrected"] = flag_data.get("corrected", "")
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
