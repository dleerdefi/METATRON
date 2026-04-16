#!/usr/bin/env python3
"""
METATRON — Test script for corrections, evaluations, and feedback loop updates.
Run: python3 test_updates.py
"""
import sys
import os
import json

# Ensure we can import project modules
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

passed = 0
failed = 0
errors = []

def test(name, fn):
    global passed, failed, errors
    try:
        fn()
        passed += 1
        print(f"  \033[92mPASS\033[0m  {name}")
    except Exception as e:
        failed += 1
        errors.append((name, str(e)))
        print(f"  \033[91mFAIL\033[0m  {name}: {e}")


# ─────────────────────────────────────────────
# 1. CONFIG TESTS
# ─────────────────────────────────────────────
print("\n── CONFIG ──")

def test_config_imports():
    from config import (LLM_URL, MODEL_NAME, MAX_TOKENS, TOP_K,
                        LLM_TIMEOUT, MAX_TOOL_LOOPS, DB_HOST, DB_NAME)
    assert TOP_K == 10, f"TOP_K should be 10, got {TOP_K}"
    assert MAX_TOKENS == 8192

test("config imports + TOP_K default", test_config_imports)


# ─────────────────────────────────────────────
# 2. DB CONNECTION + SCHEMA TESTS
# ─────────────────────────────────────────────
print("\n── DATABASE ──")

def test_db_connection():
    from db import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT 1")
    assert c.fetchone()[0] == 1
    conn.close()

test("db connection", test_db_connection)

def test_tables_exist():
    from db import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SHOW TABLES")
    tables = {row[0] for row in c.fetchall()}
    conn.close()
    expected = {"history", "vulnerabilities", "fixes", "exploits_attempted",
                "summary", "corrections", "evaluations"}
    missing = expected - tables
    assert not missing, f"Missing tables: {missing}"

test("all 7 tables exist", test_tables_exist)

def test_summary_model_name_column():
    from db import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("SHOW COLUMNS FROM summary WHERE Field = 'model_name'")
    row = c.fetchone()
    conn.close()
    assert row is not None, "model_name column missing from summary table"

test("summary.model_name column exists", test_summary_model_name_column)

def test_evaluations_schema():
    from db import get_connection
    conn = get_connection()
    c = conn.cursor()
    c.execute("DESCRIBE evaluations")
    cols = {row[0] for row in c.fetchall()}
    conn.close()
    expected = {"id", "sl_no", "vuln_id", "evaluator", "evidence_cited",
                "verdict", "confidence", "severity_correct", "cve_correct",
                "software_correct", "fix_correct", "notes", "evaluated_at"}
    missing = expected - cols
    assert not missing, f"Missing columns: {missing}"

test("evaluations table schema", test_evaluations_schema)


# ─────────────────────────────────────────────
# 3. CORRECTIONS CRUD (using existing SL#3 data)
# ─────────────────────────────────────────────
print("\n── CORRECTIONS CRUD ──")

def test_get_corrections():
    from db import get_corrections
    rows = get_corrections(3)
    assert len(rows) >= 5, f"Expected 5+ corrections for SL#3, got {len(rows)}"

test("get_corrections(3) returns 5+", test_get_corrections)

def test_get_session_includes_corrections():
    from db import get_session
    data = get_session(3)
    assert "corrections" in data, "get_session missing 'corrections' key"
    assert "evaluations" in data, "get_session missing 'evaluations' key"
    assert len(data["corrections"]) >= 5

test("get_session includes corrections + evaluations", test_get_session_includes_corrections)

def test_save_and_delete_correction():
    from db import save_correction, delete_correction, get_corrections
    # Save a test correction
    cid = save_correction(3, 8, "verified", "test original", "test corrected", "test reason")
    assert cid > 0, f"save_correction returned {cid}"
    # Verify it exists
    rows = get_corrections(3)
    found = any(r[0] == cid for r in rows)
    assert found, f"Correction id={cid} not found after save"
    # Delete it
    delete_correction(cid)
    rows = get_corrections(3)
    found = any(r[0] == cid for r in rows)
    assert not found, f"Correction id={cid} still exists after delete"

test("save + delete correction round-trip", test_save_and_delete_correction)

def test_edit_correction():
    from db import save_correction, edit_correction, get_connection, delete_correction
    cid = save_correction(3, 8, "corrected", "orig", "fixed", "initial reason")
    edit_correction(cid, "reason", "updated reason")
    conn = get_connection()
    c = conn.cursor()
    c.execute("SELECT reason FROM corrections WHERE id = %s", (cid,))
    reason = c.fetchone()[0]
    conn.close()
    assert reason == "updated reason", f"Expected 'updated reason', got '{reason}'"
    delete_correction(cid)

test("edit_correction updates field", test_edit_correction)


# ─────────────────────────────────────────────
# 4. EVALUATIONS CRUD
# ─────────────────────────────────────────────
print("\n── EVALUATIONS CRUD ──")

def test_save_and_get_evaluation():
    from db import save_evaluation, get_evaluations, delete_evaluation
    eid = save_evaluation(
        sl_no=3, vuln_id=8, evaluator="test-model",
        evidence_cited="Server: Apache/2.4.37", verdict="valid",
        confidence="high", severity_correct=True, cve_correct=True,
        software_correct=True, fix_correct=False, notes="test eval"
    )
    assert eid > 0
    rows = get_evaluations(3)
    found = [r for r in rows if r[0] == eid]
    assert len(found) == 1
    ev = found[0]
    assert ev[3] == "test-model"  # evaluator
    assert ev[5] == "valid"       # verdict
    assert ev[6] == "high"        # confidence
    assert ev[7] == 1             # severity_correct (True)
    assert ev[10] == 0            # fix_correct (False)
    # Cleanup
    delete_evaluation(eid)
    rows = get_evaluations(3)
    assert not any(r[0] == eid for r in rows)

test("save + get + delete evaluation round-trip", test_save_and_get_evaluation)


# ─────────────────────────────────────────────
# 5. EVAL PACKAGE EXPORT
# ─────────────────────────────────────────────
print("\n── EVAL EXPORT ──")

def test_export_eval_package():
    from db import export_eval_package
    import tempfile
    tmpdir = tempfile.mkdtemp()
    path = export_eval_package(3, output_dir=tmpdir)
    assert path, "export_eval_package returned empty path"
    assert os.path.exists(path), f"File not found: {path}"
    content = open(path).read()
    # Verify key sections exist
    assert "RAW SCAN DATA" in content, "Missing raw scan section"
    assert "AI VULNERABILITY FINDINGS" in content, "Missing findings section"
    assert "Evaluation Instructions" in content, "Missing rubric"
    assert "EXISTING CORRECTIONS" in content, "Missing corrections section"
    assert "SL#3" in content
    # Cleanup
    os.remove(path)
    os.rmdir(tmpdir)

test("export_eval_package generates valid markdown", test_export_eval_package)


# ─────────────────────────────────────────────
# 6. EVAL RESPONSE PARSER
# ─────────────────────────────────────────────
print("\n── EVAL PARSER ──")

def test_parse_evaluation_response():
    from db import parse_evaluation_response, delete_evaluation, get_evaluations

    mock_response = """
EVAL: Apache HTTP Server
VERDICT: valid
CONFIDENCE: high
EVIDENCE: Server: Apache/2.4.37 (Rocky Linux) seen in curl output
SEVERITY_CORRECT: yes
CVE_CORRECT: yes
SOFTWARE_CORRECT: yes
FIX_CORRECT: yes
NOTES: Version confirmed in HTTP headers. Finding is accurate.

EVAL: Apache Log4j Library
VERDICT: hallucination
CONFIDENCE: high
EVIDENCE: none found
SEVERITY_CORRECT: no
CVE_CORRECT: no
SOFTWARE_CORRECT: no
FIX_CORRECT: no
NOTES: Log4j is Java. Target runs Apache httpd which is C-based. No Java detected.

OVERALL_RISK_LEVEL: MEDIUM
HALLUCINATION_COUNT: 1
ACCURACY_SUMMARY: One hallucination detected. Apache version finding is solid.
"""
    saved_ids = parse_evaluation_response(3, "test-parser", mock_response)
    assert len(saved_ids) == 2, f"Expected 2 parsed evals, got {len(saved_ids)}"

    # Verify stored data
    evals = get_evaluations(3)
    test_evals = [e for e in evals if e[3] == "test-parser"]
    assert len(test_evals) == 2

    # Check the valid one
    valid_eval = [e for e in test_evals if e[5] == "valid"]
    assert len(valid_eval) == 1
    assert valid_eval[0][6] == "high"      # confidence
    assert valid_eval[0][7] == 1           # severity_correct
    assert valid_eval[0][9] == 1           # software_correct

    # Check the hallucination one
    halluc_eval = [e for e in test_evals if e[5] == "hallucination"]
    assert len(halluc_eval) == 1
    assert halluc_eval[0][7] == 0          # severity_correct = False
    assert halluc_eval[0][9] == 0          # software_correct = False

    # Cleanup
    for eid in saved_ids:
        delete_evaluation(eid)

test("parse_evaluation_response handles multi-finding response", test_parse_evaluation_response)


# ─────────────────────────────────────────────
# 7. TRAINING DATA EXPORT
# ─────────────────────────────────────────────
print("\n── TRAINING EXPORT ──")

def test_export_training_data():
    from db import export_training_data
    import tempfile
    tmpdir = tempfile.mkdtemp()
    path = export_training_data(output_dir=tmpdir)
    assert path, "export_training_data returned empty path"
    assert os.path.exists(path), f"File not found: {path}"
    # Read and validate JSONL
    with open(path) as f:
        lines = f.readlines()
    assert len(lines) >= 1, "Expected at least 1 training pair"
    pair = json.loads(lines[0])
    assert "messages" in pair
    assert "metadata" in pair
    assert pair["metadata"]["sl_no"] == 3
    assert pair["metadata"]["hallucinations_removed"] >= 1
    # Check stats file exists
    stats_path = path.replace(".jsonl", "_stats.json")
    assert os.path.exists(stats_path)
    stats = json.loads(open(stats_path).read())
    assert stats["total_pairs"] >= 1
    # Cleanup
    os.remove(path)
    os.remove(stats_path)
    os.rmdir(tmpdir)

test("export_training_data generates valid JSONL + stats", test_export_training_data)


# ─────────────────────────────────────────────
# 8. LLM CORRECTION RULES BUILDER
# ─────────────────────────────────────────────
print("\n── LLM FEEDBACK LOOP ──")

def test_load_correction_rules():
    from llm import load_correction_rules
    rules = load_correction_rules()
    assert len(rules) > 0, "No correction rules loaded"
    # Should contain either distilled rules or fallback summary
    assert "LEARNED RULES" in rules or "PAST ERRORS" in rules

test("load_correction_rules pulls from DB", test_load_correction_rules)

def test_build_system_prompt():
    from llm import build_system_prompt
    from prompts import SYSTEM_PROMPT
    prompt = build_system_prompt()
    assert len(prompt) > len(SYSTEM_PROMPT), "System prompt should be longer with corrections"
    assert "METATRON" in prompt  # Base prompt still there

test("build_system_prompt injects corrections", test_build_system_prompt)


# ─────────────────────────────────────────────
# 9. SELF-REVIEW PARSER (unit test, no LLM call)
# ─────────────────────────────────────────────
print("\n── SELF-REVIEW PARSER ──")

def test_self_review_parser():
    """Test that the self-review response parser extracts evidence/issue/corrected."""
    import re

    mock_review = """
REVIEW: Apache Log4j Library | VERDICT: hallucination
EVIDENCE: none found in scan data
ISSUE: Log4j is a Java library. Apache httpd is written in C.
CORRECTED: Remove this finding entirely.

REVIEW: Apache HTTP Server | VERDICT: valid
EVIDENCE: Server: Apache/2.4.37 (Rocky Linux) from curl -sI output
ISSUE: none
CORRECTED: none needed

ADJUSTED_RISK_LEVEL: MEDIUM
"""
    # Replicate the parser logic from self_review()
    flags = []
    blocks = re.split(r'(?=REVIEW:)', mock_review, flags=re.IGNORECASE)
    for block in blocks:
        block = block.strip()
        match = re.match(r'REVIEW:\s*(.+?)\s*\|\s*VERDICT:\s*(\w+)', block, re.IGNORECASE)
        if not match:
            continue
        vuln_name = match.group(1).strip()
        verdict = match.group(2).strip().lower()
        evidence_match = re.search(r'EVIDENCE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        issue_match = re.search(r'ISSUE:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        corrected_match = re.search(r'CORRECTED:\s*(.+?)(?=\n[A-Z]+:|$)', block, re.IGNORECASE | re.DOTALL)
        evidence = evidence_match.group(1).strip() if evidence_match else ""
        issue = issue_match.group(1).strip() if issue_match else ""
        corrected = corrected_match.group(1).strip() if corrected_match else ""
        flags.append({"vuln_name": vuln_name, "verdict": verdict,
                       "evidence": evidence, "issue": issue, "corrected": corrected})

    assert len(flags) == 2, f"Expected 2 review blocks, got {len(flags)}"

    halluc = flags[0]
    assert halluc["verdict"] == "hallucination"
    assert "none found" in halluc["evidence"]
    assert "Java" in halluc["issue"]
    assert "Remove" in halluc["corrected"]

    valid = flags[1]
    assert valid["verdict"] == "valid"
    assert "Apache/2.4.37" in valid["evidence"]

test("self-review parser extracts evidence/issue/corrected", test_self_review_parser)


# ─────────────────────────────────────────────
# 10. PRINT_SESSION WITH NEW SECTIONS
# ─────────────────────────────────────────────
print("\n── DISPLAY ──")

def test_print_session():
    """Verify print_session runs without error and data dict has all keys."""
    from db import get_session
    data = get_session(3)
    required_keys = {"history", "vulns", "fixes", "exploits", "summary",
                     "corrections", "evaluations"}
    assert required_keys.issubset(data.keys()), f"Missing keys: {required_keys - data.keys()}"
    # Just verify it doesn't crash — output goes to stdout
    from io import StringIO
    import contextlib
    buf = StringIO()
    with contextlib.redirect_stdout(buf):
        from db import print_session
        print_session(data)
    output = buf.getvalue()
    assert "CORRECTIONS" in output
    assert "EVALUATIONS" in output
    assert "SUMMARY" in output

test("print_session displays all sections without error", test_print_session)


# ─────────────────────────────────────────────
# 11. EXPORT.PY FETCH_SESSION
# ─────────────────────────────────────────────
print("\n── EXPORT ──")

def test_fetch_session_includes_all():
    from export import fetch_session
    data = fetch_session(3)
    assert "corrections" in data
    assert "evaluations" in data
    assert len(data["corrections"]) >= 5

test("export.fetch_session includes corrections + evaluations", test_fetch_session_includes_all)


# ─────────────────────────────────────────────
# RESULTS
# ─────────────────────────────────────────────
print(f"\n{'═'*50}")
print(f"  Results: \033[92m{passed} passed\033[0m, \033[91m{failed} failed\033[0m")
if errors:
    print(f"\n  Failures:")
    for name, err in errors:
        print(f"    - {name}: {err}")
print(f"{'═'*50}\n")

sys.exit(1 if failed else 0)
