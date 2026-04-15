#!/bin/bash
# Run migration 002: evaluations table + model_name
mysql -u metatron -p123 metatron < "$(dirname "$0")/002_evaluations.sql"
echo "[+] Migration 002 complete"

# Syntax check all Python files
cd "$(dirname "$0")/.."
for f in config.py db.py llm.py metatron.py export.py; do
    python3 -m py_compile "$f" && echo "[+] $f — syntax OK" || echo "[!] $f — SYNTAX ERROR"
done
