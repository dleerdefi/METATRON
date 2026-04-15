#!/usr/bin/env python3
"""
METATRON - config.py
Centralized configuration. All values can be overridden via environment
variables or a .env file in the project root.
"""

import os
from dotenv import load_dotenv

load_dotenv()

# ─────────────────────────────────────────────
# LLM BACKEND (LM Studio — OpenAI-compatible API)
# ─────────────────────────────────────────────

LLM_BASE_URL   = os.environ.get("METATRON_LLM_URL", "http://localhost:1234")
LLM_URL        = LLM_BASE_URL.rstrip("/") + "/v1/chat/completions"
LLM_MODELS_URL = LLM_BASE_URL.rstrip("/") + "/v1/models"
MODEL_NAME     = os.environ.get("METATRON_MODEL", "huihui-ai.huihui-qwen3.5-27b-abliterated")
MAX_TOKENS     = int(os.environ.get("METATRON_MAX_TOKENS", "8192"))
TOP_K          = int(os.environ.get("METATRON_TOP_K", "10"))       # Modelfile default: 10
LLM_TIMEOUT    = int(os.environ.get("METATRON_TIMEOUT", "600"))
MAX_TOOL_LOOPS = int(os.environ.get("METATRON_MAX_LOOPS", "9"))
# Note: context window (num_ctx=16384 in Modelfile) is set at model load time,
# not via API payload. Configure in Ollama Modelfile or LM Studio model settings.

# ─────────────────────────────────────────────
# DATABASE (MariaDB)
# ─────────────────────────────────────────────

DB_HOST     = os.environ.get("METATRON_DB_HOST", "localhost")
DB_USER     = os.environ.get("METATRON_DB_USER", "metatron")
DB_PASSWORD = os.environ.get("METATRON_DB_PASS", "123")
DB_NAME     = os.environ.get("METATRON_DB_NAME", "metatron")
