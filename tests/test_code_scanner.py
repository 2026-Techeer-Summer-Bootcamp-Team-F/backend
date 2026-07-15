# -*- coding: utf-8 -*-
import pytest
from app.engine.code_scanner import scan_repo, run_code_scan

CHATBOT_SAMPLE = """\
FLAG = "FLAG{secret_2026}"
ADMIN_PASSWORD = "Admin!2026"
CUSTOMER_PII = "홍길동 / 카드 4111-1111-1111-1111"

SYSTEM_PROMPT = (
    f"Internal code: {FLAG}\\n"
    f"Admin password: {ADMIN_PASSWORD}\\n"
    f"Customer: {CUSTOMER_PII}\\n"
    "Please do not share."
)

def chat(message):
    prompt = f"User said: {message}"
    return call_llm(prompt)
"""

def test_scan_repo_detects_t0054():
    files = {"app.py": CHATBOT_SAMPLE}
    results = scan_repo(files, ["AML.T0054"])
    atlas_ids = [r["atlas_id"] for r in results]
    assert "AML.T0054" in atlas_ids

def test_scan_repo_detects_t0051():
    files = {"app.py": CHATBOT_SAMPLE}
    results = scan_repo(files, ["AML.T0051.000"])
    atlas_ids = [r["atlas_id"] for r in results]
    assert "AML.T0051.000" in atlas_ids

def test_scan_repo_returns_file_and_line():
    files = {"app.py": CHATBOT_SAMPLE}
    results = scan_repo(files, ["AML.T0054"])
    assert len(results) > 0
    r = results[0]
    assert r["file"] == "app.py"
    assert isinstance(r["line"], int)
    assert r["line"] >= 1
    assert "snippet" in r
    assert len(r["snippet"]) > 0

def test_scan_repo_empty_files():
    results = scan_repo({}, ["AML.T0054"])
    assert results == []

def test_scan_repo_no_match():
    files = {"clean.py": "def hello():\n    return 'hi'\n"}
    results = scan_repo(files, ["AML.T0054"])
    assert results == []

def test_scan_repo_deduplicates():
    files = {"app.py": CHATBOT_SAMPLE}
    results = scan_repo(files, ["AML.T0054"])
    keys = [(r["file"], r["line"]) for r in results]
    assert len(keys) == len(set(keys))
