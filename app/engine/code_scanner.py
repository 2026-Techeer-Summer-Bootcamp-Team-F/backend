# -*- coding: utf-8 -*-
"""취약 코드 위치 탐지 — AI(Claude Haiku)가 레포 소스를 직접 읽어 ATLAS 기법별 취약점 탐지.

run_code_scan(repo_url, atlas_ids, token) → [{file, line, snippet, atlas_id, reason}]
"""
import json
import logging
import re

log = logging.getLogger("redteam.code_scanner")

_CODE_EXTS = {".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".rb", ".php"}

_ATLAS_DESCRIPTIONS = {
    "AML.T0054": "LLM Jailbreak — 하드코딩된 비밀값(토큰·패스워드·API키)이 프롬프트에 노출",
    "AML.T0051.000": "Direct Prompt Injection — 사용자 입력이 검증 없이 LLM 프롬프트에 직접 삽입",
    "AML.T0051.001": "Indirect Prompt Injection — 외부 문서·RAG 결과가 검증 없이 프롬프트에 삽입",
    "AML.T0056": "LLM Meta Prompt Extraction — 시스템프롬프트가 로그·응답에 노출될 수 있는 구조",
    "AML.T0057": "LLM Data Leakage — PII·민감 고객 데이터가 LLM 컨텍스트에 직접 포함",
    "AML.T0053": "LLM Plugin Compromise — 고위험 툴/함수 호출 시 입력 파라미터 검증 부재",
}

_SYSTEM = (
    "You are a security code reviewer specializing in MITRE ATLAS AI/LLM attack techniques. "
    "Analyze the provided source code and identify vulnerable lines. "
    "Respond ONLY with a valid JSON array — no explanation, no markdown, no extra text."
)


def _build_prompt(files_with_lines: str, atlas_ids: list[str]) -> str:
    techniques = "\n".join(
        f"- {aid}: {_ATLAS_DESCRIPTIONS.get(aid, aid)}" for aid in atlas_ids
    )
    return (
        f"Find vulnerabilities in this code for the following MITRE ATLAS techniques:\n"
        f"{techniques}\n\n"
        f"Source code (format: filename > line_number: code):\n"
        f"{files_with_lines}\n\n"
        f"Return a JSON array of findings. Each finding:\n"
        f'{{"file":"filename","line":N,"snippet":"exact line text","atlas_id":"AML.Txxxx","reason":"why vulnerable in Korean (50 chars max)"}}\n'
        f"reason must be plain text only — no markdown, no bold, no dashes, no bullets.\n"
        f"Return [] if nothing found. One finding per atlas_id maximum."
    )


def _strip_markdown(text: str) -> str:
    text = re.sub(r"\*{1,3}([^*]+)\*{1,3}", r"\1", text)   # **bold**, *italic*
    text = re.sub(r"`([^`]+)`", r"\1", text)                 # `code`
    text = re.sub(r"^[-*#>]+\s*", "", text, flags=re.MULTILINE)  # 줄 앞 기호
    text = re.sub(r"\s{2,}", " ", text)
    return text.strip()


def _format_files(files: dict[str, str], max_chars: int = 12000) -> str:
    parts = []
    total = 0
    for path, src in files.items():
        if not any(path.endswith(ext) for ext in _CODE_EXTS):
            continue
        lines = src.splitlines()
        block = "\n".join(f"{path} > {i+1}: {line}" for i, line in enumerate(lines))
        if total + len(block) > max_chars:
            break
        parts.append(block)
        total += len(block)
    return "\n\n".join(parts)


def _ai_scan(files: dict[str, str], atlas_ids: list[str], api_key: str) -> list[dict]:
    formatted = _format_files(files)
    if not formatted:
        return []

    try:
        import anthropic
        from ..config import settings
        client = anthropic.Anthropic(api_key=api_key)
        msg = client.messages.create(
            model=settings.attacker_model,
            max_tokens=1024,
            system=_SYSTEM,
            messages=[{"role": "user", "content": _build_prompt(formatted, atlas_ids)}],
        )
        text = "".join(
            b.text for b in msg.content if getattr(b, "type", "") == "text"
        ).strip()
        results = json.loads(text)
        if not isinstance(results, list):
            return []
        valid_ids = set(atlas_ids)
        return [
            {
                "file": r.get("file", ""),
                "line": int(r.get("line", 0)),
                "snippet": str(r.get("snippet", ""))[:160],
                "atlas_id": r.get("atlas_id", ""),
                "reason": _strip_markdown(r.get("reason", "")),
            }
            for r in results
            if isinstance(r, dict) and r.get("atlas_id") in valid_ids
        ]
    except Exception as e:   # noqa: BLE001
        log.warning("code_scanner: AI 분석 실패: %s", e)
        return []


def run_code_scan(repo_url: str, atlas_ids: list[str], token: str = "") -> list[dict]:
    """GitHub 레포 fetch → AI 코드 분석 → 취약 위치 목록 반환."""
    if not repo_url:
        return []
    try:
        from ..recon import fetch_repo_sources
        from ..config import settings
        files = fetch_repo_sources(repo_url, token)
        if not files:
            log.info("code_scanner: 레포 소스 없음 — %s", repo_url)
            return []
        if not settings.anthropic_api_key:
            log.info("code_scanner: API 키 없음 — AI 분석 건너뜀")
            return []
        return _ai_scan(files, atlas_ids, settings.anthropic_api_key)
    except Exception as e:   # noqa: BLE001
        log.warning("code_scanner: 스캔 실패(%s): %s", repo_url, e)
        return []
