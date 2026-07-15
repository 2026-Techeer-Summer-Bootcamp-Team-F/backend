# -*- coding: utf-8 -*-
"""취약 코드 위치 탐지 — ATLAS 기법별 regex 패턴으로 레포 소스를 스캔.

scan_repo(files, atlas_ids) → 패턴 매칭 결과 [{file, line, snippet, atlas_id}]
explain_matches(matches)    → Haiku로 reason 필드 추가 (키 없으면 템플릿)
run_code_scan(repo_url, atlas_ids, token) → 파이프라인 전체 실행, dict 목록 반환
"""
import logging
import re

log = logging.getLogger("redteam.code_scanner")

# ── ATLAS 기법별 탐지 패턴 (pattern, hint) ──
_PATTERNS: dict[str, list[tuple[re.Pattern, str]]] = {
    "AML.T0054": [
        (re.compile(r"(?i)\b(FLAG|PASSWORD|SECRET|API_KEY|CREDENTIAL|INTERNAL_KEY)\s*=\s*[\"']"),
         "비밀 상수가 코드에 하드코딩됨"),
        (re.compile(r"(?i)f[\"'].*?\{(FLAG|PASSWORD|SECRET|API_KEY|CREDENTIAL|PII)\}"),
         "시스템프롬프트 f-string에 비밀값 직접 삽입"),
    ],
    "AML.T0051.000": [
        (re.compile(r"(?i)f[\"'].*?\{(message|user_input|user_message|prompt|query|text|input)\}"),
         "사용자 입력이 f-string으로 프롬프트에 직접 삽입됨 (입력 검증 없음)"),
        (re.compile(r"(?i)\.format\(.*?(message|user_input|user_message|prompt|query)\b"),
         "사용자 입력이 .format()으로 프롬프트에 직접 삽입됨"),
    ],
    "AML.T0056": [
        (re.compile(r"(?i)\b(SYSTEM_PROMPT|system_prompt|SYS_PROMPT)\s*="),
         "시스템프롬프트 변수 발견 — 응답/로그 노출 경로 검토 필요"),
        (re.compile(r"(?i)(?:print|log|logger)\s*\(.*?(system_prompt|SYSTEM_PROMPT)"),
         "시스템프롬프트가 로그/출력에 노출될 수 있음"),
    ],
    "AML.T0057": [
        (re.compile(r"(?i)\b(CUSTOMER_PII|PII|USER_DATA|CUSTOMER_DATA)\s*=\s*[\"']"),
         "PII 데이터가 코드에 하드코딩됨"),
        (re.compile(r"(?i)f[\"'].*?\{(PII|CUSTOMER_PII|customer_pii|user_data)\}"),
         "PII 데이터가 LLM 컨텍스트에 직접 삽입됨"),
    ],
    "AML.T0053": [
        (re.compile(r"(?i)def\s+(transfer|send_money|payment|refund|delete_user|execute_sql|wire)\s*\("),
         "고위험 툴 함수 정의 — 입력 파라미터 검증 확인 필요"),
    ],
    "AML.T0051.001": [
        (re.compile(r"(?i)f[\"'].*?\{(doc|document|chunk|retrieved|context|rag_result)\}"),
         "외부 문서/RAG 결과가 검증 없이 프롬프트에 삽입됨"),
    ],
}

_TEMPLATE_REASONS: dict[str, str] = {
    "AML.T0054": "LLM Jailbreak 공격으로 이 코드의 비밀 정보가 유출될 수 있습니다.",
    "AML.T0051.000": "Direct Prompt Injection 공격자가 이 입력 경로를 통해 LLM 지침을 덮어쓸 수 있습니다.",
    "AML.T0056": "시스템프롬프트 내용이 공격자에게 노출될 수 있습니다.",
    "AML.T0057": "PII 데이터가 LLM 응답을 통해 유출될 수 있습니다.",
    "AML.T0053": "툴 파라미터 검증 미흡으로 의도치 않은 작업이 실행될 수 있습니다.",
    "AML.T0051.001": "외부 콘텐츠에 숨겨진 악성 지시가 LLM에 실행될 수 있습니다.",
}


def scan_repo(files: dict[str, str], atlas_ids: list[str]) -> list[dict]:
    """파일 dict를 라인별로 스캔해 ATLAS 기법별 매칭 결과 반환."""
    results: list[dict] = []
    seen: set[tuple] = set()

    for atlas_id in atlas_ids:
        patterns = _PATTERNS.get(atlas_id, [])
        if not patterns:
            continue
        for filepath, source in files.items():
            for lineno, line in enumerate(source.splitlines(), start=1):
                for pat, hint in patterns:
                    if pat.search(line):
                        key = (filepath, lineno, atlas_id)
                        if key in seen:
                            continue
                        seen.add(key)
                        results.append({
                            "file": filepath,
                            "line": lineno,
                            "snippet": line.strip()[:160],
                            "atlas_id": atlas_id,
                            "hint": hint,
                            "reason": "",
                        })
                        break

    return results


def explain_matches(matches: list[dict], api_key: str = "") -> list[dict]:
    """Haiku로 각 매치에 취약 이유 한 문장 추가. 키 없으면 템플릿 설명 사용."""
    if not api_key:
        for m in matches:
            m["reason"] = _TEMPLATE_REASONS.get(m["atlas_id"], m["hint"])
        return matches

    try:
        import anthropic
        client = anthropic.Anthropic(api_key=api_key)
        for m in matches:
            try:
                msg = client.messages.create(
                    model="claude-haiku-4-5-20251001",
                    max_tokens=80,
                    messages=[{"role": "user", "content": (
                        f"다음 코드 라인이 MITRE ATLAS {m['atlas_id']} 공격에 왜 취약한지 "
                        f"한 문장(60자 이내 한국어)으로 설명해:\n```\n{m['snippet']}\n```"
                    )}],
                )
                text = "".join(
                    b.text for b in msg.content if getattr(b, "type", "") == "text"
                ).strip()
                m["reason"] = text or _TEMPLATE_REASONS.get(m["atlas_id"], m["hint"])
            except Exception:   # noqa: BLE001
                m["reason"] = _TEMPLATE_REASONS.get(m["atlas_id"], m["hint"])
    except Exception:           # noqa: BLE001
        for m in matches:
            m["reason"] = _TEMPLATE_REASONS.get(m["atlas_id"], m["hint"])

    return matches


def run_code_scan(repo_url: str, atlas_ids: list[str], token: str = "") -> list[dict]:
    """GitHub 레포 fetch → 패턴 스캔 → Haiku 설명 생성 파이프라인."""
    if not repo_url:
        return []
    try:
        from ..recon import fetch_repo_sources
        from ..config import settings
        files = fetch_repo_sources(repo_url, token)
        if not files:
            log.info("code_scanner: 레포 소스 없음 — %s", repo_url)
            return []
        matches = scan_repo(files, atlas_ids)
        if not matches:
            return []
        explain_matches(matches, api_key=settings.anthropic_api_key)
        return [
            {"file": m["file"], "line": m["line"], "snippet": m["snippet"],
             "atlas_id": m["atlas_id"], "reason": m["reason"]}
            for m in matches
        ]
    except Exception as e:   # noqa: BLE001
        log.warning("code_scanner: 코드 스캔 실패(%s): %s", repo_url, e)
        return []
