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
    from ..mitigations import get_mitigation
    # 기법 설명 + ATLAS/OWASP 정본 권고(mitigations.py)를 AI에 제공 → fix가 표준 권고와 정렬되게
    techniques = []
    for aid in atlas_ids:
        desc = _ATLAS_DESCRIPTIONS.get(aid, aid)
        steps = "; ".join(get_mitigation(aid).get("steps", [])[:4])
        techniques.append(f"- {aid}: {desc}\n  ATLAS/OWASP 권고: {steps}")
    tech_block = "\n".join(techniques)
    return (
        f"You are a security code reviewer. For each MITRE ATLAS technique below, find the "
        f"vulnerable line AND propose a concrete fix tailored to THIS app's actual code, "
        f"aligned with the ATLAS/OWASP 권고 given:\n"
        f"{tech_block}\n\n"
        f"Source code (format: filename > line_number: code):\n"
        f"{files_with_lines}\n\n"
        f"Return a JSON array. Each finding:\n"
        f'{{"file":"filename","line":N,"snippet":"exact line text","atlas_id":"AML.Txxxx",'
        f'"reason":"why vulnerable, Korean (60 chars max)",'
        f'"fix":"how to fix THIS specific code, Korean — reference the ATLAS 권고, '
        f'may include a short corrected code line (140 chars max)"}}\n'
        f"reason/fix: plain text only — no markdown, no bold, no bullets.\n"
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


def _extract_json(text: str) -> str:
    """LLM 응답에서 JSON 배열만 뽑아낸다(```json 펜스·앞뒤 설명 제거).

    Haiku가 'Respond ONLY with JSON' 지시를 어기고 ```json ... ``` 로 감싸거나
    설명을 덧붙이면 json.loads가 깨져 findings=0이 됨 → 배열만 안전 추출.
    """
    m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
    if m:
        text = m.group(1).strip()
    i, j = text.find("["), text.rfind("]")
    if i != -1 and j > i:
        return text[i:j + 1]
    return text


def _context_lines(files: dict[str, str], path: str, line: int, radius: int = 3) -> list:
    """취약 라인 앞뒤 ±radius줄을 [{line, code}]로 반환(프론트에서 접었다 펴기용)."""
    src = files.get(path, "")
    if not src or line < 1:
        return []
    lines = src.splitlines()
    lo = max(0, line - 1 - radius)
    hi = min(len(lines), line + radius)
    return [{"line": k + 1, "code": lines[k]} for k in range(lo, hi)]


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
            max_tokens=2048,   # fix 필드 추가로 상향
            system=_SYSTEM,
            messages=[{"role": "user", "content": _build_prompt(formatted, atlas_ids)}],
        )
        text = "".join(
            b.text for b in msg.content if getattr(b, "type", "") == "text"
        ).strip()
        text = _extract_json(text)   # Haiku가 ```json 펜스·설명 붙여도 배열만 추출
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
                "fix": _strip_markdown(r.get("fix", "")),                     # 앱 맞춤 수정 제안(#111)
                "context": _context_lines(files, r.get("file", ""),          # 앞뒤 코드(±3줄)
                                          int(r.get("line", 0))),
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
