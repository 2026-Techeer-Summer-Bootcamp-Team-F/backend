# -*- coding: utf-8 -*-
"""ATLAS 기법별 취약 코드 패턴 탐지 — 레포 소스에서 라인 위치 반환.

scan_code(sources, atlas_ids) → list[dict]
  sources : {filepath: code_str}  (fetch_repo_sources 반환값)
  atlas_ids: set[str]             (이 스캔에서 사용된 기법)
  반환    : [{file, line, snippet, reason, atlas_technique_id, severity}]
"""
import re

# ── 기법별 패턴 정의 ──────────────────────────────────────────
# (compiled_regex, reason_ko, atlas_id, severity)
_PATTERNS: list[tuple] = [

    # T0056: 시스템 프롬프트에 민감값 하드코딩
    (re.compile(r'FLAG\{', re.I),
     '시스템 프롬프트에 카나리(FLAG) 하드코딩 — 공격 성공 시 즉시 유출',
     'AML.T0056', 'critical'),

    (re.compile(r'(password|passwd|secret|api_key|admin_pw)\s*=\s*["\'].{4,}["\']', re.I),
     '민감한 자격증명이 코드에 평문 하드코딩',
     'AML.T0056', 'high'),

    (re.compile(r'system_prompt\s*=.*(\+|f["\']|format\()', re.I),
     '시스템 프롬프트가 동적으로 조합 — 사용자 입력 주입 가능성',
     'AML.T0056', 'high'),

    # T0051: 사용자 입력이 LLM 메시지에 직접 삽입
    (re.compile(r'["\']\s*role["\']\s*:\s*["\']user["\'].*content.*\+', re.I | re.S),
     '사용자 입력이 LLM 메시지에 문자열 연결로 삽입 — 프롬프트 인젝션 취약',
     'AML.T0051.000', 'high'),

    (re.compile(r'messages\.append.*user.*content.*(input|query|message|request)', re.I),
     '사용자 입력이 필터링 없이 LLM 메시지 배열에 추가됨',
     'AML.T0051.000', 'high'),

    (re.compile(r'f["\'].*\{(user_?input|user_?msg|user_?message|query|request)\}', re.I),
     'f-string으로 사용자 입력을 LLM 프롬프트에 직접 삽입',
     'AML.T0051.000', 'medium'),

    # T0051.001: 간접 인젝션 — 외부 소스(DB, 파일 등)를 검증 없이 삽입
    (re.compile(r'(retriev|fetch|query|search)\(.*\).*content', re.I),
     '외부 데이터가 검증 없이 LLM 컨텍스트에 삽입 — 간접 인젝션 경로',
     'AML.T0051.001', 'medium'),

    # T0054: Jailbreak — 시스템 프롬프트 방어 부재
    (re.compile(r'system\s*=\s*["\'][^"\']{0,80}["\']', re.I),
     '시스템 프롬프트가 짧거나 약함 — Jailbreak 방어 지침 부재 가능성',
     'AML.T0054', 'low'),

    # T0057: 응답 필터링 없이 LLM 응답 그대로 반환
    (re.compile(r'return\s+(resp|response|reply|output|result)[\s\["\'\.]', re.I),
     'LLM 응답을 필터링 없이 그대로 반환 — 민감 정보 유출 가능',
     'AML.T0057', 'medium'),

    # T0053: 도구 함수 직접 노출
    (re.compile(r'def\s+(transfer|send_money|delete_|execute_sql|run_query)\s*\(', re.I),
     '민감한 도구 함수가 LLM에 직접 노출 가능 — 도구 악용 위험',
     'AML.T0053', 'high'),
]


def scan_code(
    sources: dict[str, str],
    atlas_ids: set[str] | None = None,
) -> list[dict]:
    """레포 소스 dict를 순회하며 취약 패턴 라인을 반환.

    atlas_ids가 주어지면 해당 기법 패턴만, None이면 전체 패턴 검사.
    동일 라인에 여러 패턴이 걸려도 첫 번째 매치만 기록(중복 방지).
    """
    results: list[dict] = []
    seen: set[tuple] = set()  # (file, line) 중복 방지

    for filepath, code in sources.items():
        lines = code.splitlines()
        for lineno, line in enumerate(lines, 1):
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#'):
                continue
            for pattern, reason, atlas_id, severity in _PATTERNS:
                if atlas_ids is not None and atlas_id not in atlas_ids:
                    continue
                if not pattern.search(line):
                    continue
                key = (filepath, lineno)
                if key in seen:
                    break
                seen.add(key)
                results.append({
                    "file":               filepath,
                    "line":               lineno,
                    "snippet":            line_stripped[:200],
                    "reason":             reason,
                    "atlas_technique_id": atlas_id,
                    "severity":           severity,
                })
                break

    _sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    results.sort(key=lambda x: (_sev_order.get(x["severity"], 9), x["file"], x["line"]))
    return results
