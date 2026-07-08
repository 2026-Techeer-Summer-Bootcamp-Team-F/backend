# -*- coding: utf-8 -*-
"""정찰(Recon) — 표적 프로파일 추출. — ARCHITECTURE.md §2 (5.정찰)

등록입력 + 리포분석(grep+AST) + 블랙박스 프로빙 → {model, purpose, defenses, tools}.
POST /projects/{id}/recon 에서 호출 → TargetProject 필드 갱신.
"""


def profile_target(target) -> dict:
    """표적 → 프로파일 dict. TODO: repo grep/AST + 블랙박스 프로빙. 후순위."""
    return {"model": "", "purpose": "", "defences": {}, "tools": {}, "rag_sources": {}}
