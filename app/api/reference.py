# -*- coding: utf-8 -*-
"""참조/상세 API — attack-types·atlas·진화트리·시도상세. — API-명세 §3-1·§5·§6

- GET /attack-types : 스캔 시작 화면 공격유형 체크박스 목록(엔진이 실제 매핑하는 유형)
- GET /atlas        : ATLAS 기법 마스터 목록(히트맵/참조)
- GET /objectives/{id}/tree : 진화 트리(parent_id 계보) — 프론트 EvolutionTree
- GET /attempts/{id}        : 시도 상세 — 프론트 EvidenceViewer
전부 읽기 전용. 린 스키마로 구현(마이그레이션 없음).
"""
from fastapi import APIRouter, Depends
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..authz import attempt_owned_or_404, objective_owned_or_404
from ..db import get_db
from ..deps import get_current_user
from ..models import Attempt, AtlasTechnique, Objective, User
from ..recon import _TYPE_TO_ATLAS

router = APIRouter(tags=["reference"])

# 공격유형 라벨(엔진 recon._TYPE_TO_ATLAS 키와 1:1 — 실제 매핑되는 유형만 노출)
_ATTACK_TYPE_LABELS = {
    "jailbreak": "탈옥 (Jailbreak)",
    "prompt_injection": "프롬프트 인젝션",
    "direct_injection": "직접 프롬프트 인젝션",
    "indirect_injection": "간접 프롬프트 인젝션",
    "rag_injection": "RAG 간접 인젝션",
    "data_leakage": "데이터 유출",
    "system_prompt_leak": "시스템 프롬프트 유출",
    "prompt_leak": "프롬프트 유출",
    "tool_misuse": "도구 오용",
    "excessive_agency": "과잉 권한(에이전트)",
    "pii": "PII 유출",
    "pii_leak": "PII 유출(민감정보)",
}


@router.get("/attack-types")
def attack_types(_: User = Depends(get_current_user)):
    """스캔 시작 화면 공격유형 체크박스 목록. key=요청값, atlas=매핑 기법."""
    return [{"key": k, "label": _ATTACK_TYPE_LABELS.get(k, k), "atlas_technique_id": a}
            for k, a in _TYPE_TO_ATLAS.items()]


@router.get("/atlas")
def atlas(db: Session = Depends(get_db), _: User = Depends(get_current_user)):
    """ATLAS 기법 마스터 목록(id·이름·전술·분류·완화책)."""
    techs = db.scalars(sa_select(AtlasTechnique).order_by(AtlasTechnique.id)).all()
    return [{"id": t.id, "name": t.name, "tactic": t.tactic, "category": t.category,
             "description": t.description, "mitigation": t.mitigation} for t in techs]


@router.get("/objectives/{objective_id}/tree")
def objective_tree(objective_id: int, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """진화 트리 — 한 목표의 attempt 계보(parent_id). 프론트가 트리로 렌더. 소유권 검증(#91). — §5"""
    obj = objective_owned_or_404(db, objective_id, user)
    attempts = db.scalars(
        sa_select(Attempt).where(Attempt.objective_id == objective_id)
        .order_by(Attempt.attempt_id)).all()
    nodes = [{
        "attempt_id": a.attempt_id, "parent_id": a.parent_id,
        "generation": a.generation, "mutation_op": a.mutation_op or "seed",
        "score": a.fitness, "breached": a.breached,
        "prompt": (a.prompt_text or "")[:200],
    } for a in attempts]
    return {"objective_id": objective_id, "atlas_technique_id": obj.atlas_technique_id,
            "status": obj.status, "nodes": nodes}


@router.get("/attempts/{attempt_id}")
def attempt_detail(attempt_id: int, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """시도 상세 — 프롬프트·응답·판정·계보. 프론트 EvidenceViewer. 소유권 검증(#91). — §5"""
    at = attempt_owned_or_404(db, attempt_id, user)
    obj = db.get(Objective, at.objective_id)
    return {
        "attempt_id": at.attempt_id, "objective_id": at.objective_id,
        "parent_id": at.parent_id, "generation": at.generation,
        "mutation_op": at.mutation_op or "seed",
        "prompt": at.prompt_text, "response": at.response_text,
        "score": at.fitness, "verdict": "breach" if at.breached else "safe",
        "atlas_technique_id": obj.atlas_technique_id if obj else None,
        "created_at": at.created_at,
    }
