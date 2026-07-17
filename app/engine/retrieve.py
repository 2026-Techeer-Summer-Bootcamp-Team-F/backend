# -*- coding: utf-8 -*-
"""씨앗 검색 (벡터 코퍼스). — 차별점. ARCHITECTURE.md §2 (씨앗 검색)

objective(목표) + 정찰정보 → attack_cases 에서 관련 공격 K개.
- 기본(플래그 OFF): 메타필터(atlas_technique_id 또는 attack_type) + verified 우선 + 무작위 다양성.
- 벡터(RETRIEVE_VECTOR_ENABLED, #130): 정찰정보로 만든 질의를 임베딩 → attack_type 선필터한
  후보들을 attack_cases.embedding(384d JSON)으로 코사인 랭킹(기획 §5.2 "메타필터→벡터랭킹").
  * attack_embeddings(pgvector) 테이블 없이도 동작(어느 DB에나 있는 JSON 임베딩 사용) → CI/새DB OK.
  * 임베딩 못 만들거나(fastembed 미로드) 후보 임베딩 없음 → 메타필터로 자동 폴백(안 죽음).
- verified=true(실전 검증 씨앗) 우선 = 성공가중치. 매칭 없으면 전체에서 폴백.
코퍼스 적재: scripts/load_corpus.py (attack_cases.embedding 포함).
"""
import logging

from sqlalchemy import func
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import AttackCase
from .embed import embed_query

log = logging.getLogger("redteam.retrieve")

_VERIFIED_BONUS = 0.05   # 검증 씨앗 코사인 가산(성공가중치) — 동점 근처에서 verified 선호


def retrieve_seeds(db: Session, atlas_id: str = None, attack_type: str = None,
                   k: int = 8, query_text: str = None) -> list:
    """objective(atlas_id 우선, 없으면 attack_type) → 씨앗 K개.

    RETRIEVE_VECTOR_ENABLED + query_text 있으면 벡터 의미검색 먼저 시도(실패 시 메타필터 폴백).
    verified 우선 → 무작위(다양성). 매칭 0건이면 전체 코퍼스에서 폴백(빈 population 방지).
    """
    if settings.retrieve_vector_enabled and query_text:
        seeds = _vector_retrieve(db, atlas_id, attack_type, k, query_text)
        if seeds:
            return seeds
        # 벡터 실패(임베딩 불가/후보 없음) → 아래 메타필터로 폴백

    return _metadata_retrieve(db, atlas_id, attack_type, k)


def _metadata_retrieve(db, atlas_id, attack_type, k) -> list:
    """기존 방식: 카테고리 필터 + verified 우선 + 무작위. 정렬/LIMIT을 SQL로 밀어 21k를 안 퍼올림."""
    order = (AttackCase.verified.desc(), func.random())
    stmt = sa_select(AttackCase)
    if atlas_id:
        stmt = stmt.where(AttackCase.atlas_technique_id == atlas_id)
    elif attack_type:
        stmt = stmt.where(AttackCase.attack_type == attack_type)
    cases = db.execute(stmt.order_by(*order).limit(k)).scalars().all()

    if not cases and (atlas_id or attack_type):   # 카테고리 미스 → 전체에서 폴백
        cases = db.execute(
            sa_select(AttackCase).order_by(*order).limit(k)).scalars().all()
    return cases


def _vector_retrieve(db, atlas_id, attack_type, k, query_text) -> list:
    """정찰 질의 임베딩 → 카테고리 선필터 후보를 코사인 랭킹 → top-k. 실패 시 None(→ 폴백)."""
    qv = embed_query(query_text)
    if qv is None:
        return None
    try:
        import numpy as np
    except Exception:   # noqa: BLE001 - numpy 없으면(플래그 off 배포) 폴백
        return None

    q = np.asarray(qv, dtype="float32")
    qn = float(np.linalg.norm(q))
    if qn == 0.0:
        return None

    # 후보 선필터: 카테고리 + 임베딩 있는 것만. verified 우선으로 상한만큼(메모리/시간 캡).
    stmt = sa_select(AttackCase).where(AttackCase.embedding.isnot(None))
    if atlas_id:
        stmt = stmt.where(AttackCase.atlas_technique_id == atlas_id)
    elif attack_type:
        stmt = stmt.where(AttackCase.attack_type == attack_type)
    stmt = stmt.order_by(AttackCase.verified.desc()).limit(settings.retrieve_candidate_cap)
    cands = db.execute(stmt).scalars().all()
    if not cands:
        return None

    scored = []
    dim = len(qv)
    for c in cands:
        emb = c.embedding
        if not emb or len(emb) != dim:
            continue
        v = np.asarray(emb, dtype="float32")
        vn = float(np.linalg.norm(v))
        if vn == 0.0:
            continue
        sim = float(q.dot(v)) / (qn * vn)
        if c.verified:
            sim += _VERIFIED_BONUS
        scored.append((sim, c))

    if not scored:
        return None
    scored.sort(key=lambda t: t[0], reverse=True)
    top = [c for _, c in scored[:k]]
    log.info("retrieve(벡터): 후보 %d → top %d (atlas=%s)", len(scored), len(top), atlas_id)
    return top
