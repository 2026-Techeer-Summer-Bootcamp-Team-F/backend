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

from sqlalchemy import func, text
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
    """질의 임베딩 → 벡터 최근접 top-k. 실패 시 None(→ 메타필터 폴백).

    - PostgreSQL(운영): pgvector `<=>`(코사인) + HNSW 인덱스로 DB단 최근접.
    - 그 외(SQLite/CI) 또는 pg 경로 실패: 앱단 numpy 코사인 폴백(이식성).
    """
    qv = embed_query(query_text)
    if qv is None:
        return None
    # 운영(PostgreSQL): pgvector HNSW 우선
    try:
        if db.get_bind().dialect.name == "postgresql":
            res = _pgvector_retrieve(db, atlas_id, attack_type, k, qv)
            if res:
                return res
    except Exception as e:  # noqa: BLE001 - pgvector 경로 실패 → numpy 폴백(안 죽음)
        log.warning("retrieve: pgvector 경로 실패 → numpy 폴백: %s", e)
    return _numpy_retrieve(db, atlas_id, attack_type, k, qv)


def _pgvector_retrieve(db, atlas_id, attack_type, k, qv) -> list:
    """attack_embeddings(vector 384) 코사인 최근접 → top-k. HNSW 인덱스 사용.

    질의 벡터는 런타임 생성값(embed_query) → pgvector 리터럴로 바인딩.
    인덱스 유지 위해 순수 `<=>` 거리로 상위 후보를 뽑고, verified 보너스는 파이썬 재랭킹.
    """
    lit = "[" + ",".join(repr(float(x)) for x in qv) + "]"
    where = ""
    params = {"qv": lit}
    if atlas_id:
        where = "where ac.atlas_technique_id = :atlas"
        params["atlas"] = atlas_id
    elif attack_type:
        where = "where ac.attack_type = :atype"
        params["atype"] = attack_type
    params["fetch"] = min(max(k * 4, k), settings.retrieve_candidate_cap)
    sql = text(
        "select ac.id as id, ac.verified as verified, "
        "(ae.embedding <=> (:qv)::vector) as dist "
        "from attack_embeddings ae join attack_cases ac on ac.id = ae.attack_case_id "
        f"{where} "
        "order by ae.embedding <=> (:qv)::vector limit :fetch"
    )
    # 카테고리 필터 + HNSW: iterative scan(pgvector 0.8+)이라야 필터된 최근접이 제대로 나온다.
    # (없으면 global 최근접이 다수 유형(prompt_injection)에 쏠려 소수 유형은 0건.) SAVEPOINT로 실패 격리.
    with db.begin_nested():
        db.execute(text("set local hnsw.iterative_scan = relaxed_order"))
        rows = db.execute(sql, params).fetchall()
    if not rows:
        return None
    ranked = sorted(rows, key=lambda r: r.dist - (_VERIFIED_BONUS if r.verified else 0.0))
    ids = [r.id for r in ranked[:k]]
    objs = db.execute(sa_select(AttackCase).where(AttackCase.id.in_(ids))).scalars().all()
    by_id = {o.id: o for o in objs}
    result = [by_id[i] for i in ids if i in by_id]
    log.info("retrieve(pgvector HNSW): 후보 %d → top %d (atlas=%s)", len(rows), len(result), atlas_id)
    return result


def _numpy_retrieve(db, atlas_id, attack_type, k, qv) -> list:
    """앱단 numpy 코사인 폴백(pgvector 없는 DB/CI). 카테고리 선필터 후보를 랭킹."""
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
    log.info("retrieve(numpy 폴백): 후보 %d → top %d (atlas=%s)", len(scored), len(top), atlas_id)
    return top
