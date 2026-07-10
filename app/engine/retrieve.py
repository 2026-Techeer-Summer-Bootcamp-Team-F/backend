# -*- coding: utf-8 -*-
"""씨앗 검색 (벡터 코퍼스). — 차별점. ARCHITECTURE.md §2 (씨앗 검색)

objective(목표) → attack_cases 에서 관련 공격 K개.
- 지금: 메타필터(atlas_technique_id 또는 attack_type) + verified 우선 + 무작위 다양성.
  정렬/LIMIT을 SQL로 밀어 21k 전체를 메모리에 안 퍼올린다.
- 운영: pgvector + HNSW(cosine) — `embedding <=> :qvec ORDER BY` 로 벡터 랭킹 교체(embedding 384d).
- verified=true(실전 검증 씨앗) 우선 = 성공가중치. 매칭 없으면 전체에서 폴백.
코퍼스 적재: scripts/load_corpus.py / 임베딩: embed.py (별도 파이프라인 산출물).
"""
from sqlalchemy import func
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..models import AttackCase


def retrieve_seeds(db: Session, atlas_id: str = None, attack_type: str = None,
                   k: int = 8) -> list:
    """objective(atlas_id 우선, 없으면 attack_type) → 씨앗 K개.

    verified 우선 → 무작위(다양성). 매칭 0건이면 전체 코퍼스에서 폴백(빈 population 방지).
    """
    # verified=True 먼저(내림차순), 그 안에서 무작위 → 검증 씨앗 우선 + 다양성
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
