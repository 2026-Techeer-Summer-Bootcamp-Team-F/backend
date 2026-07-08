# -*- coding: utf-8 -*-
"""씨앗 검색 (벡터 코퍼스). — 차별점. ARCHITECTURE.md §2 (씨앗 검색)

objective(목표) → attack_cases 에서 관련 공격 K개.
- PoC: 메타필터(attack_type=) + (선택)브루트포스 코사인. 21k 규모면 즉시.
- 운영: pgvector + HNSW(cosine) ANN.
- verified=true 우선(검증 씨앗). 임베딩은 embedding 컬럼(384d).
코퍼스 적재: corpus_ingest.py / 임베딩: embed.py (별도 파이프라인 산출물).
"""
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..models import AttackCase


def retrieve_seeds(db: Session, attack_type: str, k: int = 8, verified_only: bool = False):
    """유형별 씨앗 K개. TODO: 쿼리 임베딩 유사도 랭킹 추가(지금은 메타필터).
    운영 전환 시 pgvector `embedding <=> :qvec` ORDER BY 로 교체."""
    stmt = sa_select(AttackCase).where(AttackCase.attack_type == attack_type)
    if verified_only:
        stmt = stmt.where(AttackCase.verified.is_(True))
    return db.execute(stmt.limit(k)).scalars().all()
