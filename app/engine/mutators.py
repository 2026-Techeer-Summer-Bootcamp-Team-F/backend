# -*- coding: utf-8 -*-
"""변이 5연산자. — ARCHITECTURE.md §4.1

우선순위(비용): L0 DB검색(무료) → L1 결정론적(무료) → L2 로컬LLM → L3 Haiku.
  generate_similar / crossover / expand / shorten / rephrase
crossover 는 LLM 불필요(pool 교배). 나머지는 LLM 또는 pgvector 같은계열 검색.
"""


def mutate(seed_text: str, population: list, op: str = "crossover") -> str:
    """seed → 변이 프롬프트. TODO: 연산자별 구현(L0 검색 우선)."""
    raise NotImplementedError("변이 연산자 구현")
