# -*- coding: utf-8 -*-
"""선택 — population 에서 다음 변이 대상. — ARCHITECTURE.md §4 (UCB/MCTS bandit)"""


def select(population: list):
    """점수 기반 선택. TODO: UCB1/MCTS. 지금은 최고점수 탐욕(placeholder)."""
    if not population:
        return None
    return max(population, key=lambda x: getattr(x, "fitness", 0.0))
