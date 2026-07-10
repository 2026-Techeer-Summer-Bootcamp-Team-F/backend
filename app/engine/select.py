# -*- coding: utf-8 -*-
"""선택 — population 에서 다음 변이 대상. — ARCHITECTURE.md §4 (UCB1 bandit)

UCB1(Auer 2002) / UCT(Kocsis-Szepesvári 2006) = GPTFuzzer selection.py 계보.
탐색(적게 시도한 씨앗)과 활용(점수 높은 씨앗)을 균형 있게 고른다. LLM 불필요.
"""
import math

UCB_C = 1.4   # 탐색 가중치(√2 근사). 클수록 탐색↑


class Node:
    """진화 population 노드 — 씨앗/변이 1개의 UCB 통계. orchestrator가 소유."""
    __slots__ = ("attempt_id", "prompt", "score", "visits", "reward")

    def __init__(self, attempt_id: int, prompt: str, score: float):
        self.attempt_id = attempt_id
        self.prompt = prompt
        self.score = score        # 최근 fitness(엘리티즘 정렬용)
        self.visits = 1           # 선택된 횟수
        self.reward = score       # 누적 보상(자식 점수 역전파)


def ucb(node: Node, step: int) -> float:
    """UCB1 값 = 평균보상 + C·√(ln(step)/visits)."""
    return node.reward / node.visits + UCB_C * math.sqrt(math.log(step + 1) / node.visits)


def select(population: list, step: int = 1) -> Node:
    """population에서 UCB 최댓값 노드 선택(다음 변이 부모). 빈 population이면 None."""
    if not population:
        return None
    return max(population, key=lambda n: ucb(n, step))
