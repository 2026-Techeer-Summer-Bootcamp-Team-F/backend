# -*- coding: utf-8 -*-
"""액터 — 표적에 공격 발사. — ARCHITECTURE.md §7 (밴 회피)

HttpActor: POST {target_url} {"message": prompt} → 응답 텍스트.
429=Retry-After+지터, 502/503/504=지수백오프, 밴=즉시실패. rate-limit 좌표는 Redis.
(BrowserActor: Playwright UI 자동화 — 후순위.)
"""
import httpx


class HttpActor:
    def __init__(self, max_retries: int = 4, timeout: float = 30.0):
        self.max_retries = max_retries
        self.timeout = timeout

    async def fire(self, target_url: str, prompt: str) -> str:
        """공격 1발. TODO: 429/5xx 백오프+지터, 밴 감지 캡슐화(§7.1)."""
        async with httpx.AsyncClient(timeout=self.timeout) as client:
            resp = await client.post(target_url, json={"message": prompt})
            return resp.text
