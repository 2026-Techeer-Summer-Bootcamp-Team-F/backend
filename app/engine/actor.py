# -*- coding: utf-8 -*-
"""액터 — 대상 연결 어댑터. 엔진은 send(prompt)->response 만 안다 (기획 §5.6).

밴 회피(429/Retry-After/지터/지수백오프/max_retries)를 액터 내부에 캡슐화
(promptfoo `util/fetch` 방식). 같은 래퍼를 공격자/판정 LLM 호출에도 재사용 가능.

⚠️ 스키마 정합: `actor_type`은 별도 컬럼이 아니라 `target.config` 안에 있다
(target_projects엔 config JSON 한 컬럼만). make_actor가 config에서 꺼내 분기.
(BrowserActor: 구현만 해두고 시연은 HttpActor — 공격시나리오-설계.md §8 후순위.)
"""
import asyncio
import json
import random

import httpx


class Actor:
    async def send(self, prompt: str) -> str:  # pragma: no cover - 인터페이스
        raise NotImplementedError


class HttpActor(Actor):
    """설정 기반 HTTP 액터.
    config = {url, method, headers, body_template({{prompt}}), response_path,
              delay, max_retries}"""

    def __init__(self, config: dict):
        self.url = config["url"]
        self.method = config.get("method", "POST").upper()
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.body_template = config.get("body_template", '{"message": "{{prompt}}"}')
        self.response_path = config.get("response_path", "reply")
        self.delay = float(config.get("delay", 0))
        self.max_retries = int(config.get("max_retries", 4))

    def _build_body(self, prompt: str) -> str:
        # JSON 문자열 안전 삽입: prompt를 JSON 인코딩 후 바깥 따옴표 제거해 치환
        safe = json.dumps(prompt)[1:-1]
        return self.body_template.replace("{{prompt}}", safe)

    def _extract(self, data) -> str:
        # response_path(dot-path)로 응답 답변 위치 추출. 경로 어긋나면 원본 일부 반환.
        cur = data
        for key in self.response_path.split("."):
            if isinstance(cur, dict) and key in cur:
                cur = cur[key]
            else:
                return json.dumps(data)[:2000]
        return str(cur)

    async def send(self, prompt: str) -> str:
        if self.delay:
            await asyncio.sleep(self.delay)
        body = self._build_body(prompt)
        async with httpx.AsyncClient(timeout=30) as client:
            for attempt in range(self.max_retries):
                try:
                    resp = await client.request(
                        self.method, self.url, headers=self.headers, content=body.encode())
                    # 429/rate-limit: 서버 지정 대기 + 지터
                    if resp.status_code == 429 or resp.headers.get("x-ratelimit-remaining") == "0":
                        await asyncio.sleep(self._retry_after(resp, attempt))
                        continue
                    # 일시적 5xx: 지수백오프
                    if resp.status_code in (502, 503, 504):
                        await asyncio.sleep(min(2 ** attempt, 8) + random.uniform(0, 0.5))
                        continue
                    resp.raise_for_status()
                    try:
                        return self._extract(resp.json())
                    except json.JSONDecodeError:
                        return resp.text[:2000]
                except httpx.HTTPError as e:
                    if attempt == self.max_retries - 1:
                        return f"[ACTOR_ERROR] {type(e).__name__}"
                    await asyncio.sleep(min(2 ** attempt, 8) + random.uniform(0, 0.5))
        return "[ACTOR_ERROR] retries exhausted"

    @staticmethod
    def _retry_after(resp: httpx.Response, attempt: int) -> float:
        # 서버가 알려준 정확한 대기 + 지터(retry storm 방지)
        ra = resp.headers.get("Retry-After") or resp.headers.get("X-RateLimit-Reset")
        base = float(ra) if (ra and ra.isdigit()) else float(2 ** attempt)
        return base + random.uniform(0, 1)


class BrowserActor(Actor):
    """UI 자동화 액터 — API 없는 채팅 화면을 Playwright로 조종.
    promptfoo `browser.ts`(type→click→extract) / PyRIT `playwright_target.py` 패턴.
    config = {url, input_selector, submit_selector?, output_selector,
              wait_ms?, headless?, max_retries?}
    ⚠️ 의존성: pip install playwright && playwright install chromium
       (미설치 시 명확한 에러 반환 → 데모는 HttpActor로, 이건 구현만.)"""

    def __init__(self, config: dict):
        self.url = config["url"]
        self.input_selector = config["input_selector"]
        self.submit_selector = config.get("submit_selector")  # 없으면 Enter 키
        self.output_selector = config["output_selector"]
        self.wait_ms = int(config.get("wait_ms", 8000))
        self.headless = bool(config.get("headless", True))
        self.max_retries = int(config.get("max_retries", 2))

    async def send(self, prompt: str) -> str:
        try:
            from playwright.async_api import async_playwright
        except ImportError:
            return ("[ACTOR_ERROR] playwright 미설치 "
                    "(pip install playwright && playwright install chromium)")
        for attempt in range(self.max_retries):
            try:
                async with async_playwright() as p:
                    browser = await p.chromium.launch(headless=self.headless)
                    try:
                        page = await browser.new_page()
                        await page.goto(self.url, wait_until="domcontentloaded")
                        # 1) 입력창에 공격 프롬프트 타이핑
                        await page.wait_for_selector(self.input_selector, timeout=self.wait_ms)
                        await page.fill(self.input_selector, prompt)
                        # 2) 전송 (전송 버튼 클릭 또는 Enter)
                        if self.submit_selector:
                            await page.click(self.submit_selector)
                        else:
                            await page.press(self.input_selector, "Enter")
                        # 3) 응답 말풍선 대기 → 스트리밍 안정화 후 텍스트 추출
                        await page.wait_for_selector(self.output_selector, timeout=self.wait_ms)
                        await page.wait_for_timeout(500)
                        text = await page.eval_on_selector(
                            self.output_selector, "el => el.textContent")
                        return (text or "").strip()[:4000]
                    finally:
                        await browser.close()
            except Exception as e:  # noqa: BLE001 - 브라우저 실패 타입 다양, 재시도 후 리턴
                if attempt == self.max_retries - 1:
                    return f"[ACTOR_ERROR] {type(e).__name__}: {str(e)[:120]}"
                await asyncio.sleep(1 + attempt)
        return "[ACTOR_ERROR] browser retries exhausted"


def make_actor(target) -> Actor:
    """팩토리: target.config.actor_type 으로 분기 (http | browser).

    엔진은 send(prompt)->response 만 알고, 대상별 연결 방식은 액터가 캡슐화.
    actor_type은 DB 컬럼이 아니라 config(JSON) 안에 있다(스키마 정합). 기본 http.
    """
    config = target.config or {}
    actor_type = config.get("actor_type", "http")
    if actor_type == "http":
        return HttpActor(config)
    if actor_type == "browser":
        return BrowserActor(config)
    raise NotImplementedError(f"actor_type={actor_type} 미지원 (http|browser)")
