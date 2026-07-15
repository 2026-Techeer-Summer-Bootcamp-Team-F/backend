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
import os
import random
import re

import httpx

from .auth_provider import AuthConfigError, _dig, _secret, make_provider


class Actor:
    async def send(self, prompt: str) -> str:  # pragma: no cover - 인터페이스
        raise NotImplementedError

    async def close(self):  # 정리 훅(브라우저 컨텍스트 등). 기본 no-op — 스캔 종료 시 호출.
        return


class HttpActor(Actor):
    """설정 기반 HTTP 액터.
    config = {url, method, headers, body_template({{prompt}}), response_path,
              delay, max_retries}"""

    def __init__(self, config: dict, cache_key: str = "", transport=None):
        self.url = config["url"].strip()  # 끝/앞 공백 방어(URL 오타 → /chat%20 404 방지)
        # 스캐너가 도커 안이면 표적의 localhost는 '호스트'를 뜻함 → host.docker.internal 로 자동 변환
        # (사용자가 localhost:8100 을 그대로 넣어도 컨테이너에서 호스트 표적에 닿게 함)
        if os.path.exists("/.dockerenv"):
            self.url = re.sub(r"://(localhost|127\.0\.0\.1)\b", "://host.docker.internal", self.url)
        self._transport = transport  # 테스트용 httpx MockTransport 주입 훅(운영은 None)
        self.method = config.get("method", "POST").upper()
        self.headers = config.get("headers", {"Content-Type": "application/json"})
        self.body_template = config.get("body_template", '{"message": "{{prompt}}"}')
        self.response_path = config.get("response_path", "reply")
        self.delay = float(config.get("delay", 0))
        self.max_retries = int(config.get("max_retries", 4))
        # 인증: config.auth 있으면 TokenProvider 생성(없으면 None). cache_key로 스캔당 1회 발급 공유.
        self.auth = make_provider(config.get("auth"), cache_key or self.url)
        # 세션(멀티턴): 응답에서 세션ID 추출→다음 요청 재주입해 대화 상태 유지(#11, 크레센도 토대).
        # config.session = {session_source: header|cookie|body, session_path, inject_header?}
        self._session_cfg = config.get("session") or {}
        self._session_id = None

    def _build_body(self, prompt: str) -> str:
        # JSON 문자열 안전 삽입: prompt를 JSON 인코딩 후 바깥 따옴표 제거해 치환
        safe = json.dumps(prompt)[1:-1]
        return self.body_template.replace("{{prompt}}", safe)

    def _extract(self, data) -> str:
        # response_path로 응답 답변 위치 추출. JSONPath-lite 지원:
        #   dict키(reply·message.content) + 리스트인덱스(choices[0]·choices.0)
        #   + 선택적 '$.' 접두(garak 방식: $.choices[0].message.content).
        # 경로 어긋나면 원본 일부 반환(폴백).
        path = (self.response_path or "").strip().lstrip("$").lstrip(".")
        if not path:
            return data if isinstance(data, str) else json.dumps(data)[:2000]
        cur = data
        for tok in re.findall(r"[^.\[\]]+|\[\d+\]", path):
            idx = int(tok[1:-1]) if tok[0] == "[" else (int(tok) if tok.isdigit() else None)
            if idx is not None and isinstance(cur, list) and -len(cur) <= idx < len(cur):
                cur = cur[idx]
            elif isinstance(cur, dict) and tok in cur:
                cur = cur[tok]
            else:
                return json.dumps(data)[:2000]
        return cur if isinstance(cur, str) else str(cur)

    def _extract_session(self, resp: httpx.Response):
        """응답에서 세션ID 추출(session_source: header|cookie|body + session_path)."""
        src = self._session_cfg.get("session_source")
        path = self._session_cfg.get("session_path", "")
        if not src or not path:
            return None
        if src == "header":
            return resp.headers.get(path)
        if src == "cookie":
            return resp.cookies.get(path)
        if src == "body":
            try:
                return _dig(resp.json(), path)
            except Exception:  # noqa: BLE001 - 비JSON/경로없음
                return None
        return None

    def _inject_session(self, headers: dict) -> dict:
        """보유한 세션ID를 다음 요청에 재주입(cookie면 Cookie 헤더, 아니면 헤더)."""
        if not self._session_id:
            return headers
        src = self._session_cfg.get("session_source")
        path = self._session_cfg.get("session_path", "")
        headers = dict(headers)
        if src == "cookie":
            cur = headers.get("Cookie", "")
            headers["Cookie"] = (cur + "; " if cur else "") + f"{path}={self._session_id}"
        else:
            # header면 같은 헤더명으로, body면 지정 inject_header(기본 X-Session-Id)로 재주입
            name = path if src == "header" else self._session_cfg.get("inject_header", "X-Session-Id")
            headers[name] = self._session_id
        return headers

    async def send(self, prompt: str) -> str:
        if self.delay:
            await asyncio.sleep(self.delay)
        body = self._build_body(prompt)
        reauthed = False  # 401 강제 재인증은 1회만(무한루프 금지)
        async with httpx.AsyncClient(timeout=30, transport=self._transport) as client:
            for attempt in range(self.max_retries):
                try:
                    # 요청 직전 토큰 주입 — inject.in=header|query|body 지원(토큰 갱신 반영) + 세션 재주입
                    if self.auth:
                        headers, url, req_body = await self.auth.apply_request(
                            self.headers, self.url, body, self.method)
                    else:
                        headers, url, req_body = self.headers, self.url, body
                    headers = self._inject_session(headers)
                    resp = await client.request(
                        self.method, url, headers=headers, content=req_body.encode())
                    # 401/403: 토큰 만료/무효 → 1회만 강제 재인증 후 재발사 (raise 이전에 가로채기)
                    if resp.status_code in (401, 403):
                        if self.auth and not reauthed:
                            await self.auth.invalidate()
                            reauthed = True
                            continue
                        return f"[ACTOR_ERROR] auth_denied ({resp.status_code})"
                    # 429/rate-limit: 서버 지정 대기 + 지터
                    if resp.status_code == 429 or resp.headers.get("x-ratelimit-remaining") == "0":
                        await asyncio.sleep(self._retry_after(resp, attempt))
                        continue
                    # 일시적 5xx: 지수백오프
                    if resp.status_code in (502, 503, 504):
                        await asyncio.sleep(min(2 ** attempt, 8) + random.uniform(0, 0.5))
                        continue
                    resp.raise_for_status()
                    # 세션ID 추출→보관(다음 send에 재주입, 멀티턴 상태유지)
                    sid = self._extract_session(resp)
                    if sid:
                        self._session_id = sid
                    try:
                        return self._extract(resp.json())
                    except json.JSONDecodeError:
                        return resp.text[:2000]
                except AuthConfigError as e:
                    return f"[ACTOR_ERROR] auth_config: {e}"
                except httpx.HTTPStatusError as e:
                    # 상태 코드 + 응답 일부를 포함해 원인 파악 용이
                    body_preview = e.response.text[:120].replace("\n", " ")
                    return f"[ACTOR_ERROR] HTTP {e.response.status_code}: {body_preview}"
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
              wait_ms?, headless?, max_retries?,
              storage_state?, login?, reuse_page?}

    인증/세션(HTTP와 다름 — 액터-인증-설계 §12):
      - storage_state: 이미 로그인한 브라우저 쿠키/스토리지(JSON dict/파일경로) 주입 → 그 상태로 시작
      - login: {url, user_selector, pass_selector, submit_selector?, username, password_env}
      - 브라우저는 쿠키를 컨텍스트에 자동 보관 → **컨텍스트 재사용으로 멀티턴 세션 유지**(HTTP의 auth/session 필드 안 씀)
      - reuse_page: true면 첫 턴만 goto(SPA 인페이지 멀티턴), 기본은 매 턴 로드(쿠키는 유지)
    ⚠️ 의존성: pip install playwright && playwright install chromium
       (미설치 시 명확한 에러 반환 → 데모는 HttpActor로.)"""

    def __init__(self, config: dict):
        self.url = config["url"]
        self.input_selector = config["input_selector"]
        self.submit_selector = config.get("submit_selector")  # 없으면 Enter 키
        self.output_selector = config["output_selector"]
        self.wait_ms = int(config.get("wait_ms", 8000))
        self.headless = bool(config.get("headless", True))
        self.max_retries = int(config.get("max_retries", 2))
        self.storage_state = config.get("storage_state")   # dict(JSON) 또는 파일경로
        self.login_cfg = config.get("login")               # 로그인 플로우(선택)
        self.reuse_page = bool(config.get("reuse_page", False))
        # 컨텍스트 재사용(멀티턴 쿠키 유지)용 상태 — lazy 기동
        self._pw = self._browser = self._context = self._page = None
        self._navigated = False

    async def _ensure(self):
        """최초 send에서 브라우저/컨텍스트/페이지 lazy 기동 + (있으면) 로그인. 이후 재사용."""
        if self._page is not None:
            return
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=self.headless)
        ctx_kw = {}
        if self.storage_state:
            ctx_kw["storage_state"] = self.storage_state   # 쿠키/스토리지 주입 = 로그인 상태로 시작
        self._context = await self._browser.new_context(**ctx_kw)
        self._page = await self._context.new_page()
        if self.login_cfg:
            await self._do_login()

    async def _do_login(self):
        """로그인 페이지에서 아이디/비번(env) 타이핑 → 제출. 쿠키는 컨텍스트에 자동 저장."""
        lc = self.login_cfg
        pw = _secret(lc, "password", "password_env")
        await self._page.goto(lc["url"], wait_until="domcontentloaded")
        await self._page.fill(lc["user_selector"], lc.get("username", ""))
        await self._page.fill(lc["pass_selector"], pw)
        if lc.get("submit_selector"):
            await self._page.click(lc["submit_selector"])
        else:
            await self._page.press(lc["pass_selector"], "Enter")
        await self._page.wait_for_timeout(1000)

    async def send(self, prompt: str) -> str:
        try:
            await self._ensure()
        except ImportError:
            return ("[ACTOR_ERROR] playwright 미설치 "
                    "(pip install playwright && playwright install chromium)")
        except AuthConfigError as e:
            return f"[ACTOR_ERROR] auth_config: {e}"
        except Exception as e:  # noqa: BLE001 - 기동/로그인 실패 타입 다양
            await self.close()
            return f"[ACTOR_ERROR] browser_init {type(e).__name__}: {str(e)[:100]}"

        for attempt in range(self.max_retries):
            try:
                page = self._page
                # reuse_page면 첫 턴만 goto(인페이지 멀티턴), 아니면 매 턴 로드(쿠키=세션은 유지)
                if not (self.reuse_page and self._navigated):
                    await page.goto(self.url, wait_until="domcontentloaded")
                    self._navigated = True
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
            except Exception as e:  # noqa: BLE001 - 브라우저 실패 타입 다양, 재시도 후 리턴
                if attempt == self.max_retries - 1:
                    return f"[ACTOR_ERROR] {type(e).__name__}: {str(e)[:120]}"
                await asyncio.sleep(1 + attempt)
        return "[ACTOR_ERROR] browser retries exhausted"

    async def close(self):
        """스캔 종료 시 정리(컨텍스트/브라우저/playwright). 재호출 안전."""
        for obj, meth in ((self._context, "close"), (self._browser, "close"), (self._pw, "stop")):
            try:
                if obj is not None:
                    await getattr(obj, meth)()
            except Exception:  # noqa: BLE001 - 정리 실패는 무시
                pass
        self._pw = self._browser = self._context = self._page = None


def make_actor(target) -> Actor:
    """팩토리: target.config.actor_type 으로 분기 (http | browser).

    엔진은 send(prompt)->response 만 알고, 대상별 연결 방식은 액터가 캡슐화.
    actor_type은 DB 컬럼이 아니라 config(JSON) 안에 있다(스키마 정합). 기본 http.
    """
    config = target.config or {}
    actor_type = config.get("actor_type", "http")
    if actor_type == "http":
        # cache_key = target_id + auth지문 → 액터가 objective마다 재생성돼도 토큰 캐시 공유(스캔당 1회 발급)
        tid = getattr(target, "target_id", "x")
        auth = config.get("auth") or {}
        cache_key = f"{tid}:{auth.get('type', 'none')}:{auth.get('role', '')}"
        return HttpActor(config, cache_key=cache_key)
    if actor_type == "browser":
        return BrowserActor(config)
    raise NotImplementedError(f"actor_type={actor_type} 미지원 (http|browser)")
