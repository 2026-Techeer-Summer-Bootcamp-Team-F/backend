# -*- coding: utf-8 -*-
"""액터 인증 — 토큰 발급/캐시/갱신/주입. 액터-인증-설계.md 구현.

액터는 `provider.apply(headers)`만 부른다(엔진↔액터 분리 철학과 동일: 액터는
"어떻게 붙이는지" 몰라도 됨). type별 구현체가 `_fetch()`만 채우고, 캐시·갱신·
동시성(herd 방지)은 공통.

비밀은 값이 아니라 **env 변수 이름**으로 참조(`*_env`) — DB(config JSON) 평문 저장 금지.
3.9 호환. promptfoo HTTP provider(OAuth 자동발급+만료 60초前 갱신) 패턴 차용,
단 선언적 config만(임의코드 실행 배제).
"""
import asyncio
import logging
import os
import random
import time
from dataclasses import dataclass
from typing import Optional

import httpx

log = logging.getLogger("redteam.auth")


class AuthConfigError(Exception):
    """auth config 오설정(누락 필드·env 미설정 등) → 프리플라이트에서 조기 실패."""


@dataclass
class TokenState:
    value: str
    expires_at: float   # epoch seconds (절대시각)


# ── 모듈 전역 캐시 + 키별 락 (target_id+auth지문 키로 스캔당 1회 발급 공유) ──
_CACHE = {}   # cache_key -> TokenState
_LOCKS = {}   # cache_key -> asyncio.Lock


def _lock_for(key: str) -> asyncio.Lock:
    return _LOCKS.setdefault(key, asyncio.Lock())


def _secret(cfg: dict, val_key: str, env_key: str) -> str:
    """env 참조 우선(표준). 값 직접입력은 하위호환+경고. 둘 다 없으면 오류."""
    if cfg.get(env_key):
        v = os.environ.get(cfg[env_key], "")
        if not v:
            raise AuthConfigError(f"env {cfg[env_key]} 미설정")
        return v
    if cfg.get(val_key):
        log.warning("auth 비밀을 config에 평문 저장 중 — %s_env 사용 권장", val_key)
        return cfg[val_key]
    raise AuthConfigError(f"{val_key} 또는 {env_key} 필요")


def _dig(data, path: str):
    """응답 JSON에서 dot-path 추출(login 토큰/만료 위치). 실패 시 None."""
    cur = data
    for key in path.split("."):
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        elif isinstance(cur, list) and key.isdigit() and int(key) < len(cur):
            cur = cur[int(key)]
        else:
            return None
    return cur


async def _request_with_backoff(method: str, url: str, **kw) -> httpx.Response:
    """토큰 발급 요청 — 429/5xx 백오프+지터(actor.send와 동일 정책). 발급용 짧은 타임아웃."""
    timeout = kw.pop("timeout", 15)
    max_retries = kw.pop("max_retries", 4)
    async with httpx.AsyncClient(timeout=timeout) as client:
        for attempt in range(max_retries):
            resp = await client.request(method, url, **kw)
            if resp.status_code == 429:
                ra = resp.headers.get("Retry-After")
                base = float(ra) if (ra and ra.isdigit()) else float(2 ** attempt)
                await asyncio.sleep(base + random.uniform(0, 1))
                continue
            if resp.status_code in (502, 503, 504):
                await asyncio.sleep(min(2 ** attempt, 8) + random.uniform(0, 0.5))
                continue
            return resp
    raise AuthConfigError(f"토큰 발급 실패(재시도 소진): {url}")


class TokenProvider:
    """type별 구현체가 _fetch()만 채운다. 캐시·갱신·동시성은 공통."""
    REFRESH_BUFFER = 60  # 만료 60초 전 갱신 (promptfoo 동일)

    def __init__(self, cfg: dict, cache_key: str):
        self.cfg = cfg
        self.cache_key = cache_key
        self._inject = cfg.get("inject", {"in": "header",
                                          "name": "Authorization",
                                          "format": "Bearer {token}"})

    async def token(self) -> str:
        st = _CACHE.get(self.cache_key)
        if st and time.time() < st.expires_at - self.REFRESH_BUFFER:
            return st.value
        async with _lock_for(self.cache_key):          # thundering herd 방지
            st = _CACHE.get(self.cache_key)             # 락 안에서 재확인(double-check)
            if st and time.time() < st.expires_at - self.REFRESH_BUFFER:
                return st.value
            st = await self._fetch()
            _CACHE[self.cache_key] = st
            return st.value

    async def invalidate(self):                         # 401 강제 갱신용
        _CACHE.pop(self.cache_key, None)

    async def apply(self, headers: dict) -> dict:       # 요청 직전 헤더 주입
        tok = await self.token()
        inj = self._inject
        if inj.get("in", "header") == "header":
            headers = dict(headers)
            headers[inj["name"]] = inj["format"].replace("{token}", tok)
        return headers                                  # query/body 주입은 액터 send에서

    async def _fetch(self) -> TokenState:               # 구현체가 오버라이드
        raise NotImplementedError


class BearerProvider(TokenProvider):
    """정적 토큰 1개(env). 발급 불필요 → 먼 미래 만료로 캐시."""
    async def _fetch(self) -> TokenState:
        tok = _secret(self.cfg, "token", "token_env")
        return TokenState(tok, time.time() + 10 ** 9)


class ApiKeyProvider(TokenProvider):
    """API 키(env). 기본 주입=헤더(name은 inject로 지정, 기본 X-API-Key/{token})."""
    def __init__(self, cfg: dict, cache_key: str):
        cfg = dict(cfg)
        cfg.setdefault("inject", {"in": "header", "name": "X-API-Key", "format": "{token}"})
        super().__init__(cfg, cache_key)

    async def _fetch(self) -> TokenState:
        key = _secret(self.cfg, "key", "key_env")
        return TokenState(key, time.time() + 10 ** 9)


class OAuth2ClientProvider(TokenProvider):
    """client_credentials grant → token_url에서 자동 발급/갱신."""
    async def _fetch(self) -> TokenState:
        data = {"grant_type": "client_credentials",
                "client_id": self.cfg["client_id"],
                "client_secret": _secret(self.cfg, "client_secret", "client_secret_env")}
        if self.cfg.get("scope"):
            data["scope"] = self.cfg["scope"]
        resp = await _request_with_backoff("POST", self.cfg["token_url"], data=data)
        js = resp.json()
        return TokenState(js["access_token"],
                          time.time() + float(js.get("expires_in", 3600)))


class OAuth2PasswordProvider(TokenProvider):
    """password grant (username/password_env)."""
    async def _fetch(self) -> TokenState:
        data = {"grant_type": "password",
                "client_id": self.cfg.get("client_id", ""),
                "username": self.cfg["username"],
                "password": _secret(self.cfg, "password", "password_env")}
        if self.cfg.get("client_secret_env") or self.cfg.get("client_secret"):
            data["client_secret"] = _secret(self.cfg, "client_secret", "client_secret_env")
        if self.cfg.get("scope"):
            data["scope"] = self.cfg["scope"]
        resp = await _request_with_backoff("POST", self.cfg["token_url"], data=data)
        js = resp.json()
        return TokenState(js["access_token"],
                          time.time() + float(js.get("expires_in", 3600)))


class LoginProvider(TokenProvider):
    """범용: 임의 로그인 엔드포인트에 POST → 응답에서 토큰 추출(dot-path)."""
    async def _fetch(self) -> TokenState:
        pw = _secret(self.cfg, "password", "password_env")
        body = self.cfg.get("body_template", '{"password":"{{password}}"}')
        # {{password}}는 JSON 안전 삽입
        import json as _json
        body = body.replace("{{password}}", _json.dumps(pw)[1:-1])
        headers = self.cfg.get("headers", {"Content-Type": "application/json"})
        resp = await _request_with_backoff(
            self.cfg.get("method", "POST").upper(), self.cfg["login_url"],
            headers=headers, content=body.encode())
        js = resp.json()
        tok = _dig(js, self.cfg["token_path"])
        if tok is None:
            raise AuthConfigError(f"token_not_found: {self.cfg['token_path']}")
        exp_path = self.cfg.get("expires_in_path")
        ttl = _dig(js, exp_path) if exp_path else None
        if ttl is None:
            ttl = self.cfg.get("default_ttl", 900)
        return TokenState(str(tok), time.time() + float(ttl))


_PROVIDERS = {
    "bearer": BearerProvider,
    "api_key": ApiKeyProvider,
    "oauth2_client": OAuth2ClientProvider,
    "oauth2_password": OAuth2PasswordProvider,
    "login": LoginProvider,
}


def make_provider(auth_cfg: Optional[dict], cache_key: str) -> Optional[TokenProvider]:
    """팩토리: auth.type 분기 (actor.py make_actor와 대칭). auth 없으면 None."""
    if not auth_cfg:
        return None
    atype = auth_cfg.get("type", "none")
    if atype == "none":
        return None
    cls = _PROVIDERS.get(atype)
    if cls is None:
        raise AuthConfigError(f"auth.type={atype} 미지원 ({'|'.join(_PROVIDERS)})")
    return cls(auth_cfg, cache_key)


def cleanup_cache(cache_key_prefix: str = "") -> None:
    """스캔 종료 시 토큰/락 정리(비밀 잔존 방지). 프리픽스로 해당 스캔만."""
    for k in [k for k in _CACHE if k.startswith(cache_key_prefix)]:
        _CACHE.pop(k, None)
    for k in [k for k in _LOCKS if k.startswith(cache_key_prefix)]:
        _LOCKS.pop(k, None)
