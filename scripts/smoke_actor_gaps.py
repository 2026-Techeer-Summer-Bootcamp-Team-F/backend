# -*- coding: utf-8 -*-
"""액터 갭 스모크 — #30. inject query/body · HMAC 서명 · refresh_token 검증.

네트워크 없이 httpx.MockTransport + provider 단위로 자체완결 검증:
  1) inject.in=query : 토큰이 URL 쿼리스트링으로
  2) inject.in=body  : 토큰이 JSON 바디 최상위 키로(+원래 필드 유지)
  3) hmac            : 요청별 X-Signature/X-Timestamp 주입 + 서명 값 재현 일치
  4) refresh_token   : 2회차 발급이 refresh grant 사용

실행(컨테이너 안): docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_actor_gaps.py
"""
import asyncio
import hashlib
import hmac
import json
import os
import urllib.parse

import httpx

from app.engine import auth_provider as ap
from app.engine.actor import HttpActor
from app.engine.auth_provider import make_provider

_fail = 0


def check(name, cond):
    global _fail
    if not cond:
        _fail += 1
    print(f"  {'✅' if cond else '❌'} {name}")


async def test_query_inject():
    print("[1] inject.in=query — 토큰이 URL 쿼리로")
    seen = {}

    def handler(req):
        seen["url"] = str(req.url)
        return httpx.Response(200, json={"reply": "ok"})

    ap._CACHE.pop("k-q", None)
    os.environ["SMOKE_TOK"] = "qtok123"
    cfg = {"url": "http://t/api/chat", "response_path": "reply",
           "auth": {"type": "bearer", "token_env": "SMOKE_TOK",
                    "inject": {"in": "query", "name": "access_token", "format": "{token}"}}}
    actor = HttpActor(cfg, cache_key="k-q", transport=httpx.MockTransport(handler))
    await actor.send("hi")
    check("URL에 access_token=qtok123 주입", "access_token=qtok123" in seen.get("url", ""))


async def test_body_inject():
    print("[2] inject.in=body — 토큰이 JSON 바디로")
    seen = {}

    def handler(req):
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"reply": "ok"})

    ap._CACHE.pop("k-b", None)
    os.environ["SMOKE_TOK2"] = "btok"
    cfg = {"url": "http://t/api", "response_path": "reply",
           "body_template": '{"message":"{{prompt}}"}',
           "auth": {"type": "bearer", "token_env": "SMOKE_TOK2",
                    "inject": {"in": "body", "name": "token", "format": "Bearer {token}"}}}
    actor = HttpActor(cfg, cache_key="k-b", transport=httpx.MockTransport(handler))
    await actor.send("hi")
    body = json.loads(seen.get("body", "{}"))
    check("바디에 token='Bearer btok' 주입", body.get("token") == "Bearer btok")
    check("원래 message='hi' 유지", body.get("message") == "hi")


async def test_hmac():
    print("[3] hmac — 요청별 서명 헤더")
    seen = {}

    def handler(req):
        seen["h"] = {k.lower(): v for k, v in req.headers.items()}
        seen["body"] = req.content.decode()
        return httpx.Response(200, json={"reply": "ok"})

    os.environ["SMOKE_HMAC"] = "s3cr3t"
    cfg = {"url": "http://t/api", "response_path": "reply",
           "body_template": '{"message":"{{prompt}}"}',
           "auth": {"type": "hmac", "secret_env": "SMOKE_HMAC", "key_id": "k1"}}
    actor = HttpActor(cfg, cache_key="k-h", transport=httpx.MockTransport(handler))
    await actor.send("hi")
    h = seen.get("h", {})
    check("X-Signature 헤더 있음", bool(h.get("x-signature")))
    check("X-Timestamp 헤더 있음", bool(h.get("x-timestamp")))
    check("X-Key-Id=k1", h.get("x-key-id") == "k1")
    canonical = f"POST\n/api\n{h.get('x-timestamp')}\n{seen.get('body')}"
    expect = hmac.new(b"s3cr3t", canonical.encode(), hashlib.sha256).hexdigest()
    check("서명 값 재현 일치", h.get("x-signature") == expect)


async def test_refresh():
    print("[4] refresh_token — 2회차 발급은 refresh grant")
    grants = []

    async def fake_req(method, url, **kw):
        grants.append((kw.get("data") or {}).get("grant_type"))
        n = len(grants)
        return httpx.Response(200, json={"access_token": f"tok{n}",
                                         "expires_in": 1, "refresh_token": "R1"})

    orig = ap._request_with_backoff
    ap._request_with_backoff = fake_req
    try:
        ap._CACHE.pop("k-rf", None)
        os.environ["SMOKE_CS"] = "sec"
        p = make_provider({"type": "oauth2_client", "token_url": "http://t/oauth",
                           "client_id": "c", "client_secret_env": "SMOKE_CS"}, "k-rf")
        await p.token()   # 1회차 (client_credentials)
        await p.token()   # expires_in=1 < buffer 60 → 만료 간주 → 2회차 (refresh)
        check("1회차 grant=client_credentials", grants and grants[0] == "client_credentials")
        check("2회차 grant=refresh_token", len(grants) >= 2 and grants[1] == "refresh_token")
    finally:
        ap._request_with_backoff = orig


async def main():
    print("=" * 60)
    print(" 액터 갭 스모크 (#30) — query/body 주입 · HMAC · refresh_token")
    print("=" * 60)
    await test_query_inject()
    await test_body_inject()
    await test_hmac()
    await test_refresh()
    print("\nSMOKE gaps:", "PASS ✅" if _fail == 0 else f"FAIL ❌ ({_fail}건)")
    return 0 if _fail == 0 else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
