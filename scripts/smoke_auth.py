# -*- coding: utf-8 -*-
"""액터 auth 스모크 — TokenProvider 6모드 로직 + HttpActor 401 재인증 관통.

네트워크 없이 httpx.MockTransport로 자체완결 검증:
  1) bearer/api_key: env 변수 → 헤더 주입
  2) login: 응답 dot-path로 토큰 추출 + 만료
  3) 캐시 동시성(herd): 동시 요청에도 발급 1회(락)
  4) 401 재인증: 스테일 토큰 401 → invalidate → 재발급 → 200 (HttpActor 관통)

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_auth.py
"""
import asyncio
import os

import httpx

from app.engine.actor import HttpActor
from app.engine import auth_provider as ap
from app.engine.auth_provider import make_provider, TokenProvider, TokenState


results = []


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


async def test_bearer_apikey():
    print("[1] bearer / api_key env 주입")
    os.environ["SMOKE_TOKEN"] = "tok-abc"
    os.environ["SMOKE_KEY"] = "key-xyz"
    p = make_provider({"type": "bearer", "token_env": "SMOKE_TOKEN"}, "k-bearer")
    h = await p.apply({})
    check("bearer → Authorization: Bearer tok-abc", h.get("Authorization") == "Bearer tok-abc")
    p2 = make_provider({"type": "api_key", "key_env": "SMOKE_KEY"}, "k-apikey")
    h2 = await p2.apply({})
    check("api_key → X-API-Key: key-xyz", h2.get("X-API-Key") == "key-xyz")


async def test_login_parse():
    print("[2] login 응답 dot-path 파싱")
    os.environ["SMOKE_PW"] = "s3cret"
    calls = {"n": 0}

    def handler(request):
        calls["n"] += 1
        return httpx.Response(200, json={"data": {"accessToken": "log-tok-1", "expiresIn": 3600}})

    ap._CACHE.pop("k-login", None)
    # login provider의 _request_with_backoff가 이 transport를 쓰도록 잠시 교체
    orig = ap._request_with_backoff

    async def patched(method, url, **kw):
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as c:
            return await c.request(method, url, **kw)

    ap._request_with_backoff = patched
    try:
        p = make_provider({
            "type": "login", "login_url": "http://t/login",
            "body_template": '{"pw":"{{password}}"}', "password_env": "SMOKE_PW",
            "token_path": "data.accessToken", "expires_in_path": "data.expiresIn",
        }, "k-login")
        tok = await p.token()
        check("login token_path 추출 = log-tok-1", tok == "log-tok-1")
        tok2 = await p.token()  # 캐시 재사용 → 발급 1회
        check("캐시 재사용(발급 1회)", tok2 == "log-tok-1" and calls["n"] == 1)
    finally:
        ap._request_with_backoff = orig


async def test_herd():
    print("[3] 캐시 동시성 — herd 방지(발급 1회)")
    fetch_calls = {"n": 0}

    class Counting(TokenProvider):
        async def _fetch(self):
            fetch_calls["n"] += 1
            await asyncio.sleep(0.05)
            return TokenState("herd-tok", __import__("time").time() + 3600)

    ap._CACHE.pop("k-herd", None)
    p = Counting({}, "k-herd")
    toks = await asyncio.gather(*[p.token() for _ in range(10)])
    check("동시 10요청 → _fetch 1회", fetch_calls["n"] == 1 and all(t == "herd-tok" for t in toks))


async def test_401_reauth():
    print("[4] 401 재인증 관통 (HttpActor)")
    state = {"issued": 0}

    class Rotating(TokenProvider):
        async def _fetch(self):
            state["issued"] += 1
            return TokenState(f"tok{state['issued']}", __import__("time").time() + 3600)

    def target_handler(request):
        auth = request.headers.get("Authorization", "")
        # tok1(스테일)이면 401, tok2부터 200 → 재인증 유도
        if auth == "Bearer tok2":
            return httpx.Response(200, json={"reply": "OK breached"})
        return httpx.Response(401, json={"error": "unauthorized"})

    ap._CACHE.pop("k-401", None)
    actor = HttpActor(
        {"url": "http://t/chat", "body_template": '{"m":"{{prompt}}"}', "response_path": "reply"},
        cache_key="k-401", transport=httpx.MockTransport(target_handler))
    actor.auth = Rotating({}, "k-401")  # 테스트 더블 주입
    resp = await actor.send("attack")
    check("401→invalidate→재발급→200", resp == "OK breached" and state["issued"] == 2)


async def main():
    await test_bearer_apikey()
    await test_login_parse()
    await test_herd()
    await test_401_reauth()
    ok = all(c for _, c in results)
    print(f"\nSMOKE auth: {'PASS ✅ (6모드 로직 + 401 재인증 관통)' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
