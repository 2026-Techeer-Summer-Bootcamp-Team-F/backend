# -*- coding: utf-8 -*-
"""액터 세션(멀티턴) 스모크 — #11. 응답 세션ID 추출→다음 요청 재주입 검증.

MockTransport 표적: 1턴째 세션ID 발급(body), 2턴째 그 세션ID를 헤더로 받으면
"기억함" 응답. 액터가 세션을 유지하는지(크레센도 토대) 확인.

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_session.py
"""
import asyncio

import httpx

from app.engine.actor import HttpActor

results = []


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


def make_target():
    """세션 기억하는 표적: 1턴 body로 sid 발급, 2턴 X-Session-Id 헤더 확인."""
    def handler(request):
        sid = request.headers.get("X-Session-Id")
        if not sid:
            return httpx.Response(200, json={"reply": "안녕하세요, 무엇을 도와드릴까요?",
                                             "sid": "sess-123"})
        if sid == "sess-123":
            return httpx.Response(200, json={"reply": "이전 대화를 기억합니다.", "sid": "sess-123"})
        return httpx.Response(200, json={"reply": "누구세요?"})
    return httpx.MockTransport(handler)


async def main():
    cfg = {
        "url": "http://t/chat",
        "body_template": '{"message":"{{prompt}}"}',
        "response_path": "reply",
        "session": {"session_source": "body", "session_path": "sid"},  # 폼과 동일
    }
    actor = HttpActor(cfg, transport=make_target())

    r1 = await actor.send("첫 질문")
    check("1턴: 세션ID 추출됨", actor._session_id == "sess-123")
    print("   1턴 응답:", r1)

    r2 = await actor.send("둘째 질문")  # 세션 재주입 → 서버가 기억
    check("2턴: 세션 재주입 → 서버가 기억", "기억" in r2)
    print("   2턴 응답:", r2)

    # 세션 없는 액터는 매턴 신규(기억 안 함)
    actor_no = HttpActor({"url": "http://t/chat", "body_template": '{"message":"{{prompt}}"}',
                          "response_path": "reply"}, transport=make_target())
    await actor_no.send("a")
    r_no = await actor_no.send("b")
    check("세션 미설정 → 매턴 신규(기억 안 함)", "기억" not in r_no)

    ok = all(c for _, c in results)
    print(f"\nSMOKE session: {'PASS ✅ (멀티턴 세션 유지)' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
