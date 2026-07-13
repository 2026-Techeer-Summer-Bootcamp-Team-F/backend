# -*- coding: utf-8 -*-
"""로그아웃 grant revoke 스모크 — POST /auth/logout + _revoke_github_grant.

네트워크 없이 httpx.MockTransport로 자체완결 검증:
  [U1 헬퍼] revoke 호출 파라미터(DELETE·URL·Basic auth·body) / 토큰없음 스킵 /
            client_id·secret 미설정 스킵 / 응답 비정상·네트워크 오류에도 예외 없이 False.
  [U2 배선] 저장 토큰 있으면 복호화→revoke 호출 + access_token_enc 비워짐 + 204 /
            dev-login(토큰 없음) 사용자는 revoke 스킵 + 204.

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_logout.py
로컬(Docker 미가동): PYTHONUTF8=1 DATABASE_URL="sqlite:///./redteam.db" AUTH_MODE=mock \
                     PYTHONPATH=. python scripts/smoke_logout.py
"""
import base64

import httpx
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.api import auth as auth_mod
from app.config import settings
from app.db import SessionLocal, get_db
from app.deps import get_current_user
from app.main import app
from app.models import User
from app.security import encrypt_token

results = []


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


# ── [U1] _revoke_github_grant 헬퍼 (MockTransport 주입) ──────────────────────
def test_helper_params():
    print("[1] revoke 호출 파라미터 검증(DELETE·URL·Basic·body)")
    settings.github_client_id = "cid-123"
    settings.github_client_secret = "csecret-456"
    seen = {}

    def handler(request):
        seen["method"] = request.method
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("Authorization", "")
        seen["body"] = request.read().decode()
        return httpx.Response(204)

    ok = auth_mod._revoke_github_grant("gh-tok-xyz", transport=httpx.MockTransport(handler))
    expect_basic = "Basic " + base64.b64encode(b"cid-123:csecret-456").decode()
    check("method=DELETE", seen.get("method") == "DELETE")
    check("URL=applications/{client_id}/grant",
          seen.get("url") == "https://api.github.com/applications/cid-123/grant")
    check("Basic auth = client_id:secret", seen.get("auth") == expect_basic)
    check('body={"access_token": ...}', '"access_token"' in seen.get("body", "")
          and "gh-tok-xyz" in seen.get("body", ""))
    check("204 → 반환 True", ok is True)


def test_helper_no_token():
    print("[2] 저장 토큰 없음 → revoke 스킵")
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(204)

    ok = auth_mod._revoke_github_grant("", transport=httpx.MockTransport(handler))
    check("토큰 빈값 → 호출 0회, 반환 False", called["n"] == 0 and ok is False)


def test_helper_no_creds():
    print("[3] client_id/secret 미설정 → revoke 스킵")
    settings.github_client_id = ""
    settings.github_client_secret = ""
    called = {"n": 0}

    def handler(request):
        called["n"] += 1
        return httpx.Response(204)

    ok = auth_mod._revoke_github_grant("gh-tok", transport=httpx.MockTransport(handler))
    check("자격증명 미설정 → 호출 0회, 반환 False", called["n"] == 0 and ok is False)


def test_helper_failures():
    print("[4] API 실패/네트워크 오류에도 예외 없이 False")
    settings.github_client_id = "cid-123"
    settings.github_client_secret = "csecret-456"

    ok_500 = auth_mod._revoke_github_grant(
        "gh-tok", transport=httpx.MockTransport(lambda r: httpx.Response(500)))
    check("비정상 응답(500) → 예외 없이 False", ok_500 is False)

    def raiser(request):
        raise httpx.ConnectError("boom")

    ok_net = auth_mod._revoke_github_grant("gh-tok", transport=httpx.MockTransport(raiser))
    check("네트워크 오류 → 예외 없이 False", ok_net is False)


# ── [U2] logout 배선 (TestClient + get_current_user 오버라이드) ──────────────
def _make_user(github_id, token_plain):
    db = SessionLocal()
    try:
        db.query(User).filter(User.github_id == github_id).delete()
        db.commit()
        u = User(github_id=github_id, github_name="smoke",
                 access_token_enc=encrypt_token(token_plain) if token_plain else "")
        db.add(u)
        db.commit()
        db.refresh(u)
        return u.user_id
    finally:
        db.close()


def _token_enc(uid):
    db = SessionLocal()
    try:
        return db.get(User, uid).access_token_enc
    finally:
        db.close()


def _cleanup(github_ids):
    db = SessionLocal()
    try:
        db.query(User).filter(User.github_id.in_(github_ids)).delete()
        db.commit()
    finally:
        db.close()


def test_wiring():
    print("[5] logout 배선 — 토큰 복호화→revoke + access_token_enc 비움 + 204")
    settings.github_client_id = "cid-123"
    settings.github_client_secret = "csecret-456"
    spy = {"n": 0, "token": None}
    orig = auth_mod._revoke_github_grant

    def fake_revoke(access_token, transport=None):
        spy["n"] += 1
        spy["token"] = access_token
        return True

    auth_mod._revoke_github_grant = fake_revoke
    client = TestClient(app)

    def override_as(uid):
        # 오버라이드가 get_db에 의존 → logout의 db와 같은 요청 세션 공유(실전과 동일).
        def _cur(db: Session = Depends(get_db)):
            return db.get(User, uid)
        app.dependency_overrides[get_current_user] = _cur

    try:
        uid = _make_user("smoke-logout-owner", "plain-gh-tok")
        override_as(uid)
        r = client.post("/auth/logout")
        check("토큰 보유 사용자 → 204", r.status_code == 204)
        check("revoke 1회 호출 + 복호화된 원문 전달",
              spy["n"] == 1 and spy["token"] == "plain-gh-tok")
        check("access_token_enc 비워짐", _token_enc(uid) == "")

        # dev-login(토큰 없음) → revoke 스킵
        spy["n"] = 0
        uid2 = _make_user("smoke-logout-dev", "")
        override_as(uid2)
        r2 = client.post("/auth/logout")
        check("토큰 없는 사용자 → 204 + revoke 0회", r2.status_code == 204 and spy["n"] == 0)
    finally:
        auth_mod._revoke_github_grant = orig
        app.dependency_overrides.pop(get_current_user, None)
        _cleanup(["smoke-logout-owner", "smoke-logout-dev"])


def main():
    test_helper_params()
    test_helper_no_token()
    test_helper_no_creds()
    test_helper_failures()
    test_wiring()
    ok = all(c for _, c in results)
    print(f"\nSMOKE logout: {'PASS ✅ (grant revoke 파라미터 + 배선 + 예외처리)' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
