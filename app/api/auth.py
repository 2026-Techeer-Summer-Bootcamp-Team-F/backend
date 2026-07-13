# -*- coding: utf-8 -*-
"""§1 Auth — GitHub OAuth(SPA 주도형) + PoC dev-login + logout. (담당: auth)

흐름(SPA 주도형, 결정 2026-07-09):
  ① login    → 200 {authorize_url}   (프론트가 이 URL로 이동)
  ② GitHub   → redirect_uri(?code&state)
  ③ callback(code,state) → 토큰교환 → GitHub /user → users upsert → JWT
               → 200 {access_token, token_type, user}
  ④ logout   → 204 무상태(서버 blacklist 없음; 클라가 토큰 삭제 + 짧은 만료).
               추가로 GitHub grant(인가) 자체를 취소해 재로그인 시 동의 화면을
               다시 띄운다(silent re-auth 방지). JWT 무효화는 범위 밖(무상태 유지).
"""
import logging
from urllib.parse import urlencode

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..config import settings
from ..db import get_db
from ..deps import get_current_user
from ..models import User
from ..schemas import DevLoginIn
from ..security import (create_access_token, create_oauth_state,
                        decrypt_token, encrypt_token, verify_oauth_state)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_USER = "https://api.github.com/user"
GITHUB_GRANT = "https://api.github.com/applications/{client_id}/grant"


def _user_public(u: User) -> dict:
    """응답에 노출할 최소 사용자 정보(user_id·github_name·name)."""
    return {"user_id": u.user_id, "github_name": u.github_name, "name": u.name}


def _issue(u: User) -> dict:
    """사용자에게 줄 JWT 액세스 토큰 응답 페이로드 생성."""
    return {"access_token": create_access_token(u.user_id),
            "token_type": "bearer", "user": _user_public(u)}


def _upsert(db: Session, github_id: str, github_name: str,
            name: str, token_enc: str = "") -> User:
    """github_id 기준 사용자 upsert(없으면 생성). 토큰이 있으면 함께 갱신."""
    user = db.query(User).filter(User.github_id == github_id).first()
    if user is None:
        user = User(github_id=github_id)
        db.add(user)
    user.github_name = github_name
    user.name = name
    if token_enc:
        user.access_token_enc = token_enc
    db.commit()
    db.refresh(user)
    return user


@router.get("/github/login")
def github_login():
    """OAuth 시작 → authorize_url 반환(SPA가 이동). state=CSRF 서명토큰."""
    if not settings.github_client_id:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GITHUB_CLIENT_ID 미설정")
    params = {
        "client_id": settings.github_client_id,
        "redirect_uri": settings.github_redirect_uri,
        "scope": settings.github_scope,
        "state": create_oauth_state(),
    }
    return {"authorize_url": f"{GITHUB_AUTHORIZE}?{urlencode(params)}"}


@router.get("/github/callback")
def github_callback(code: str, state: str = "", db: Session = Depends(get_db)):
    """code→access_token 교환 → GitHub /user → users upsert → JWT 발급."""
    if not verify_oauth_state(state):
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "state 검증 실패(CSRF)")
    if not (settings.github_client_id and settings.github_client_secret):
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "GitHub OAuth 자격증명 미설정")
    with httpx.Client(timeout=10) as client:
        try:
            tok_resp = client.post(
                GITHUB_TOKEN,
                headers={"Accept": "application/json"},
                data={"client_id": settings.github_client_id,
                      "client_secret": settings.github_client_secret,
                      "code": code,
                      "redirect_uri": settings.github_redirect_uri},
            )
        except httpx.RequestError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 토큰 교환 요청 실패") from None
        if tok_resp.status_code != 200:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY,
                                f"GitHub 토큰 교환 응답 오류(status={tok_resp.status_code})")
        try:
            tok = tok_resp.json()
        except ValueError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 토큰 응답 파싱 실패") from None
        access_token = tok.get("access_token")
        if not access_token:
            err = tok.get("error_description") or tok.get("error") or "unknown"
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, f"토큰 교환 실패: {err}")
        try:
            u_resp = client.get(
                GITHUB_USER,
                headers={"Authorization": f"Bearer {access_token}",
                         "Accept": "application/vnd.github+json"},
            )
        except httpx.RequestError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 사용자 조회 요청 실패") from None
        if u_resp.status_code != 200:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub 사용자 조회 실패")
        try:
            gh = u_resp.json()
        except ValueError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 사용자 응답 파싱 실패") from None

    gh_id = gh.get("id")
    if gh_id is None:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 사용자 응답에 id 없음")
    user = _upsert(db, github_id=str(gh_id),
                   github_name=gh.get("login") or "",
                   name=gh.get("name") or "",
                   token_enc=encrypt_token(access_token))
    return _issue(user)


@router.post("/dev-login")
def dev_login(body: DevLoginIn, db: Session = Depends(get_db)):
    """AUTH_MODE=mock 전용 — GitHub 없이 토큰 발급(Swagger 테스트용)."""
    if settings.auth_mode != "mock":
        raise HTTPException(status.HTTP_403_FORBIDDEN, "dev-login은 AUTH_MODE=mock 에서만 허용")
    user = _upsert(db, github_id=f"dev:{body.github_name}",
                   github_name=body.github_name,
                   name=body.name or body.github_name)
    return _issue(user)


@router.get("/me")
def me(user: User = Depends(get_current_user)):
    """현재 로그인 사용자 정보."""
    return {"user_id": user.user_id, "github_id": user.github_id,
            "github_name": user.github_name, "name": user.name}


def _revoke_github_grant(access_token: str,
                         transport: httpx.BaseTransport | None = None) -> bool:
    """GitHub OAuth grant(인가)를 취소 — 재로그인 시 동의 화면 재노출을 유도.

    `DELETE /applications/{client_id}/grant`(Basic auth=client_id:secret,
    body={"access_token": ...})는 토큰뿐 아니라 인가 자체를 지워 silent
    re-auth를 막는다(토큰만 지우는 .../token 과 다름 — 반드시 grant).

    client_id/secret 미설정 또는 토큰이 없으면 아무 것도 하지 않고 False.
    네트워크·응답 오류는 로그만 남기고 삼킨다(로그아웃을 막지 않음). 성공 시 True.
    `transport`는 테스트(MockTransport) 주입용.
    """
    if not access_token:
        return False
    if not (settings.github_client_id and settings.github_client_secret):
        logger.info("GitHub grant revoke 스킵 — client_id/secret 미설정")
        return False
    url = GITHUB_GRANT.format(client_id=settings.github_client_id)
    try:
        with httpx.Client(timeout=10, transport=transport) as client:
            resp = client.request(
                "DELETE", url,
                auth=(settings.github_client_id, settings.github_client_secret),
                headers={"Accept": "application/vnd.github+json"},
                json={"access_token": access_token},
            )
    except httpx.RequestError as exc:
        logger.warning("GitHub grant revoke 요청 실패(무시하고 로그아웃 진행): %s", exc)
        return False
    if resp.status_code != 204:
        logger.warning("GitHub grant revoke 응답 비정상(status=%s) — 로그아웃은 계속",
                       resp.status_code)
        return False
    return True


@router.post("/logout", status_code=204)
def logout(user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """로그아웃 — GitHub grant 취소 + 저장 토큰 삭제. 항상 204(무상태).

    저장된 GitHub 토큰이 있으면 grant를 취소해 재로그인 시 동의 화면을 다시
    띄운다. revoke 성공 여부와 무관하게 access_token_enc를 비우고 204로 마무리.
    JWT 무효화(블랙리스트)는 범위 밖 — 클라가 토큰을 삭제한다.
    """
    if user.access_token_enc:
        _revoke_github_grant(decrypt_token(user.access_token_enc))
        user.access_token_enc = ""
        db.commit()
    return None
