# -*- coding: utf-8 -*-
"""§1 Auth — GitHub OAuth(SPA 주도형) + PoC dev-login + logout. (담당: auth)

흐름(SPA 주도형, 결정 2026-07-09):
  ① login    → 200 {authorize_url}   (프론트가 이 URL로 이동)
  ② GitHub   → redirect_uri(?code&state)  (프론트 콜백 또는 이 콜백)
  ③ callback(code,state) → 토큰교환 → GitHub /user → users upsert → JWT
               → 200 {access_token, token_type, user}
  ④ logout   → 204 무상태(서버 blacklist 없음; 클라가 토큰 삭제 + 짧은 만료)
"""
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
                        encrypt_token, verify_oauth_state)

router = APIRouter(prefix="/auth", tags=["auth"])

GITHUB_AUTHORIZE = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN = "https://github.com/login/oauth/access_token"
GITHUB_USER = "https://api.github.com/user"


def _user_public(u: User) -> dict:
    return {"user_id": u.user_id, "github_name": u.github_name, "name": u.name}


def _issue(u: User) -> dict:
    return {"access_token": create_access_token(u.user_id),
            "token_type": "bearer", "user": _user_public(u)}


def _upsert(db: Session, github_id: str, github_name: str,
            name: str, token_enc: str = "") -> User:
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
        tok_resp = client.post(
            GITHUB_TOKEN,
            headers={"Accept": "application/json"},
            data={"client_id": settings.github_client_id,
                  "client_secret": settings.github_client_secret,
                  "code": code,
                  "redirect_uri": settings.github_redirect_uri},
        )
        tok = tok_resp.json()
        access_token = tok.get("access_token")
        if not access_token:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED,
                                f"토큰 교환 실패: {tok.get('error_description') or tok.get('error') or 'unknown'}")
        u_resp = client.get(
            GITHUB_USER,
            headers={"Authorization": f"Bearer {access_token}",
                     "Accept": "application/vnd.github+json"},
        )
        if u_resp.status_code != 200:
            raise HTTPException(status.HTTP_401_UNAUTHORIZED, "GitHub 사용자 조회 실패")
        gh = u_resp.json()

    user = _upsert(db, github_id=str(gh["id"]),
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
    """현재 로그인 사용자."""
    return {"user_id": user.user_id, "github_id": user.github_id,
            "github_name": user.github_name, "name": user.name}


@router.post("/logout", status_code=204)
def logout(user: User = Depends(get_current_user)):
    """무상태 로그아웃 — 서버 상태 없음(클라가 토큰 삭제). 204 No Content."""
    return None
