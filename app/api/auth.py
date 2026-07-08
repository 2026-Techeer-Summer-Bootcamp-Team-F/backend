# -*- coding: utf-8 -*-
"""§1 Auth — GitHub OAuth + PoC dev-login + logout. (담당: auth)"""
from fastapi import APIRouter

router = APIRouter(prefix="/auth", tags=["auth"])


@router.get("/github/login")
def github_login():
    """OAuth 시작 → authorize_url 반환. TODO"""
    return {"authorize_url": "https://github.com/login/oauth/authorize?..."}


@router.get("/github/callback")
def github_callback(code: str, state: str = ""):
    """code→access_token→user upsert→JWT. TODO"""
    return {"access_token": "TODO", "token_type": "bearer"}


@router.post("/dev-login")
def dev_login():
    """AUTH_MODE=mock 전용 — GitHub 없이 토큰 발급. TODO"""
    return {"access_token": "TODO-mock", "token_type": "bearer"}


@router.get("/me")
def me():
    """현재 사용자. TODO"""
    return {"user_id": 0, "github_login": "TODO"}


@router.post("/logout", status_code=204)
def logout():
    """JWT 무효화. TODO"""
    return None
