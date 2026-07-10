# -*- coding: utf-8 -*-
"""인증 유틸 — JWT 발급/검증, OAuth state 서명, GitHub 토큰 enc/dec.

- JWT: PyJWT(HS256), sub=user_id, typ로 access/state 구분. 무상태 로그아웃이라
  blacklist 없음(짧은 만료로 커버).
- state: OAuth CSRF. Redis 없이 서명된 JWT(짧은 만료)로 무상태 검증.
  ⚠️ PoC 한계: 브라우저 세션에 바인딩되지 않음(서명·만료만). 실서비스는
  per-session nonce 저장(쿠키/Redis)으로 강화 필요.
- 토큰 enc/dec: settings.token_enc_key 있으면 Fernet, 없으면 평문(PoC 시임).
"""
from datetime import datetime, timedelta, timezone

import jwt

from .config import settings


def _now() -> datetime:
    """현재 UTC 시각(timezone-aware)."""
    return datetime.now(timezone.utc)


def create_access_token(user_id: int) -> str:
    """로그인 사용자 액세스 토큰(Bearer) 발급. typ=access."""
    payload = {
        "sub": str(user_id),
        "typ": "access",
        "iat": _now(),
        "exp": _now() + timedelta(minutes=settings.jwt_expire_min),
    }
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_alg)


def decode_access_token(token: str) -> dict:
    """액세스 토큰 검증 → payload. typ!=access(예: state 토큰)는 거부.

    검증 실패 시 jwt.PyJWTError(InvalidTokenError 등) 발생 → 호출측에서 401 변환.
    """
    payload = jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_alg])
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("access 토큰이 아님")
    return payload


def create_oauth_state() -> str:
    """OAuth CSRF state — 서명된 짧은 만료 토큰(무상태). typ=state."""
    payload = {"typ": "state", "iat": _now(), "exp": _now() + timedelta(minutes=10)}
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_alg)


def verify_oauth_state(state: str) -> bool:
    """OAuth state의 서명·만료·typ 검증. 유효하면 True."""
    try:
        data = jwt.decode(state, settings.jwt_secret, algorithms=[settings.jwt_alg])
        return data.get("typ") == "state"
    except jwt.PyJWTError:
        return False


def _fernet():
    """settings.token_enc_key 있으면 Fernet 인스턴스, 없으면 None(평문 시임)."""
    key = settings.token_enc_key
    if not key:
        return None
    from cryptography.fernet import Fernet
    return Fernet(key)


def encrypt_token(plaintext: str) -> str:
    """GitHub 토큰 저장용 암호화(키 없으면 평문 그대로 반환)."""
    f = _fernet()
    if f is None or not plaintext:
        return plaintext or ""
    return f.encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """GitHub 토큰 복호화(키 없으면 원문 그대로). 복호화 실패 시 원문 반환(평문 호환)."""
    f = _fernet()
    if f is None or not ciphertext:
        return ciphertext or ""
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except Exception:
        return ciphertext  # 평문으로 저장됐던 값 호환
