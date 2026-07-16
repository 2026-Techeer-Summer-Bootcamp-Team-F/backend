# -*- coding: utf-8 -*-
"""관측성(Langfuse) — LLM 호출 트레이싱. — ARCHITECTURE.md §3.11 (관측성)

judge Tier3·코드스캐너·리포트요약의 Haiku 호출을 트레이싱해 지연·토큰·비용·플로우를
Langfuse 대시보드로 본다. 원칙 2가지:
  1) 키(LANGFUSE_*) 없으면 완전 no-op — 순수 판정/요약 경로에 의존성 0(하위호환).
  2) 마스킹 기본 ON — 프롬프트/표적응답 '원문'은 Langfuse로 안 보낸다(길이·메타데이터만).
     보안 레드팀 도구가 캐낸 유출데이터(카나리·PII·소스코드)를 제3자 SaaS에 흘리지
     않기 위함. 원문은 이미 우리 DB(attempts)에 있으므로 관측엔 메타만 있으면 충분.
"""
import logging
from contextlib import contextmanager

from .config import settings

log = logging.getLogger("redteam.observability")

_client = None          # Langfuse 싱글턴(지연 초기화). 키 없으면 None 유지.
_initialized = False


def _mask(*, data, **kwargs):
    """마스킹 콜백(Langfuse mask=). 문자열 원문은 길이만 남기고 가린다.

    - str  → "[REDACTED N chars]" (원문 미전송, 크기 힌트만)
    - dict/list → 재귀 마스킹(중첩 input/output 대응)
    - 그 외(숫자·불리언 등) → 그대로(토큰수·verdict 같은 메타는 관측에 필요)
    Langfuse는 start_observation/update의 input·output 속성에 이 콜백을 적용한다.
    usage_details(토큰수)는 이 경로를 안 타므로 그대로 전송된다.
    """
    if isinstance(data, str):
        return f"[REDACTED {len(data)} chars]" if data else data
    if isinstance(data, dict):
        return {k: _mask(data=v) for k, v in data.items()}
    if isinstance(data, list):
        return [_mask(data=v) for v in data]
    return data


def get_langfuse():
    """Langfuse 클라이언트(싱글턴). 키 없음/초기화 실패 시 None(→ 트레이싱 no-op)."""
    global _client, _initialized
    if _initialized:
        return _client
    _initialized = True
    if not (settings.langfuse_public_key and settings.langfuse_secret_key):
        return None
    try:
        from langfuse import Langfuse
        kw = {
            "public_key": settings.langfuse_public_key,
            "secret_key": settings.langfuse_secret_key,
        }
        if settings.langfuse_mask:
            kw["mask"] = _mask
        # host 파라미터명은 SDK 버전에 따라 base_url/host 로 갈려 둘 다 시도.
        if settings.langfuse_host:
            try:
                _client = Langfuse(base_url=settings.langfuse_host, **kw)
            except TypeError:
                _client = Langfuse(host=settings.langfuse_host, **kw)
        else:
            _client = Langfuse(**kw)
        log.info("Langfuse 관측성 활성화 (mask=%s, host=%s)",
                 settings.langfuse_mask, settings.langfuse_host or "default")
    except Exception as e:   # noqa: BLE001 - 패키지 미설치/키무효/네트워크 → 비활성 진행
        log.warning("Langfuse 초기화 실패(비활성 진행): %s", e)
        _client = None
    return _client


@contextmanager
def trace_llm(name: str, model: str, input_data):
    """LLM 호출 1건을 generation 으로 트레이싱(마스킹 적용). 키 없으면 no-op.

    사용:
        with trace_llm("judge-escalate", model, {"response": resp[:1500]}) as gen:
            msg = client.messages.create(...)
            if gen is not None:
                gen.update(output=text, usage_details={
                    "input_tokens": msg.usage.input_tokens,
                    "output_tokens": msg.usage.output_tokens})
    input_data 의 문자열은 mask 콜백이 자동으로 [REDACTED]로 바꿔 전송한다.
    """
    client = get_langfuse()
    cm = None
    if client is not None:
        try:
            cm = client.start_as_current_observation(
                as_type="generation", name=name, model=model, input=input_data)
        except Exception as e:   # noqa: BLE001 - 트레이스 시작 실패는 LLM 호출을 막지 않음
            log.warning("Langfuse 트레이스 시작 실패(무시): %s", e)
            cm = None
    if cm is None:
        yield None
        return
    with cm as gen:
        yield gen


def flush():
    """대기 중 트레이스 강제 전송(워커 태스크 종료 시 호출 → 데모 즉시 반영)."""
    client = get_langfuse()
    if client is not None:
        try:
            client.flush()
        except Exception:   # noqa: BLE001 - flush 실패는 무시(다음 배치에 전송)
            pass
