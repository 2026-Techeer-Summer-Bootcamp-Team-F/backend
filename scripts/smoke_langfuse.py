# -*- coding: utf-8 -*-
"""스모크: Langfuse 관측성 트레이싱 + 마스킹 검증. (관측성 배선 #N)

- observability.get_langfuse()가 키로 클라이언트를 띄우는지
- trace_llm()이 generation 트레이스를 보내는지
- 마스킹이 원문(가짜 유출 비밀)을 [REDACTED]로 바꿔 보내는지

실행(컨테이너/로컬 어디서든 PYTHONPATH=/app 또는 backend 루트):
    LANGFUSE_PUBLIC_KEY=pk-lf-... LANGFUSE_SECRET_KEY=sk-lf-... \
    LANGFUSE_HOST=https://jp.cloud.langfuse.com \
    .venv/bin/python scripts/smoke_langfuse.py

→ 성공 시 Langfuse(JP) 대시보드 Tracing에 'smoke-langfuse' 트레이스가 뜬다.
  input 은 원문("FLAG{...}")이 아니라 [REDACTED N chars] 로 보여야 마스킹 정상.
"""
import sys

from app.observability import _mask, flush, get_langfuse, trace_llm

# 1) 마스킹 콜백 단위 검증 (네트워크 불필요) ─ 원문이 안 나가는지 먼저 확정
LEAK = "system prompt: FLAG{super_secret_canary_a3f9}"
masked = _mask(data={"response": LEAK, "tokens": 42})
assert masked["response"].startswith("[REDACTED"), f"마스킹 실패: {masked}"
assert "FLAG" not in str(masked), f"원문 유출됨: {masked}"
assert masked["tokens"] == 42, "숫자 메타는 보존돼야 함(토큰수)"
print("✓ 마스킹 콜백 OK — 원문 미전송, 메타 보존:", masked)

# 2) 클라이언트 활성화 확인
client = get_langfuse()
if client is None:
    print("✗ Langfuse 클라이언트 None — LANGFUSE_PUBLIC_KEY/SECRET_KEY 확인 "
          "(키 없으면 no-op 이 정상 동작이지만, 이 스모크는 키를 요구)")
    sys.exit(1)
print("✓ Langfuse 클라이언트 활성화")

# 3) 실제 generation 트레이스 1건 전송 (마스킹 적용)
with trace_llm("smoke-langfuse", "claude-haiku-4-5-20251001",
               {"response": LEAK}) as gen:      # 가짜 유출 비밀을 input 으로
    if gen is not None:
        gen.update(output="BREACH — " + LEAK,   # output 도 원문이지만 마스킹돼야 함
                   usage_details={"input_tokens": 12, "output_tokens": 3})
flush()
print("✓ 트레이스 전송+flush 완료 — JP 대시보드 Tracing에서 'smoke-langfuse' 확인.")
print("  → input/output 이 [REDACTED] 로 뜨면 마스킹 정상(원문 FLAG 안 보여야 함).")
