# -*- coding: utf-8 -*-
"""DB 스키마 자동 보정(additive-only) — 배포 시 모델 신규 컬럼을 RDS에 자동 반영. (#89)

문제: 운영 RDS엔 마이그레이션이 자동으로 안 돌아, 모델에 컬럼을 추가하고 CD로 배포하면
RDS엔 그 컬럼이 없어 조회 SQL이 통째로 500난다(2026-07-15 code_locations 사고).
`recreate_db`는 dev 전용(데이터 삭제)이라 운영엔 못 쓴다. `create_all`은 없는 '테이블'만
만들고 없는 '컬럼'은 못 채운다.

해결: 부팅 시 모델 vs 실제 DB를 비교해 '모델엔 있는데 DB에 없는 컬럼'만 ADD 한다.
- additive-only: DROP·타입변경·이름변경은 절대 안 함(파괴적 변경은 사람이 처리).
- idempotent: `ADD COLUMN IF NOT EXISTS`, 매 부팅 안전.
- nullable 로 추가 → 기존 행 보존(앱 코드가 None 방어: `or {}` / `or []` / isinstance).
- 한 컬럼 실패해도 삼키고 계속(부팅 자체는 막지 않음).

범위 밖(자동 아님): 컬럼 삭제/이름변경/타입변경 → 발표 후 Alembic 정식 도입 검토.
"""
import logging

from sqlalchemy import inspect, text

log = logging.getLogger("redteam.schema_sync")


def ensure_schema(engine, base) -> list:
    """모델엔 있는데 DB 테이블엔 없는 컬럼을 ADD. 추가한 컬럼 목록 반환(로그용).

    테이블 자체가 없는 경우는 건드리지 않는다 — 그건 `Base.metadata.create_all`
    (main.py 부팅) 담당. 여기선 '기존 테이블의 빠진 컬럼'만 메운다.
    """
    insp = inspect(engine)
    added = []
    for table in base.metadata.sorted_tables:
        if not insp.has_table(table.name):
            continue  # create_all 이 생성 담당
        existing = {c["name"] for c in insp.get_columns(table.name)}
        for col in table.columns:
            if col.name in existing:
                continue
            coltype = col.type.compile(dialect=engine.dialect)
            sql = ('ALTER TABLE %s ADD COLUMN IF NOT EXISTS "%s" %s'
                   % (table.name, col.name, coltype))
            try:
                with engine.begin() as conn:
                    conn.execute(text(sql))
                added.append("%s.%s %s" % (table.name, col.name, coltype))
            except Exception:  # noqa: BLE001 - 한 컬럼 실패가 부팅을 막지 않게
                log.exception("[schema_sync] 컬럼 추가 실패(계속): %s.%s",
                              table.name, col.name)
    if added:
        log.warning("[schema_sync] 스키마 자동 보정 — 추가한 컬럼: %s", added)
    return added
