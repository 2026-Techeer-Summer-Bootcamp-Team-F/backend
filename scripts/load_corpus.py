# -*- coding: utf-8 -*-
"""corpus.db(SQLite) → 앱 DB(postgres) 공격 데이터 적재. — 엔진 retrieve 입력 준비.

컨테이너 안에서 실행(app 모듈 + postgres 접근). corpus.db 는 마운트.
run:
  docker compose run --rm \
    -v "$PWD/scripts:/app/scripts" -v "$PWD/corpus.db:/app/corpus.db" \
    backend python scripts/load_corpus.py
"""
import json
import os
import sqlite3
import sys

sys.path.insert(0, "/app")
from app.db import Base, SessionLocal, engine   # noqa: E402
from app.models import AtlasTechnique, AttackCase  # noqa: E402

SRC = os.environ.get("CORPUS_DB", "corpus.db")


def main():
    Base.metadata.create_all(bind=engine)
    sq = sqlite3.connect(SRC)
    db = SessionLocal()

    # 1) ATLAS 마스터 먼저(FK 대상)
    a = 0
    for r in sq.execute("SELECT id,name,tactic,category,description,mitigation FROM atlas_techniques"):
        db.merge(AtlasTechnique(id=r[0], name=r[1], tactic=r[2] or "", category=r[3] or "",
                                description=r[4] or "", mitigation=r[5] or ""))
        a += 1
    db.commit()

    # 2) attack_cases (이미 있으면 스킵 = 멱등)
    if db.query(AttackCase).count():
        print(f"skip: attack_cases 이미 적재됨 (ATLAS {a} merge)")
        return
    n = 0
    for r in sq.execute("SELECT prompt_text,attack_type,atlas_technique_id,source,verified,tags,embedding FROM attack_cases"):
        db.add(AttackCase(prompt_text=r[0], attack_type=r[1], atlas_technique_id=r[2],
                          source=r[3], verified=bool(r[4]),
                          tags=json.loads(r[5]) if r[5] else {},
                          embedding=json.loads(r[6]) if r[6] else None))
        n += 1
        if n % 2000 == 0:
            db.commit()
            print(f"   ... {n}")
    db.commit()
    print(f"DONE: ATLAS {a} + attack_cases {n} 적재 (postgres)")


if __name__ == "__main__":
    main()
