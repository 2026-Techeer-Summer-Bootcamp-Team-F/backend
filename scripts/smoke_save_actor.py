# -*- coding: utf-8 -*-
"""저장 API 스모크 — POST /projects/{id}/actor.

FastAPI TestClient + get_current_user 의존성 오버라이드(JWT는 팀원 담당 미구현이라).
검증: 정상 저장(config·actor_type) / actor_type 누락=422 / url 누락=422 /
      browser 셀렉터 누락=422 / 타인 프로젝트=403 / 없는 프로젝트=404.

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_save_actor.py
"""
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal
from app.deps import get_current_user
from app.models import User, TargetProject

results = []


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


def setup():
    """테스트용 owner/other 유저 + owner 소유 타겟 생성(재실행 위해 먼저 정리)."""
    db = SessionLocal()
    try:
        db.query(TargetProject).filter(TargetProject.project_name == "smoke-proj").delete()
        db.query(User).filter(User.github_id.in_(["smoke-owner", "smoke-other"])).delete()
        db.commit()
        owner = User(github_id="smoke-owner", github_name="owner")
        other = User(github_id="smoke-other", github_name="other")
        db.add(owner); db.add(other); db.commit(); db.refresh(owner); db.refresh(other)
        tgt = TargetProject(user_id=owner.user_id, project_name="smoke-proj")
        db.add(tgt); db.commit(); db.refresh(tgt)
        return owner.user_id, other.user_id, tgt.target_id
    finally:
        db.close()


def teardown():
    db = SessionLocal()
    try:
        db.query(TargetProject).filter(TargetProject.project_name == "smoke-proj").delete()
        db.query(User).filter(User.github_id.in_(["smoke-owner", "smoke-other"])).delete()
        db.commit()
    finally:
        db.close()


def as_user(uid):
    """get_current_user를 uid 유저로 오버라이드."""
    def _fake():
        db = SessionLocal()
        try:
            return db.get(User, uid)
        finally:
            db.close()
    app.dependency_overrides[get_current_user] = _fake


def main():
    owner_id, other_id, tid = setup()
    client = TestClient(app)
    try:
        as_user(owner_id)
        good = {"config": {"actor_type": "http", "url": "http://t/chat",
                           "body_template": '{"message":"{{prompt}}"}', "response_path": "reply"},
                "system_prompt": "You are a bank bot.", "model": "gpt-4o"}
        r = client.post(f"/projects/{tid}/actor", json=good)
        check("정상 저장 200", r.status_code == 200)
        check("actor_type 노출 = http", r.json().get("actor_type") == "http")
        check("config.url 저장됨", r.json()["config"].get("url") == "http://t/chat")

        # DB에 실제로 반영됐나 + 전용 컬럼
        db = SessionLocal()
        t = db.get(TargetProject, tid)
        check("DB config 저장", (t.config or {}).get("url") == "http://t/chat")
        check("DB system_prompt 전용컬럼", t.system_prompt == "You are a bank bot.")
        check("DB model 전용컬럼", t.model == "gpt-4o")
        db.close()

        r = client.post(f"/projects/{tid}/actor", json={"config": {"url": "http://t"}})
        check("actor_type 누락 → 422", r.status_code == 422)
        r = client.post(f"/projects/{tid}/actor", json={"config": {"actor_type": "http"}})
        check("url 누락 → 422", r.status_code == 422)
        r = client.post(f"/projects/{tid}/actor",
                        json={"config": {"actor_type": "browser", "url": "http://t"}})
        check("browser 셀렉터 누락 → 422", r.status_code == 422)
        r = client.post("/projects/999999/actor", json=good)
        check("없는 프로젝트 → 404", r.status_code == 404)

        as_user(other_id)
        r = client.post(f"/projects/{tid}/actor", json=good)
        check("타인 프로젝트 → 403", r.status_code == 403)
    finally:
        app.dependency_overrides.clear()
        teardown()

    ok = all(c for _, c in results)
    print(f"\nSMOKE save-actor: {'PASS ✅' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
