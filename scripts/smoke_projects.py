# -*- coding: utf-8 -*-
"""프로젝트 CRUD 스모크 — POST/GET/PATCH/DELETE /projects.

FastAPI TestClient + get_current_user 의존성 오버라이드(smoke_save_actor 패턴).
검증: 등록 201·필드 / actor_type 무효=422 / 목록(본인·삭제제외) /
      상세 200·타인403·없음404 / 부분수정 반영·보존 / soft-delete 204·목록제외.

실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_projects.py
"""
from fastapi.testclient import TestClient

from app.main import app
from app.db import SessionLocal
from app.deps import get_current_user
from app.models import User, TargetProject

results = []
_NAMES = ["smoke-proj-a", "smoke-proj-b", "smoke-proj-c"]


def check(name, cond):
    results.append((name, cond))
    print(f"  {'✅' if cond else '❌'} {name}")


def setup():
    """owner/other 유저 생성(프로젝트는 API로 만든다). 재실행 위해 먼저 정리."""
    db = SessionLocal()
    try:
        db.query(TargetProject).filter(TargetProject.project_name.in_(_NAMES)).delete(
            synchronize_session=False)
        db.query(User).filter(User.github_id.in_(["smoke-owner", "smoke-other"])).delete()
        db.commit()
        owner = User(github_id="smoke-owner", github_name="owner")
        other = User(github_id="smoke-other", github_name="other")
        db.add(owner); db.add(other); db.commit(); db.refresh(owner); db.refresh(other)
        return owner.user_id, other.user_id
    finally:
        db.close()


def teardown():
    db = SessionLocal()
    try:
        db.query(TargetProject).filter(TargetProject.project_name.in_(_NAMES)).delete(
            synchronize_session=False)
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
    owner_id, other_id = setup()
    client = TestClient(app)
    try:
        as_user(owner_id)

        # --- POST /projects (등록) ---
        req = {"project_name": "smoke-proj-a", "actor_type": "http",
               "config": {"url": "http://t/chat", "response_path": "reply"},
               "purpose": "고객봇", "system_prompt": "너는 상담원", "repo_url": "http://g/r"}
        r = client.post("/projects", json=req)
        check("등록 201", r.status_code == 201)
        body = r.json()
        tid_a = body.get("target_id")
        check("등록 target_id 발급", isinstance(tid_a, int) and tid_a > 0)
        check("등록 actor_type=http(config에서 노출)", body.get("actor_type") == "http")
        check("등록 config.url 저장", body.get("config", {}).get("url") == "http://t/chat")
        check("등록 응답 정찰필드 존재",
              all(k in body for k in ("model", "defences", "tools", "rag_sources", "created_at")))

        # actor_type이 config에 병합됐는지 DB 확인
        db = SessionLocal()
        t = db.get(TargetProject, tid_a)
        check("DB config.actor_type 병합", (t.config or {}).get("actor_type") == "http")
        check("DB purpose 전용컬럼", t.purpose == "고객봇")
        db.close()

        # actor_type 무효 → 422 (느슨한 등록: 그래도 actor_type 값 검증)
        r = client.post("/projects", json={"project_name": "smoke-proj-x", "actor_type": "ftp"})
        check("actor_type 무효 → 422", r.status_code == 422)
        # 빈 project_name → 422
        r = client.post("/projects", json={"project_name": "", "actor_type": "http"})
        check("빈 project_name → 422", r.status_code == 422)

        # 두 번째 프로젝트(목록/삭제 검증용)
        r = client.post("/projects", json={"project_name": "smoke-proj-b", "actor_type": "browser",
                                           "config": {}})
        tid_b = r.json()["target_id"]

        # --- GET /projects (목록) ---
        r = client.get("/projects")
        check("목록 200", r.status_code == 200)
        data = r.json().get("data", [])
        names = {d["project_name"] for d in data}
        check("목록 본인 프로젝트 2건 포함", {"smoke-proj-a", "smoke-proj-b"} <= names)
        check("목록 축약필드만",
              data and set(data[0].keys()) == {"target_id", "project_name", "actor_type",
                                               "model", "repo_url", "created_at"})

        # --- GET /projects/{id} (상세) ---
        r = client.get(f"/projects/{tid_a}")
        check("상세 200", r.status_code == 200)
        check("상세 purpose 노출", r.json().get("purpose") == "고객봇")
        r = client.get("/projects/999999")
        check("없는 프로젝트 상세 → 404", r.status_code == 404)

        # --- PATCH /projects/{id} (부분수정) ---
        r = client.patch(f"/projects/{tid_a}", json={"purpose": "변경된 용도"})
        check("수정 200", r.status_code == 200)
        check("수정 purpose 반영", r.json().get("purpose") == "변경된 용도")
        check("수정 project_name 보존", r.json().get("project_name") == "smoke-proj-a")
        # config만 갱신해도 actor_type 소실 안 됨(config 안에만 있으므로 승계)
        r = client.patch(f"/projects/{tid_a}", json={"config": {"url": "http://new/chat"}})
        check("config 교체 후 actor_type 보존", r.json().get("actor_type") == "http")
        check("config 교체 반영", r.json().get("config", {}).get("url") == "http://new/chat")

        # --- DELETE /projects/{id} (soft-delete) ---
        r = client.delete(f"/projects/{tid_b}")
        check("삭제 204", r.status_code == 204)
        db = SessionLocal()
        check("DB deleted_at 세팅", db.get(TargetProject, tid_b).deleted_at is not None)
        db.close()
        r = client.get("/projects")
        names = {d["project_name"] for d in r.json()["data"]}
        check("삭제된 프로젝트 목록 제외", "smoke-proj-b" not in names)
        r = client.get(f"/projects/{tid_b}")
        check("삭제된 프로젝트 상세 → 404", r.status_code == 404)

        # --- 소유권: 타인 접근 → 403 ---
        as_user(other_id)
        r = client.get(f"/projects/{tid_a}")
        check("타인 상세 → 403", r.status_code == 403)
        r = client.patch(f"/projects/{tid_a}", json={"purpose": "x"})
        check("타인 수정 → 403", r.status_code == 403)
        r = client.delete(f"/projects/{tid_a}")
        check("타인 삭제 → 403", r.status_code == 403)
        r = client.get("/projects")
        check("타인 목록엔 owner 프로젝트 없음",
              all(d["project_name"] not in _NAMES for d in r.json()["data"]))
    finally:
        app.dependency_overrides.clear()
        teardown()

    ok = all(c for _, c in results)
    print(f"\nSMOKE projects: {'PASS ✅' if ok else 'FAIL ❌'}")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
