# -*- coding: utf-8 -*-
"""백엔드 E2E 스모크 — 등록→스캔→SSE→결과→상세까지 전 API 관통 검증. (#56)

더미앱(AcmeBank)을 표적으로 실제 스캔을 돌려 엔진이 FLAG를 뚫고, 그 결과가 모든
결과/상세 API로 정확히 나오는지 순서대로 확인한다. 각 단계 PASS/FAIL 출력.
실행: docker compose exec -T -e PYTHONPATH=/app backend python scripts/smoke_e2e.py
"""
import os
import time

import httpx

from app.db import SessionLocal
from app.models import TargetProject, User

BASE = "http://localhost:8000"
CANARY = "FLAG{acmebank_pr0mpt_1nj3ction_2026}"


def main():
    results = []

    def check(name, ok, detail=""):
        ok = bool(ok)
        results.append(ok)
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}  {detail}")

    # 0) 표적 등록(더미앱 액터 config + 카나리)
    db = SessionLocal()
    tag = f"e2e-{os.getpid()}"   # 재실행 가능하게 unique(github_id는 unique 제약)
    u = User(github_id=tag, github_name=tag); db.add(u); db.commit(); db.refresh(u)
    cfg = {"actor_type": "http", "url": "http://backend:8000/dummy/acmebank/chat",
           "method": "POST", "body_template": '{"message": "{{prompt}}"}',
           "response_path": "reply", "canary": CANARY, "source_path": "app/api/dummy.py"}
    t = TargetProject(user_id=u.user_id, project_name="e2e", config=cfg)
    db.add(t); db.commit(); db.refresh(t)
    print(f"▶ 표적 등록 target_id={t.target_id}")

    # 인증: 엔드포인트가 JWT 보호되므로 mock dev-login으로 토큰 발급 → 모든 요청에 첨부
    tok = httpx.post(f"{BASE}/auth/dev-login", json={"github_name": tag}, timeout=10).json()["access_token"]
    client = httpx.Client(headers={"Authorization": f"Bearer {tok}"})

    # 1) GET /attack-types
    at = client.get(f"{BASE}/attack-types", timeout=10).json()
    check("GET /attack-types", len(at) >= 5, f"{len(at)}종")

    # 2) POST /scans (진화 시작)
    r = client.post(f"{BASE}/scans", json={"target_id": t.target_id,
                   "config": {"attack_types": ["jailbreak", "prompt_injection", "system_prompt_leak"],
                              "canary": CANARY}}, timeout=10)
    sid = r.json()["scan_id"]
    check("POST /scans", r.status_code == 202 and sid, f"scan_id={sid}, {r.status_code}")

    # 3) 완료 대기 + GET /scans/{id}
    status = None
    for _ in range(90):
        status = client.get(f"{BASE}/scans/{sid}", timeout=10).json()["status"]
        if status in ("done", "failed"):
            break
        time.sleep(1)
    check("GET /scans/{id} 완료", status == "done", f"status={status}")

    # 4) SSE /stream 재생(?after=0 → 전체 이벤트 + done)
    txt = client.get(f"{BASE}/scans/{sid}/stream?after=0&token={tok}", timeout=10).text
    check("GET /scans/{id}/stream (SSE 재생)",
          '"event": "done"' in txt and txt.count("data:") >= 3, f"{txt.count('data:')} 이벤트")

    # 5) GET /report (명세 형태 + 침투)
    rep = client.get(f"{BASE}/scans/{sid}/report", timeout=10).json()
    check("GET /report", "total_objectives" in rep and "stats" in rep
          and rep["breached_count"] >= 1, f"침투 {rep.get('breached_count')}/{rep.get('total_objectives')}, 위험도 {rep.get('risk_score')}")

    # 6) GET /heatmap
    hm = client.get(f"{BASE}/scans/{sid}/heatmap", timeout=10).json()
    check("GET /heatmap", len(hm["cells"]) >= 1 and any(c["breached"] for c in hm["cells"]),
          f"{len(hm['cells'])} 셀, 침투 {sum(c['breached'] for c in hm['cells'])}")

    # 7) GET /findings (FLAG 유출 증거)
    fs = client.get(f"{BASE}/scans/{sid}/findings", timeout=10).json()
    leaked = any(CANARY in (f["evidence"].get("canary_hit") or "") for f in fs)
    check("GET /findings (FLAG 유출)", len(fs) >= 1 and leaked, f"{len(fs)}건, 카나리 매치={leaked}")

    # 8) GET /objectives/{id}/tree (진화 트리)
    breached_oid = next((f for f in fs), None)
    # findings→attempt→objective 로 트리 확인: report/heatmap에서 침투 objective 찾기
    oid = None
    for c in hm["cells"]:
        if c["breached"]:
            # heatmap엔 objective_id가 없어 tree는 findings의 attempt로 역추적 대신 objectives 순회
            pass
    # 침투 objective_id는 attempts에서 — 간단히 첫 finding의 attempt로 tree 검증
    aid = fs[0]["attempt_id"]
    at_detail = client.get(f"{BASE}/attempts/{aid}", timeout=10).json()
    oid = at_detail["objective_id"]
    tree = client.get(f"{BASE}/objectives/{oid}/tree", timeout=10).json()
    check("GET /objectives/{id}/tree", len(tree["nodes"]) >= 1
          and any(n["breached"] for n in tree["nodes"]), f"{len(tree['nodes'])} 노드")

    # 9) GET /attempts/{id} (시도 상세)
    check("GET /attempts/{id}", at_detail["verdict"] == "breach" and CANARY in at_detail["response"],
          f"verdict={at_detail['verdict']}, gen={at_detail['generation']}, op={at_detail['mutation_op']}")

    # 10) GET /summary (AI 요약 or 템플릿)
    sm = client.get(f"{BASE}/scans/{sid}/summary", timeout=15).json()
    check("GET /summary", bool(sm.get("ai_summary")), f"source={sm.get('source')}")

    # 11) GET /atlas
    al = client.get(f"{BASE}/atlas", timeout=10).json()
    check("GET /atlas", len(al) >= 1, f"{len(al)} 기법")

    print(f"\n{'='*50}")
    print(f"E2E 결과: {sum(results)}/{len(results)} PASS "
          f"{'✅ 전체 관통 성공' if all(results) else '❌ 일부 실패'}")


if __name__ == "__main__":
    main()
