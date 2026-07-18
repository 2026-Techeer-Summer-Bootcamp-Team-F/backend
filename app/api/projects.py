# -*- coding: utf-8 -*-
"""§2 GitHub Repos + §3 Projects — 레포목록·등록·수정·삭제·정찰. (담당: BE-API)

`POST /projects/{id}/actor`(액터 구성 저장)는 엔진(사용자) 스코프 — 스캔이 읽을
config 스키마를 정의하는 쪽이라 여기서 구현. 소유권 검증은 get_current_user(팀원 auth) 의존.
"""
import os

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select as sa_select
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import Objective, Scan, TargetProject, User, _now
from ..engine.code_scanner import run_code_scan
from ..recon import detect_http_contract, fetch_repo_sources, profile_target
from ..schemas import ActorSaveIn, DetectIn, ProjectCreateIn, ProjectUpdateIn
from ..security import decrypt_token

router = APIRouter(tags=["projects"])

_VALID_ACTOR_TYPES = {"http", "browser"}

# dev-login 사용자(실 GitHub 토큰 없음)용 픽스처 — Swagger/화면 테스트가 비지 않게.
_FIXTURE_REPOS = [
    {"full_name": "demo-user/bank-bot",
     "html_url": "https://github.com/demo-user/bank-bot",
     "description": "고객지원 챗봇(데모)", "private": False,
     "updated_at": "2026-07-01T09:00:00Z"},
    {"full_name": "demo-user/rag-assistant",
     "html_url": "https://github.com/demo-user/rag-assistant",
     "description": "사내 문서 RAG 어시스턴트(데모)", "private": True,
     "updated_at": "2026-06-20T12:00:00Z"},
]


def _project_out(t: TargetProject) -> dict:
    """TargetProject → API 응답 dict(액터 config·전용 컬럼 노출)."""
    return {"target_id": t.target_id, "project_name": t.project_name,
            "actor_type": (t.config or {}).get("actor_type", ""),
            "config": t.config or {}, "system_prompt": t.system_prompt, "model": t.model}


def _project_detail(t: TargetProject) -> dict:
    """상세/등록/수정 응답 — Project 전체 필드(§3 Project 스키마)."""
    return {"target_id": t.target_id, "project_name": t.project_name,
            "actor_type": (t.config or {}).get("actor_type", ""),
            "config": t.config or {}, "purpose": t.purpose,
            "system_prompt": t.system_prompt, "repo_url": t.repo_url,
            "model": t.model, "defences": t.defences or {},
            "tools": t.tools or {}, "rag_sources": t.rag_sources or {},
            "created_at": t.created_at}


def _project_list_item(t: TargetProject) -> dict:
    """목록 응답 — 대시보드 좌측용 축약 필드."""
    return {"target_id": t.target_id, "project_name": t.project_name,
            "actor_type": (t.config or {}).get("actor_type", ""),
            "config": t.config or {},
            "model": t.model, "repo_url": t.repo_url, "created_at": t.created_at}


def _owned_or_error(db: Session, target_id: int, user: User) -> TargetProject:
    """소유 프로젝트 조회 — 없음/삭제됨=404, 타인=403. (§3 소유권 규칙)"""
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 접근 가능")
    return target


@router.get("/github/repos")
def github_repos(q: str = "", page: int = 1,
                 user: User = Depends(get_current_user)):
    """로그인 사용자 GitHub 레포 목록(Vercel식 Import 화면용). 응답 {data:[...]}.

    저장된 access_token 으로 GitHub /user/repos 호출. dev-login 사용자(토큰 없음)는
    픽스처 목록을 돌려줘 Swagger/화면 테스트가 가능하게 한다. q=이름·설명 필터, page=페이지.
    """
    token = decrypt_token(user.access_token_enc)
    if not token:
        data = list(_FIXTURE_REPOS)
    else:
        try:
            with httpx.Client(timeout=10) as client:
                resp = client.get(
                    "https://api.github.com/user/repos",
                    headers={"Authorization": f"Bearer {token}",
                             "Accept": "application/vnd.github+json"},
                    params={"per_page": 30, "page": page, "sort": "updated"},
                )
        except httpx.RequestError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 레포 조회 요청 실패") from None
        if resp.status_code != 200:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 레포 조회 실패")
        try:
            repos = resp.json()
        except ValueError:
            raise HTTPException(status.HTTP_502_BAD_GATEWAY, "GitHub 레포 응답 파싱 실패") from None
        data = [{"full_name": r["full_name"], "html_url": r["html_url"],
                 "description": r.get("description"), "private": r["private"],
                 "updated_at": r.get("updated_at")} for r in repos]
    if q:
        ql = q.lower()
        data = [r for r in data
                if ql in (r["full_name"] or "").lower()
                or ql in (r.get("description") or "").lower()]
    return {"data": data}


@router.post("/projects", status_code=201)
def create_project(body: ProjectCreateIn, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """대상 앱 등록 — 동의 후 '액터 정보 작성' 화면에서 제출(§3, 기능명세 ④).

    actor_type을 config에 병합 저장(별도 컬럼 없음). 정찰 필드
    (model/defences/tools/rag_sources)는 비운 채 생성 → 이후 recon으로 채움.
    config 상세검증은 느슨(등록 시엔 actor_type만 검증, url·셀렉터는 /actor에서).
    """
    if body.actor_type not in _VALID_ACTOR_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"actor_type 필수 (http|browser), 받음={body.actor_type!r}")
    config = dict(body.config or {})
    config["actor_type"] = body.actor_type                 # config 안에 병합 저장
    target = TargetProject(
        user_id=user.user_id, project_name=body.project_name, config=config,
        purpose=body.purpose or "", system_prompt=body.system_prompt or "",
        repo_url=body.repo_url or "")
    db.add(target)
    db.commit()
    db.refresh(target)
    return _project_detail(target)


@router.post("/projects/detect")
def detect_config(body: DetectIn, user: User = Depends(get_current_user)):
    """레포에서 HTTP 연결 config 자동 감지 → 등록 폼 프리필(마찰 감소).

    공개 레포는 스코프 없이 fetch(비공개는 저장 토큰). 감지는 휴리스틱이라
    실패(fetch 불가/파싱 불가) 시 detected=false → 프론트가 프리셋·수동으로 폴백.
    route_path는 참고용(호스트는 런타임이라 url은 사용자가 확인/입력).
    """
    token = decrypt_token(user.access_token_enc)
    sources = fetch_repo_sources(body.repo_url, token) if body.repo_url else {}
    contract = detect_http_contract(sources) if sources else None
    if not contract:
        return {"detected": False, "source": "none", "config": None}
    cfg = {"actor_type": "http", "method": "POST",
           "body_template": contract["body_template"],
           "response_path": contract["response_path"]}
    # URL 프리필: 사용자가 준 url 우선, 없으면 감지한 포트+경로로 추천.
    hint = None
    if body.url:
        cfg["url"] = body.url
    elif contract.get("route_path"):
        portpart = f":{contract['port']}" if contract.get("port") else ""
        route = contract["route_path"]
        if settings.public_deployment:
            # 배포된 스캐너는 사용자 PC의 localhost에 못 닿는다. host.docker.internal도
            # 클라우드 호스트를 가리켜 무의미 → 로컬 주소를 그대로 제안하되 공개 URL 안내.
            cfg["url"] = f"http://localhost{portpart}{route}"
            hint = ("감지된 주소가 로컬(localhost)이에요. 배포된 REDI는 여러분 PC의 "
                    "localhost에 닿지 못해요. 공개 URL(ngrok·cloudflared 터널 주소)로 "
                    f"바꿔주세요 — 경로 {route} 는 그대로 두면 됩니다.")
        else:
            # 로컬 개발: 스캐너가 도커면 표적의 localhost는 host.docker.internal.
            host = "host.docker.internal" if os.path.exists("/.dockerenv") else "localhost"
            cfg["url"] = f"http://{host}{portpart}{route}"
    return {"detected": True, "source": "repo",
            "confidence": contract["confidence"],
            "route_path": contract.get("route_path"),
            "port": contract.get("port"), "hint": hint, "config": cfg}


@router.get("/projects")
def list_projects(db: Session = Depends(get_db),
                  user: User = Depends(get_current_user)):
    """등록된 내 프로젝트 목록(대시보드 좌측). soft-deleted 제외, 응답 {data:[...]}."""
    rows = (db.query(TargetProject)
              .filter(TargetProject.user_id == user.user_id,
                      TargetProject.deleted_at.is_(None))
              .order_by(TargetProject.created_at.desc())
              .all())
    return {"data": [_project_list_item(t) for t in rows]}


@router.get("/projects/{target_id}")
def get_project(target_id: int, db: Session = Depends(get_db),
                user: User = Depends(get_current_user)):
    """프로젝트 단건 조회 — 본인 소유만(§3). 없음=404 / 타인=403."""
    return _project_detail(_owned_or_error(db, target_id, user))


@router.get("/projects/{target_id}/scan-history")
def scan_history(target_id: int, db: Session = Depends(get_db),
                 user: User = Depends(get_current_user)):
    """스캔 버전 관리용 이력(#132) — 프로젝트의 스캔을 최신순으로 요약. 소유권 검증(§3).

    각 스캔: id·날짜·commit_sha·상태 + objective 집계(총/방어/돌파). objective는 한 번에
    조회해 Python에서 스캔별 집계(N+1 회피). 최대 50건.
    """
    target = _owned_or_error(db, target_id, user)
    scans = db.scalars(
        sa_select(Scan).where(Scan.target_id == target_id)
        .order_by(Scan.scan_id.desc()).limit(50)).all()
    scan_ids = [s.scan_id for s in scans]
    # objective(status)를 한 번에 조회 → 스캔별 (총, 방어, 돌파) 집계.
    # 방어는 종료 상태만 명시 집계(미확정 pending/running을 방어로 오집계하지 않음, CodeRabbit #134).
    agg: dict = {}
    if scan_ids:
        rows = db.execute(
            sa_select(Objective.scan_id, Objective.status)
            .where(Objective.scan_id.in_(scan_ids))).all()
        for sid, st in rows:
            total, defended, breached = agg.get(sid, (0, 0, 0))
            if st == "breached":
                breached += 1
            elif st not in ("pending", "running"):     # safe/exhausted/failed = 방어 확정
                defended += 1
            agg[sid] = (total + 1, defended, breached)
    out = []
    for s in scans:
        total, defended, breached = agg.get(s.scan_id, (0, 0, 0))
        out.append({
            "scan_id": s.scan_id,
            "date": s.created_at.date().isoformat() if s.created_at else None,
            "commit_sha": s.commit_sha,
            "status": s.status,
            "total_objectives": total,
            "defended": defended,
            "breach_count": breached,
        })
    return {"target_id": target_id, "project_name": target.project_name, "scans": out}


@router.patch("/projects/{target_id}")
def update_project(target_id: int, body: ProjectUpdateIn,
                   db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """프로젝트 부분 수정 — 전달된 필드만 반영(§3). 없음=404 / 타인=403.

    config는 통째 교체(부분 병합 아님). 미전달 필드는 기존값 보존.
    """
    target = _owned_or_error(db, target_id, user)
    if body.project_name is not None:
        target.project_name = body.project_name
    if body.config is not None:
        new_config = dict(body.config)                    # actor_type는 config 안에만 있음
        at = new_config.get("actor_type")
        if at is not None and at not in _VALID_ACTOR_TYPES:  # 명시 값이면 POST·save_actor와 동일 검증
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"actor_type 필수 (http|browser), 받음={at!r}")
        new_config.setdefault("actor_type",               # 생략 시엔 기존값 승계(소실 방지)
                              (target.config or {}).get("actor_type", ""))
        target.config = new_config
    if body.purpose is not None:
        target.purpose = body.purpose
    if body.system_prompt is not None:
        target.system_prompt = body.system_prompt
    if body.repo_url is not None:
        target.repo_url = body.repo_url
    db.commit()
    db.refresh(target)
    return _project_detail(target)


@router.delete("/projects/{target_id}", status_code=204)
def delete_project(target_id: int, db: Session = Depends(get_db),
                   user: User = Depends(get_current_user)):
    """등록 해제(soft-delete) — deleted_at 세팅(§3, 기능명세: 삭제=등록해제)."""
    target = _owned_or_error(db, target_id, user)
    target.deleted_at = _now()
    db.commit()
    return None


@router.post("/projects/{target_id}/actor")
def save_actor(target_id: int, body: ActorSaveIn,
               db: Session = Depends(get_db),
               user: User = Depends(get_current_user)):
    """액터 구성 저장 — 동의 후 '액터 정보 입력' 화면에서 제출.

    config(JSON)에 액터 설정 저장. actor_type은 config 안(DB 컬럼 아님).
    system_prompt·model은 전용 컬럼. 스캔 엔진이 이 config를 읽어 액터 생성→발사.
    """
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 수정 가능")

    cfg = body.config or {}
    actor_type = cfg.get("actor_type")
    if actor_type not in _VALID_ACTOR_TYPES:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"config.actor_type 필수 (http|browser), 받음={actor_type!r}")
    if not cfg.get("url"):
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "config.url 필수")
    if actor_type == "browser":
        for req in ("input_selector", "output_selector"):
            if not cfg.get(req):
                raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                    f"browser: config.{req} 필수")

    target.config = cfg                                   # 액터 설정 저장(JSON)
    if body.system_prompt is not None:                    # 전용 컬럼
        target.system_prompt = body.system_prompt
    if body.model is not None:
        target.model = body.model
    db.commit()
    db.refresh(target)
    return _project_out(target)


@router.post("/projects/{target_id}/recon")
def recon(target_id: int, db: Session = Depends(get_db),
          user: User = Depends(get_current_user)):
    """정찰 실행 → target_projects.model/defences/tools/rag_sources/code_locations 갱신."""
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 정찰 가능")

    # 기존 프로파일 추출
    profile = profile_target(target)
    target.model = profile["model"] or target.model
    if profile["system_prompt"]:
        target.system_prompt = profile["system_prompt"]
    target.defences = {"detected": profile["defenses"]}
    target.tools = {"detected": profile["tools"]}
    target.rag_sources = {"detected": profile["rag_sources"]}

    # 코드 위치 스캔 (GitHub token으로 레포 fetch)
    token = decrypt_token(user.access_token_enc) or ""
    all_atlas_ids = [
        "AML.T0054", "AML.T0051.000", "AML.T0051.001",
        "AML.T0056", "AML.T0057", "AML.T0053",
    ]
    target.code_locations = run_code_scan(target.repo_url, all_atlas_ids, token)

    db.commit()
    db.refresh(target)
    return {"target_id": target_id, "profile": profile,
            "code_locations_count": len(target.code_locations)}
