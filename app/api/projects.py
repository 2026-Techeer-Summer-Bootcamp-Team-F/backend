# -*- coding: utf-8 -*-
"""§2 GitHub Repos + §3 Projects — 레포목록·등록·수정·삭제·정찰. (담당: BE-API)

`POST /projects/{id}/actor`(액터 구성 저장)는 엔진(사용자) 스코프 — 스캔이 읽을
config 스키마를 정의하는 쪽이라 여기서 구현. 소유권 검증은 get_current_user(팀원 auth) 의존.
"""
import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..db import get_db
from ..deps import get_current_user
from ..models import TargetProject, User
from ..recon import profile_target
from ..schemas import ActorSaveIn, ProjectCreateIn
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


@router.get("/projects")
def list_projects():
    """등록된 내 프로젝트(대시보드 좌측). TODO"""
    return []


@router.get("/projects/{target_id}")
def get_project(target_id: int):
    """프로젝트 단건 조회. TODO"""
    return {"target_id": target_id}


@router.patch("/projects/{target_id}")
def update_project(target_id: int):
    """config·purpose·system_prompt 등 수정. TODO"""
    return {"target_id": target_id}


@router.delete("/projects/{target_id}", status_code=204)
def delete_project(target_id: int):
    """등록 해제(soft-delete). TODO"""
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
    """정찰 실행 → target_projects.model/defences/tools/rag_sources 갱신. recon.py 호출.

    코드 소스는 config.source_path(로컬) 우선, 없으면 등록입력만. repo fetch는 팀원 auth 대기.
    save_actor와 동일하게 인증+소유권 검증(본인 프로젝트만).
    """
    target = db.get(TargetProject, target_id)
    if target is None or target.deleted_at is not None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "프로젝트 없음")
    if target.user_id != user.user_id:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "본인 프로젝트만 정찰 가능")
    profile = profile_target(target)
    target.model = profile["model"] or target.model
    if profile["system_prompt"]:
        target.system_prompt = profile["system_prompt"]
    target.defences = {"detected": profile["defenses"]}
    target.tools = {"detected": profile["tools"]}
    target.rag_sources = {"detected": profile["rag_sources"]}
    db.commit()
    db.refresh(target)
    return {"target_id": target_id, "profile": profile}
