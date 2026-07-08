# ▶ 다음에 오면 여기부터 (바로 시작용)

> 갱신: **2026-07-07** 세션 종료. 결정 기록: `docs/결정로그-2026-07-07.md`, 트러블슈팅: `트러블슈팅.md`, 차례: `README.md`.

## ★ 향후 일정 (로드맵) — 사용자 확정
```
1. (진행 중) 팀원이 디자인 작업        ← 지금 여기
2. 디자인 완료 후 → 벡터DB(pgvector) 구축  ← **소스 조사·13유형 매핑 완료(2026-07-07~08, `docs/벡터DB-적재계획.md`)**. 남은 건 **실제 수집→정제→dedup→임베딩→적재**.
     · 실제 공격 사례를 더 수집 → 데이터베이스로 구축 (attack_cases + embedding)
3. 개발 환경 세팅
4. 개발 착수
```
→ **디자인·벡터DB 데이터 수집이 먼저**, 그 다음 개발 세팅→개발. (아래 "개발 착수 순서"는 4단계에서 볼 것)

## 오늘(2026-07-07) 한 것
1. **ERD 정규화** (삼각형/3NF 제거): `findings`에서 `objective_id`·`atlas_technique_id` 삭제(attempt_id 조인), `objectives`에서 `name`·`category` 삭제(atlas_techniques 조인). `scan_id`·`mitigation`은 의도적 유지. → `docs/ERD-완전정리.md`·ERDCloud·새 ERD 이미지 반영.
2. **기능명세 검증 + 플로우 확정**: 노션 기능명세 17행 ↔ API 매칭 → `docs/기능명세.md`. 플로우 = 온보딩→GitHub로그인→대시보드(내 레포목록)→레포선택→동의+액터구성→스캔→리포트.
3. **결정 변경**: AI 요약 **채택**(LLM 요약 도입), 진화트리 후순위, 삭제=동의해제, 통계지표 4개 확정(`breached`→`breached_attempts`).
4. **문서 대정리**: 모든 기획/스펙/PoC를 **`기획/` 폴더로 통합**. `poc`→`기획/poc`(corpus.py 경로 수정), `slides` 삭제(발표용, 노션 중복). 아키텍처 관측성 스택 보강. 새 ERD·시스템아키텍처 이미지 저장.
5. 별도 설계노트: `docs/액터-인증-설계.md`, `docs/진화엔진-정리.md`, `docs/정찰-액터자동구성-설계.md`.

## 개발 착수 순서 (로드맵 4단계에서 — 기술)
**A. ERD 모델 리팩터** ⚠️큰 작업 (도는 데모 깨질 수 있음, 매 단계 `run_demo.py` 검증)
- `app/backend/app/models.py`: 옛 11테이블 → **오늘 정규화한 10테이블**. `Target`→`target_projects`(정찰 통합), ownership/verify·avatar_url 삭제, `github_login`→`github_name`, `seed_case_id`→`attack_id`, findings/objectives 정규화 반영, (선택)PK `xxx_id` 단수 통일.
- 영향: `routers/*` + 엔진 + `run_demo.py` + `gen_erd.py` 연쇄.

**B. 벡터검색 채우기** (최대 차별점) — 로드맵 2번의 데이터 위에서
- `pip install sentence-transformers`, `attack_cases.embedding` 생성 + 코사인 검색(PoC 브루트포스 → Prod pgvector).

**C. 프론트 새 플로우·화면** — 확정 플로우(대시보드=GitHub 레포목록, 동의+액터구성) + 와이어프레임 6화면 반영.

**D. LLM 자리 배선** (옵션) — 변이(L2 로컬/L3 상용)·판정(애매한것)·정찰 요약·**리포트 AI 요약**.

**E. 신규 엔드포인트**: `GET /github/repos`, `POST /auth/logout`, `PATCH /projects/{id}`, 스캔 config `attack_types`/`target_model` 반영, 리포트 `ai_summary`.

## 미결정 (착수 전 정할 것)
- **D1 히트맵 충돌**: attack_types→objectives를 atlas 기준 dedup 할지(권장) / attack_type_key 추가할지.
- **A2 ATLAS 커버리지**: attack-types 13종의 `T0062`·`T0029` 등을 atlas_techniques 마스터에 추가.
- **★공격 시나리오(멘토 피드백 2026-07-08)**: 로그인/비로그인·역할별·앱종류·부작용 등 상태별 공격 시나리오 → `docs/공격시나리오-설계.md`. 지금 락 후보 = ①인증 컨텍스트별 스캔(scans.config `auth_context`) ②카나리 없는 판정 ③안전모드(드라이런). 스캔 config 구조에 영향 → 착수 전 범위 확정 필요.
- 노션 중복 DB("API 명세 v2"·옛 "api 명세서") archive 정리.

## 실행 방법 (환경 주의)
- 로컬: 시스템 py3.9 venv. `cd app/backend && .venv/bin/python run_demo.py` (진화→FLAG 유출 확인).
- 서버: `.venv/bin/uvicorn app.main:app --reload --port 8000` / 프론트 `cd app/frontend && npm run dev`.
- **Docker**: ⚠️Docker Desktop **데몬 켜야** 함. 켜고 `docker compose up --build` → 프론트 http://localhost:8080.
- 미설치(실행하려면 필요): playwright(BrowserActor), anthropic(LLM), sentence-transformers(벡터검색). homebrew py3.13/3.14 libexpat 깨짐 여전 → Docker는 py3.11이라 무관.
- ⚠️ 코퍼스 실데이터: `기획/poc/ai_redteam/data/jailbreak_prompts.csv`를 `corpus.py`가 읽음(이동 시 경로 주의).

## 오늘(2026-07-07~08) 추가로 한 것 — 벡터DB 소스 조사
- **`docs/벡터DB-적재계획.md` 완성**: DB 띄우기(로컬Docker→RDS/Neon, 비용설정)·영속성·이관·팀공유 + **데이터 소스 20+ 직접 실사**(컬럼·접근·날짜·모델·라이선스·fit) + **ATLAS 13유형 커버리지 매핑** + **소스 품질 평가**.
- **결론**: 13유형 전부 확보 경로 확정 = ①대량적재(Necent·in-the-wild·SALAD·BIPIA·InjecAgent·Tensor Trust·Anthropic red-team 등) ②각색(hallucination=HaluEval/FactCHD/AutoHall) ③템플릿 자체제작(DoS=Engorgio/ThinkTrap식).
- **주의**: 소스는 OK지만 **중복 많음→dedup 필수 / 2023 편중→최신 보강 / 품질편차→verified 재검증**. ⚠️ai4privacy는 제외(공격 아님).
- **실제 적재는 안 함**(조사·기록만).

## 내일(다음 세션) 시작점 ★
→ **디자인(팀원)** 대기 중. 그다음 **벡터DB 실제 적재**: `docs/벡터DB-적재계획.md` §0~2 따라 (1)로컬 pgvector `docker compose up` (2)Necent+in-the-wild부터 수집 (3)정제·dedup·임베딩·적재 파이프라인 1소스 관통 → 확장.

## 현재 상태 한 줄
문서·설계·ERD·기능명세·아키텍처 **최신 확정** + **벡터DB 소스조사·계획 완료**. `app/`은 **돌아가는 PoC(옛 11테이블 스펙)** — 오늘 정규화·플로우 미반영. 다음 = 디자인 → **벡터DB 실제 적재** → 개발세팅 → A. models 리팩터.
