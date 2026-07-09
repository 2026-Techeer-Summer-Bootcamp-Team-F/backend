# ▶ 다음에 오면 여기부터 (바로 시작용)

> 갱신: **2026-07-09** 세션. 스캔 엔진 구현 착수. 상세 계획: `docs/스캔API-구현계획.md`, 트러블슈팅: `트러블슈팅.md`.

## 🔥 지금 상태 (2026-07-09) — 스캔 파이프라인 구현 중

**환경**: docker compose(backend·db(pgvector)·redis·worker) 로컬 구동 중. 코퍼스 `attack_cases` 21,219건 + atlas_techniques 9건 적재됨.

**스캔 엔진 진행 (사용자 담당, `POST /scans` 이후):**
| 이슈 | 내용 | 상태 |
|---|---|---|
| #34 | Celery+Redis 백그라운드 실행 뼈대 | ✅ 머지(PR#44) |
| #35 | 실시간 중계·기록 `scan_manager`(persist-then-publish) | ✅ 머지(PR#45) |
| #36 | 스캔 시작~완료 전체 흐름 관통(POST→워커→done) | ✅ 머지(PR#46) |
| #37 | 정찰(ast+grep 프로파일→공격유형 매핑→objectives) | 🔨 **구현+스모크PASS, feat/#37 미커밋**(검토 후 커밋→클로드리뷰) |
| #38 | 엔진 부품(retrieve·select·mutate·judge) | ⬜ |
| #39 | 진화루프(실제 FLAG 뚫기) = 가운데 빈 자리 채우기 | ⬜ |
| #40 | Haiku 판정(애매 1~3%) | ⬜ |
| #41 | SSE 실시간 화면(`GET /scans/{id}/events`) | ⬜ |
| #42 | 결과 API + AI 요약 | ⬜ |
| #43 | 액터 배선(진화루프→actor.fire) | ⬜ |

**"접수→큐→워커→정찰→(진화 빈자리)→완료" 배관 관통 완료.** 남은 알맹이 = #38·#39(실제 공격).

**다음 세션 시작점**: feat/#37 코드 검토 → 커밋 → 클로드 리뷰 → 머지 → **#38 엔진 부품**.

**오늘(07-09) 확정한 것**:
- **리뷰 워크플로우**: CodeRabbit 일일 토큰 상한 있음 → 아끼려고 **Claude 코드리뷰(code-reviewer 에이전트)로 대체 가능**. develop는 "대화해결 필수" 룰셋이라 리뷰 후 `gh pr merge --admin`(기계적 잠금 우회, 트러블 #18).
- **목표(objectives) 0개 처리**: #36은 관대(즉시 done). "공격유형 0개면 422 거절"은 #37 이후 매핑표 완비 시(코드 `TODO(#37)`).
- **정찰 대상 = 팀원이 만드는 실제 공격용 챗봇 레포**(내 `app/api/dummy.py`는 임시 검증 스탠드인). recon 엔진은 범용 — `config.source_path`/repo만 갈아끼움. ⚠️ 리포 자동 fetch는 OAuth `repo` 스코프(팀원 auth) 대기.
- **벡터 임베딩 별도 테이블 분리**(멘토 제안): 검색용 벡터를 빼면 나머지 테이블 가벼워져 분석↑. FK 강제X + soft ref id는 필수. 배포(RDS) 시점 검토 → `docs/ERD-완전정리.md` 메모.

---

## (이하 2026-07-07 기록 — 참고용)

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

## 오늘(2026-07-09) 한 것 — 액터 파트 전부 구현 ★
액터 = 표적에 공격 발사하는 부분. 이슈별 PR로 구현(각 PR = 이슈 1개).
- **#18 actor.py** (머지됨): Actor/HttpActor/BrowserActor/make_actor. send(prompt)->response. **actor_type은 config 안**으로 분기(DB 컬럼 없음=스키마 정합). HttpActor=429/5xx 백오프. BrowserActor=Playwright(구현만, 시연은 http).
- **#21 config연동+더미앱** (PR 열림·머지 보류): target.config→make_actor→실제 발사 관통. 취약 더미앱(`app/api/dummy.py` AcmeBank 카나리 FLAG) 이식. `scripts/smoke_actor.py` PASS(약한=거절/강한=FLAG유출).
- **#22 auth** (PR 열림·머지 보류): `auth_provider.py` TokenProvider 6모드(bearer/api_key/oauth2_client/oauth2_password/login) + 캐시/키별락/만료갱신/herd방지 + HttpActor 401 재인증. **비밀=env 참조(*_env)**. `scripts/smoke_auth.py` PASS.
- 설계 근거: `docs/액터-인증-설계.md`. 폼 스펙: `docs/actor-form-mockup.html`(FE 핸드오프).
- **컨펌 대기**: #21·#22는 팀장이 코드 리뷰 후 머지 예정(그래서 머지 보류).

## 내일 체크리스트 ★ — 액터 PR 컨펌·머지 (CodeRabbit 기반)
액터 파트 = **열린 PR 4개**(전부 스모크 PASS, 컨펌 대기). 내일: **CodeRabbit 리뷰 결과 확인 → 수정 → 컨펌 → 머지**.
- [ ] **#21** config연동+더미앱 (독립, develop base) — CodeRabbit 보고 머지
- [ ] **#26** 저장 API `POST /projects/{id}/actor` (독립, develop base) — CodeRabbit 보고 머지
- [ ] **#23** auth (TokenProvider 6모드+401재인증) — CodeRabbit 보고 머지
- [ ] **#27** session/멀티턴 — ⚠️ **#23 위에 스택**(base=feat/#22). **#23 먼저 머지 → #27 base를 develop로 retarget → 머지.**
- 머지 순서: #21·#26 아무때나 / #23 먼저 → #27. 규칙: 브랜치·이슈 삭제 금지(Closes로 닫히는 건 OK).
- 참고: 새로 만든 스모크(`scripts/smoke_actor·auth·save_actor·session.py`)는 컨테이너서 `PYTHONPATH=/app`로 실행. dev용 docker-compose 볼륨마운트+--reload는 #18에 포함.
- 체크사항(달라진 것): actor_type=config 안 / 비밀=env(*_env) / 저장API 소유권검증은 get_current_user(팀원 JWT 미구현이라 501 의존, 완성되면 동작) / #27은 stacked PR.

## 내일(다음 세션) 시작점 ★ — 스캔 파트
1. **액터 PR 컨펌**: #21·#22 코드 리뷰 → 머지.
2. **스캔 파트 구현** (POST /scans 이후 = 사용자 담당):
   - **정찰(정적분석)**: 스캔 step① 리포 AST 분석 → 프로파일(model·system_prompt·defences·tools·rag) 추출 → 씨앗 필터. (`app/recon.py`, PoC ast_scanner 참고)
   - **진화 파이프라인**: `orchestrator.run_evolution` 배선(retrieve→select→mutate→actor.send→judge→update→publish) + `tasks.run_scan`.
   - **SSE + 로그**: `GET /scans/{id}/stream` 실시간(log/progress/finding/done 이벤트) + scan_events 재생.
   - **실제 API 붙여 공격**: 액터로 더미앱(또는 실표적) 실발사 → judge 3계층 판정 → findings 저장.
   - API명세 §4·§5 반영. `scans.config`의 auth_context(역할별)·safe_mode(드라이런) 배선.
- (별개) **벡터DB 실제 적재**: `docs/벡터DB-적재계획.md` — retrieve 씨앗검색의 전제(진화 전에/병행).

## 메모: 시연용 취약 표적 후보 (나중에 결정)
액터는 config(url·body·response_path) 기반이라 표적 무관 → 시연 때 붙일 후보만 메모:
- **우리 더미앱**(`app/api/dummy.py`, AcmeBank 카나리 FLAG): 결정론적·오프라인·CI/데모 앵커.
- **DVLA** (github.com/ReversecLabs/damn-vulnerable-llm-agent): ReAct 에이전트, 도구오용 시나리오. Streamlit 8501 → 브라우저액터/shim 필요.
- **DVAA** (github.com/opena2a-org/damn-vulnerable-ai-agent): "AI판 DVWA", Docker 9000 API.
- **greshake/llm-security**: 간접 프롬프트 인젝션 예제(RAG 시나리오 근거).
- 방향: 데모 앵커=더미앱, 현실 쇼케이스=DVLA/DVAA(URL만 교체). **실제 채택은 시연 준비 때 결정.**

## 현재 상태 한 줄
문서·설계·ERD·기능명세·아키텍처 **최신 확정** + **벡터DB 소스조사·계획 완료**. `app/`은 **돌아가는 PoC(옛 11테이블 스펙)** — 오늘 정규화·플로우 미반영. 다음 = 디자인 → **벡터DB 실제 적재** → 개발세팅 → A. models 리팩터.
