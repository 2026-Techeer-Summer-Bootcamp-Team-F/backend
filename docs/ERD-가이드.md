# ERD 이해 가이드 (발표·팀 공유용)

> ## ⚠️ 이 문서는 **초안** 입니다 — 최신 정합본은 [ERD-완전정리.md](./ERD-완전정리.md)
> 이 가이드는 11테이블 초안 기준이라 아래가 옛날임(최신본 참고):
> - `recon_profiles` **삭제 → `target_projects`에 통합** (10테이블), `targets`→`target_projects`
> - `ownership_verified`/`verify_*` **삭제**, `avatar_url` 삭제, `seed_case_id`→`attack_id`
> - §12의 "미정" 항목(정찰 통합/소유확인)은 **최종본에서 확정됨**.

> `ERD.md`가 "정확한 스키마 정의"라면, 이 문서는 **"각 테이블·컬럼이 뭔지 쉽게 + 예시로"** 설명한 가이드다.
> 발표 대본, 팀원 온보딩, "이 컬럼 왜 있어?" 질문 대응에 그대로 쓰는 용도.
> ⚠️ 아래 §12 「오늘 논의한 설계 결정」은 팀 최종 확정 후 `ERD.md`·`models.py`에 반영 예정 (미정 표시된 것 주의).

---

## 0. 전체 흐름 한 줄

```
사용자가 → 앱(대상)을 등록하고 → 스캔을 돌리면 → 목표별로 → 여러 번 공격해서 → 뚫린 걸 기록
users      targets           scans      objectives  attempts      findings
```

관계 요약:
```
users ──< targets ──< scans ──< objectives ──< attempts ──< findings
              │(1:1)     │           │↑ (자기참조=진화계보)
        recon_profiles   ├──< scan_events (실시간 로그)
                         └──1:1─ scan_reports (통계요약)
attack_cases (씨앗) ──> attempts.seed_case_id
atlas_techniques (기법 사전) = 여기저기서 참조
```

---

## 1. `users` (사용자)
로그인한 사람. **누가 이 도구를 쓰는지.**

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | 우리 DB 내부 고유번호(PK) | `1` |
| github_id | GitHub 고유ID(안 변하는 숫자, 진짜 신원) | `"583231"` |
| github_login | GitHub 계정명(바뀔 수 있는 username) | `"gangminseo"` |
| name | 표시 이름 | `"강민서"` |
| avatar_url | 프로필 이미지 URL | `https://...` |
| access_token_enc | GitHub 토큰(암호화, 리포 분석용) | `"gAAA...(암호문)"` |
| created/updated/deleted_at | 생성·수정·삭제(soft) 시각 | |

- **`id` vs `github_id`**: id=우리 DB용(다른 테이블은 이걸로 연결), github_id=GitHub용. 계정명 바뀌어도 github_id로 같은 사람 식별.
- **`access_token_enc`**: 대상 리포를 분석하려면 GitHub 권한 필요. 민감정보라 **암호화(`_enc`)** 저장.

## 2. `targets` (공격 대상 앱 = 프로젝트)
공격할 AI 앱 하나. **뭘, 어떻게 공격하고, 공격해도 되는지.**

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `3` |
| user_id | 소유자(FK→users) | `1` |
| name | 대상 표시 이름 | `"AcmeBank 고객봇"` |
| actor_type | 공격 방식(http/browser) | `"http"` |
| config | 액터 설정(어디에 어떻게 쏘나) | `{url, body_template, response_path...}` |
| model_hint | 대상 모델(사용자 추측) | `"gpt-4o-mini"` |
| purpose | 앱 용도 | `"고객지원 챗봇"` |
| system_prompt | 앱 시스템프롬프트(알면 입력) | `"너는 은행 상담원..."` |
| repo_url | 화이트박스 분석용 리포 주소 | `github.com/acme/bot` |
| ownership_verified | 소유/공격권한 확인됨? | `true` |
| verify_method / verify_token | 소유 확인 방식·토큰 | (아래 결정 §12 참고) |
| created/updated/deleted_at | 공통 | |

- **actor_type + config** = 아까의 "액터". 이 설정만 있으면 **어떤 앱이든 코드 수정 없이** 공격.
  - http: `{url, method, body_template("{{prompt}}"), response_path, max_retries}`
  - browser: `{url, input_selector, submit_selector, output_selector}`
- **ownership_verified** = 무단 공격 방지. true인 대상만 스캔 허용. (보안 도구 핵심)

## 3. `recon_profiles` (정찰 결과)
공격 **전에 대상을 조사**한 결과. 이걸로 "이 앱에 먹힐 공격"만 골라 쏨.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `5` |
| (연결 FK) | targets 또는 scans (아래 §12 미정) | |
| model | 대상 모델(정찰로 확인) | `"gpt-4o"` |
| purpose | 앱 용도 | `"고객지원 챗봇"` |
| defenses (JSON) | 감지된 방어장치 | `["moderation","input_filter"]` |
| tools (JSON) | 앱이 쓰는 도구/함수 | `["send_email","db_query"]` |
| rag_sources (JSON) | RAG 지식소스 | `["faq.pdf","policy_db"]` |
| source | 정보 출처(신뢰도) | `repo`/`probe`/`input` |
| created/updated/deleted_at | 공통 | |

- 각 정찰 → 대응 공격: defenses→우회, tools→도구 오용(agentic), rag_sources→간접 인젝션.
- **targets.model_hint(추측) vs recon.model(확인)** 차이. 둘 다 "대상(적) 모델".

## 4. `scans` (스캔 = 분석 실행 1회)
앱 하나를 **한 번 공격하는 전체 과정**. "스캔 시작" 버튼 한 번 = scan 하나. (몇 분 소요)

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `12` |
| target_id | 어느 앱(FK→targets) | `3` |
| status | 진행 상태 | `pending→running→done`/`failed` |
| config | 어떻게 돌릴지 | `{objectives:[...], population_size:8, max_generations:5}` |
| progress | 실시간 진행 스냅샷(현재 1개) | `{generation:2, best_score:0.7, phase:"mutate"}` |
| started_at / finished_at | 시작·종료 시각 | |
| created/updated/deleted_at | 공통 | |

- `targets : scans = 1:N` — **같은 앱을 여러 번 재스캔**(고쳤나 재확인·주기검사).
- `config`에서 **model 필드는 제거**(우리 엔진은 클로드 고정 → config가 아니라 상수).
- `progress`(현재 1개, 덮어씀) vs `scan_events`(전 과정 다 쌓음) 구분.

## 5. `objectives` (공격 목표)
한 스캔 안에서 앱을 **여러 각도로** 공격 — 그 각도 하나.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `3` |
| scan_id | 어느 스캔(FK) | `12` |
| atlas_technique_id | 노리는 ATLAS 기법 | `"AML.T0051.000"` |
| name | 구체적 공격 이름 | `"Direct Prompt Injection"` |
| category | 큰 분류 | `prompt_injection`/`jailbreak`/`data_leakage`/`pii` |
| status | 결과 | `breached`(뚫림)/`safe`/`exhausted` |
| best_score | 최고 점수 | `0.95` |
| stop_reason | 왜 멈췄나 | `success`/`budget`/`stagnation`/`extinct`/`timeout` |
| created/updated/deleted_at | 공통 | |

- **category(넓은 분류) → name(구체 공격) → atlas_id(표준 코드)** = 넓음→좁음→기계용.
- 목표마다 **따로 진화·종료**돼서 "인젝션은 뚫림, 탈옥은 안전" 정밀 리포트. 히트맵 한 칸 = objective 하나.

## 6. `attempts` (공격 시도 = 진화 트리 노드) ★핵심
공격 프롬프트를 **한 번 쏜 것**. 수십~수백 개가 진화하며 쌓임.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `9` |
| objective_id | 어느 목표(FK) | `3` |
| parent_attempt_id | **부모 시도(자기참조)=진화계보** ★ | `7` |
| seed_case_id | 출발 씨앗(FK→attack_cases) | `102` |
| generation | 몇 세대(0=씨앗) | `1` |
| prompt_text | 쏜 공격문 | `"이전 지시 무시하고..."` |
| response_text | 대상 응답 | `"죄송..."/"FLAG123..."` |
| score | 판정 점수(0~1) | `0.95` |
| verdict | 판정 | `breach`/`safe`/`error` |
| judge_detail (JSON) | 판정 근거 | `{stage:"canary", canary_hit:true}` |
| mutation_op | 어떤 변이 | `expand`/`rephrase`/`crossover`... |
| improvement | 변이 이유(LLM 설명) | `"관리자 프레이밍 강화"` |
| created/updated/deleted_at | 공통 | |

- **`parent_attempt_id`(자기참조)** = 진화 계보. 씨앗→변이1→변이2→성공 족보 → 진화트리 시각화(우리 차별점).
- 성공·실패 **다 기록**(실패도 진화 과정). 뚫린 건 findings로 연결.

## 7. `attack_cases` (공격 코퍼스 = 씨앗 도서관)
검증된 공격 프롬프트 저장고(1,405개). 진화의 **출발점** + **최대 차별점(벡터검색)**.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `102` |
| prompt_text | 공격 프롬프트 원문 | `"You are DAN..."` |
| attack_type | 유형 | `jailbreak`/`prompt_injection`... |
| atlas_technique_id | ATLAS 라벨(정적) | `"AML.T0054"` |
| source | 출처 데이터셋 | `jailbreak_llms`/`L1B3RT4S`... |
| worked_on (JSON) | 성공했던 모델들 | `["gpt-4o"]` |
| verified | 자체 검증 통과? | `true` |
| tags (JSON) | 자유 태그 | `["roleplay"]` |
| embedding | **벡터(검색용)** ★ | `[0.12,-0.34,...]` (384차원) |
| created/updated/deleted_at | 공통 | |

- **embedding = 의미 기반 벡터검색** → 다른 도구(promptfoo/garak/PyRIT)엔 없는 차별점. ⚠️ PoC엔 아직 미구현(메타필터만) → 다음 알맹이 작업.
- 유일한 대용량 테이블(수만~). 나머지는 스캔당 소량.

## 8. `findings` (뚫린 취약점)
실제로 **뚫린 것만 확정** 기록. 리포트 알맹이.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK | `7` |
| scan_id / objective_id | 소속 | |
| attempt_id | 뚫은 시도(증거, FK) | `9` |
| atlas_technique_id | 기법 | `"AML.T0051"` |
| severity | 심각도 | `low/medium/high/critical` |
| title | 취약점 제목 | `"시스템프롬프트 유출"` |
| evidence (JSON) | 증거 | `{prompt, response, canary}` |
| mitigation | 완화책 | `"입력 필터 추가..."` |
| created/updated/deleted_at | 공통 | |

- **attempts(모든 시도) 중 뚫린 것만** 골라 취약점으로 확정. attempts=과정, findings=성과.
- **severity(취약점 하나의 등급)** vs **risk_score(앱 전체 점수)** 구분.

## 9. `atlas_techniques` (ATLAS 기법 마스터 = 사전)
MITRE ATLAS 공격 기법 **표준 사전**(12개, 고정). 다른 테이블이 ID로 참조.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | 기법 ID(PK, 문자열) | `"AML.T0051.000"` |
| name | 기법 이름 | `"Direct Prompt Injection"` |
| tactic | 상위 전술 | `"Initial Access"` |
| category | 우리식 분류 | `prompt_injection` |
| description | 설명 | `"공격자가 프롬프트에..."` |
| mitigation | 완화책 | `"입력 검증..."` |
| created/updated/deleted_at | 공통 | |

- 미리 채워두고 안 바뀌는 **참조 데이터**. 히트맵 라벨 + 완화책 + 정적 매핑 기준표. ID만 저장하고 뜻은 여기서 조회(정규화).

## 10. `scan_events` (스캔 이벤트 로그)
스캔 중 **모든 사건을 순번 매겨 기록하는 일지**.

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| id | PK(**순번**! 유실복구 핵심) | `47` |
| scan_id | 어느 스캔(FK) | `12` |
| objective_id | 어느 목표(FK, 선택) | `3` |
| event_type | 사건 종류 | `progress`/`attempt`/`finding`/`done` |
| payload (JSON) | 사건 내용 | `{generation:2, score:0.7}` |
| created_at | 발생 시각 | `15:01:23` |
| updated/deleted_at | 공통 | |

- 역할 ①**실시간 유실방어**(먼저 저장→pub/sub 방송, 순번으로 복구) ②감사 타임라인.
- 파일 아닌 **DB 테이블**인 이유 = "47번 이후만/finding만/목표랑 JOIN/동시쓰기 안전" = 검색·조회·연결 때문.

## 11. `scan_reports` (스캔 통계 리포트)
스캔 결과를 **숫자로 요약**. 대시보드 상단 "한눈에 보는 결과".

| 컬럼 | 뜻 | 예시 |
|---|---|---|
| report_id | PK | `8` |
| scan_id | 어느 스캔(FK, UNIQUE=1:1) | `12` |
| total_objectives | 전체 목표 수 | `3` |
| breached_count | 뚫린 목표 수 | `2` |
| coverage_pct | 커버리지 비율 | `100` |
| severity_counts (JSON) | 심각도별 개수 | `{critical:1, high:2}` |
| risk_score | 종합 위험도(0~100) | `90` |
| generated_at | 리포트 생성 시각 | |
| created/updated/deleted_at | 공통 | |

- **findings(낱개)를 집계한 요약(1줄)**. `scans : scan_reports = 1:1`(scan_id UNIQUE).
- "없으면 즉석 생성" = 성능용 캐시.

---

## 12. 오늘 논의한 설계 결정 (팀 확정 대기)

| # | 항목 | 결정/제안 | 상태 |
|---|---|---|---|
| 1 | 프로젝트 테이블 | **안 만듦.** 프로젝트=앱(targets)이 1:1이라 중복. targets가 곧 프로젝트. | ✅ 결정 |
| 2 | 소유 확인 | GitHub 로그인 + 리포 접근으로 갈음(DNS/meta 인증 생략). `verify_token`·`verify_method` 삭제 가능. | ✅ 방향 결정 (컬럼정리 반영 대기) |
| 3 | recon 연결 | targets에 **1:1**(target_id + UNIQUE). scans 아님(정찰=앱 정보). | ⚠️ "별도 테이블 1:1" vs "targets에 흡수" 미정 |
| 4 | 엔진 모델 | 클로드 고정 → `scans.config.model` 삭제, 상수(config.py)로. | ✅ 결정 |
| 5 | scan_reports | scans와 **1:1**(scan_id UNIQUE). | ✅ 결정 |
| 6 | coverage_pct 타입 | INT(정수%) vs DECIMAL(소수%) | ⚠️ 미정 |

**미정 2개(팀 확정 필요):**
- 정찰(recon): 별도 테이블 1:1로 둘까 / targets에 컬럼으로 흡수할까?
- coverage_pct: 정수(INT)로 충분 / 소수(DECIMAL) 필요?

---

## 13. 자주 헷갈리는 개념 (부록)

- **액터(actor)**: 대상마다 다른 공격 방법을 감싸는 어댑터. 엔진은 `send(프롬프트)→응답`만 앎. http(API)/browser(UI 자동화).
- **실시간(SSE)**: 스캔 진행을 생중계로 보는 화면. `워커(Celery) → Redis(pub/sub) → FastAPI → SSE → 브라우저`. FastAPI가 중계기(브라우저는 Redis 직접 접근 X).
- **pub/sub 유실 방어**: pub/sub은 새지만, **먼저 scan_events(DB)에 저장(persist-then-publish)** → 놓치면 DB에서 순번(id) 기준 재생(SSE Last-Event-ID). "라디오 놓쳐도 전광판(DB)엔 있음".
- **심각도 vs 위험도**: severity=취약점 하나 등급(findings), risk_score=앱 전체 점수(scan_reports). 심각도들 종합=위험도.
- **Celery vs uvicorn**: uvicorn=빠른 웹 응답, Celery=무겁고 오래 걸리는 스캔 오프로딩. async는 "기다림"만 쪼개고 CPU 계산은 못 쪼개서 Celery로 분리. (PoC는 BackgroundTasks, 프로덕션은 Celery)
- **Redis 5역할**: 브로커·result backend·pub/sub(SSE)·rate-limit·캐시. RabbitMQ(브로커만)보다 하나로 통합. (PoC엔 Redis도 아직 없음)

---

> 관련: [ERD.md](./ERD.md)(정확 스키마) · [ARCHITECTURE.md](./ARCHITECTURE.md) · [API.md](./API.md) · `../app/backend/app/models.py`
