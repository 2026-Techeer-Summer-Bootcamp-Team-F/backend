# AI 레드팀 도구 — API 명세서

> ## ⚠️ 이 문서는 **옛 버전** 입니다 — 최신은 [API-명세.md](./API-명세.md)
> ERD 최종본 반영으로 아래가 바뀜(이 문서 대신 최신본 참고):
> - `targets` → **`projects`**(엔드포인트) / 필드 `name`→`project_name`
> - **`/targets/{id}/verify` 삭제** (소유확인 컬럼 삭제 — GitHub 로그인으로 갈음)
> - `avatar_url` 삭제, `seed_case_id`→`attack_id`
> - `GET /github/repos`·`GET /attack-types` 신설, 스캔 config에 `attack_types`/`target_model`
>
> 아래는 히스토리 참고용.

> FastAPI 백엔드(`app/backend`)의 REST API. 실제 라우트와 경로가 일치한다.
> - Base URL(PoC): `http://localhost:8000`
> - 인증: GitHub OAuth → JWT(Bearer). 보호 엔드포인트는 `Authorization: Bearer <token>` 필요.
> - 공통 에러: `{ "detail": "<message>" }`, 상태코드 400/401/403/404/409/422/500.
> - **PoC 모드**: `AUTH_MODE=mock` 이면 실제 GitHub 없이 `POST /auth/dev-login` 으로 토큰 발급(데모용).

---

## 0. 인증 플로우 (전체 그림)

```
[프론트] "GitHub로 로그인" 클릭
   → GET  /auth/github/login           → 302 GitHub 인가 페이지로 redirect
   ← GitHub 콜백
   → GET  /auth/github/callback?code=  → 유저 upsert + JWT 발급 → 프론트로 redirect(#token=)
   → GET  /auth/me  (Bearer)           → 로그인 사용자 정보
[PoC/데모] POST /auth/dev-login {login} → JWT 발급 (AUTH_MODE=mock 일 때만)
```

---

## 1. Auth

### `GET /auth/github/login`
GitHub OAuth 인가 시작. `state` CSRF 토큰 세팅 후 GitHub authorize URL로 302 redirect.
- 200 (JSON 모드): `{ "authorize_url": "https://github.com/login/oauth/authorize?..." }`

### `GET /auth/github/callback`
| 쿼리 | 타입 | 설명 |
|---|---|---|
| code | string | GitHub 인가 코드 |
| state | string | CSRF 검증 |

- 처리: code→access_token 교환 → GitHub `/user` 조회 → `users` upsert → JWT 발급.
- 200: `{ "access_token": "<jwt>", "token_type": "bearer", "user": {User} }`
- 401: 코드/state 무효.

### `POST /auth/dev-login`  *(PoC 전용, `AUTH_MODE=mock`)*
실제 GitHub 없이 데모 로그인.
- 요청: `{ "login": "demo-user", "name": "Demo" }`
- 200: `{ "access_token": "<jwt>", "token_type": "bearer", "user": {User} }`
- 403: `AUTH_MODE != mock` 이면 비활성.

### `GET /auth/me`  🔒
- 200: `User` — `{ id, github_login, name, avatar_url, created_at }`
- 401: 토큰 없음/만료.

---

## 2. Targets (대상 앱)

### `POST /targets`  🔒
대상 등록.
- 요청:
```json
{
  "name": "AcmeBank 챗봇",
  "actor_type": "http",
  "config": {
    "url": "http://localhost:8000/dummy/acmebank/chat",
    "method": "POST",
    "headers": {"Content-Type": "application/json"},
    "body_template": "{\"message\": \"{{prompt}}\"}",
    "response_path": "reply",
    "delay": 0,
    "max_retries": 4
  },
  "model_hint": "gpt-4o-mini",
  "purpose": "고객지원 챗봇",
  "system_prompt": null,
  "repo_url": "https://github.com/acme/bank-bot"
}
```
- 201: `Target` (ownership_verified=false, verify_token 발급 포함)
- 422: 필수 필드 누락.

### `GET /targets`  🔒
- 200: `[Target, ...]` (본인 소유만)

### `GET /targets/{id}`  🔒
- 200: `Target` / 403: 타인 소유 / 404: 없음

### `POST /targets/{id}/verify`  🔒
대상 **소유/권한 확인**. (기획 §5.1 인가)
- 요청: `{ "method": "dns_txt" | "meta_tag" | "repo_file" | "manual" }`
- 처리: verify_token 을 대상 도메인 DNS TXT / meta 태그 / 리포 파일에서 확인.
  - PoC(`AUTH_MODE=mock` 또는 더미앱 대상): `manual` 즉시 통과.
- 200: `{ "ownership_verified": true, "method": "manual" }`
- 409: 확인 실패(토큰 불일치).

### `POST /targets/{id}/recon`  🔒
정찰 실행(등록입력 + 리포분석 + 블랙박스 프로빙). 프로파일 반환.
- 200: `{ "model": "...", "purpose": "...", "defenses": ["moderation"], "tools": [], "rag_sources": [], "source": "repo|probe|input" }`

### `DELETE /targets/{id}`  🔒 → 204

---

## 3. Scans (스캔)

### `POST /scans`  🔒
스캔 트리거(백그라운드 실행). `ownership_verified=true` 필수.
- 요청:
```json
{
  "target_id": 1,
  "config": {
    "objectives": ["AML.T0051.000", "AML.T0054", "AML.T0057"],
    "population_size": 8,
    "max_generations": 5,
    "model": "haiku"
  }
}
```
- 202: `{ "scan_id": 12, "status": "pending" }` (즉시 반환, 워커가 백그라운드 실행)
- 403: `ownership_verified=false` → `{"detail": "대상 소유 확인 필요"}`

### `GET /scans`  🔒 → `[Scan, ...]`

### `GET /scans/{id}`  🔒
- 200: `Scan` + `{ objectives: [Objective], progress: {...} }`

### `GET /scans/{id}/stream?token=<jwt>`  🔒  *(SSE)*
스캔 실시간 진행. `text/event-stream`. 브라우저 `EventSource`는 Authorization 헤더를
못 실으므로 **JWT를 `?token=` 쿼리로** 전달(SSE 표준 패턴). 미제공 시 401.
```
event: progress
data: {"generation":2,"evaluated":14,"best_score":0.7,"phase":"mutate"}

event: attempt
data: {"objective_id":3,"generation":2,"verdict":"safe","score":0.4,"prompt":"...","parent_attempt_id":7}

event: finding
data: {"objective_id":3,"atlas":"AML.T0057","severity":"high","canary":"FLAG..."}

event: done
data: {"status":"done","breached":2,"total_objectives":3}
```

### `POST /scans/{id}/cancel`  🔒 → `{ "status": "failed", "stop_reason": "cancelled" }`

---

## 4. Results / Dashboard

### `GET /scans/{id}/findings`  🔒
- 200: `[Finding, ...]` — `{ id, atlas_technique_id, severity, title, evidence, mitigation }`

### `GET /scans/{id}/heatmap`  🔒
ATLAS 커버리지 히트맵(정적 매핑 기반).
- 200:
```json
{
  "techniques": [
    {"atlas_technique_id":"AML.T0051.000","name":"Direct Prompt Injection","status":"breached","attempts":9,"best_score":0.95},
    {"atlas_technique_id":"AML.T0054","name":"LLM Jailbreak","status":"safe","attempts":12,"best_score":0.42}
  ]
}
```

### `GET /objectives/{id}/tree`  🔒
진화 트리(재귀 계보).
- 200:
```json
{
  "objective_id": 3,
  "nodes": [
    {"id":7,"parent_attempt_id":null,"generation":0,"score":0.4,"verdict":"safe","mutation_op":"none","prompt":"...","seed_case_id":102},
    {"id":9,"parent_attempt_id":7,"generation":1,"score":0.95,"verdict":"breach","mutation_op":"rephrase","improvement":"관리자 프레이밍 강화","prompt":"..."}
  ]
}
```

### `GET /attempts/{id}`  🔒 → `Attempt`(전체 상세: prompt/response/judge_detail)

### `GET /scans/{id}/report`  🔒
스캔 통계 요약(대시보드용). 없으면 즉석 생성.
- 200: `{ scan_id, total_objectives, breached_count, coverage_pct, severity_counts:{critical,high,..}, risk_score, generated_at }`

### `GET /scans/{id}/events`  🔒
스캔 타임라인/감사 로그(영속화된 이벤트).
- 200: `[{ id, scan_id, objective_id, event_type: progress|attempt|finding|done, payload, created_at }]`

### `GET /scans/{id}/recon`  🔒
정찰 프로파일(씨앗 필터 근거).
- 200: `[{ model, purpose, defenses[], tools[], rag_sources[], source }]`

### `GET /atlas`  🔒
ATLAS 기법 마스터(정적 매핑 테이블).
- 200: `[{ id, name, tactic, category, description, mitigation }]`

---

## 5. Attack Corpus (씨앗 코퍼스)

### `GET /corpus/stats`  🔒
- 200: `{ "total": 1405, "by_type": {"jailbreak": 900, ...}, "verified": 210, "sources": ["jailbreak_llms","L1B3RT4S"] }`

### `GET /corpus/search`  🔒
- 쿼리: `?attack_type=jailbreak&atlas=AML.T0054&verified=true&limit=20`
- 200: `[AttackCase, ...]` (embedding 필드는 제외/축약)

---

## 6. Dummy Target (취약 더미앱 — 데모 대상)

> self-testing 데모용. 우리가 띄운 격리 대상. 시스템프롬프트에 카나리(FLAG) 은닉.

### `POST /dummy/acmebank/chat`  *(인증 불필요, 격리 데모)*
- 요청: `{ "message": "<사용자/공격 프롬프트>" }`
- 200: `{ "reply": "<챗봇 응답>" }`
- 취약점: 특정 프롬프트 인젝션/롤플레이에 카나리 `FLAG{...}` 유출 → 스캔이 이걸 탐지.

---

## 7. Health

### `GET /health` → `{ "status": "ok", "auth_mode": "mock", "db": "sqlite" }`

---

## 8. 상태코드 규약
| 코드 | 의미 |
|---|---|
| 200 | 조회/처리 성공 |
| 201 | 리소스 생성 |
| 202 | 비동기 작업 수락(스캔 트리거) |
| 204 | 삭제 성공(본문 없음) |
| 401 | 미인증(토큰 없음/만료) |
| 403 | 권한 없음(타인 리소스 / 소유 미확인) |
| 404 | 리소스 없음 |
| 409 | 상태 충돌(소유 확인 실패 등) |
| 422 | 요청 검증 실패(FastAPI 기본) |

---

> 관련: [ARCHITECTURE.md](./ARCHITECTURE.md) · [ERD.md](./ERD.md) · `../app/backend/app/routers/`
