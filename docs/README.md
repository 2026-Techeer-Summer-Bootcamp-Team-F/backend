# 📁 기획 — AI 레드팀 (차례)

> 이 폴더 = **모든 기획·설계·스펙 + PoC 통합**. 아래 순서대로 읽으면 됨. (실제 구현 코드는 `../app/`)

---

## 1. 비전·기획 (무엇을·왜)
1. [기획.md](기획.md) — **통합 기획서** (정의·차별점·파이프라인·상세설계·비용·우선순위). ⭐먼저 읽기.
2. [아키텍처-기술스택.md](아키텍처-기술스택.md) — 확정 스택과 이유.
3. [오픈소스-분석.md](오픈소스-분석.md) — 참조 OSS(promptfoo/PyRIT/garak/GPTFuzzer/AutoDAN) 차용 설계.
4. [docs/진화엔진-정리.md](docs/진화엔진-정리.md) — 진화 엔진 출처·파이프라인·AI 사용 3자리·자기학습 코퍼스.
5. [AI레드팀-PoC-발표.md](AI레드팀-PoC-발표.md) — 발표 자료.
5-1. [poc/](poc/) — **PoC 코드·실데이터** (poc1 데이터적재·poc2 공격생성·poc3 파이프라인·static_scan AST). 실데이터: `jailbreak_prompts.csv`(1,405)·`ATLAS.yaml`·`l1b3rt4s/`. ⚠️백엔드 `corpus.py`가 이 CSV를 읽음(경로 의존).

## 2. 스펙 (어떻게 — ERD·API·디자인)
6. [docs/ERD-완전정리.md](docs/ERD-완전정리.md) — **ERD 최종본**(10테이블, 컬럼·예시·기능). 이미지 → [docs/assets/airedteam-erd.png](docs/assets/airedteam-erd.png).
7. [docs/API-명세.md](docs/API-명세.md) — **API 31개 명세**(화면↔API 매핑). 노션 "💽 API 명세" DB와 동기화.
8. [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — 시스템 구성·데이터 흐름. **다이어그램** → [docs/assets/시스템아키텍처.png](docs/assets/시스템아키텍처.png) (Vercel 프론트 + AWS EC2/Docker[Nginx·FastAPI·Redis·Celery·모니터링] + RDS pgvector + Claude API).
9. [docs/DESIGN-REF.md](docs/DESIGN-REF.md) — 디자인 방향·마스코트·색상. 와이어프레임 → [docs/assets/wireframe.png](docs/assets/wireframe.png).
10. [docs/액터-인증-설계.md](docs/액터-인증-설계.md) — 액터 토큰 자동발급/갱신 설계(후순위).
10-1. [docs/정찰-액터자동구성-설계.md](docs/정찰-액터자동구성-설계.md) — 레포 코드/네트워크에서 액터 config 자동 추출 설계(후순위).
10-2. [docs/공격시나리오-설계.md](docs/공격시나리오-설계.md) — **대상 상태·컨텍스트별 공격 시나리오**(로그인/비로그인·역할·앱종류·방어·부작용) + 우선순위·설계 반영점. (멘토 피드백 반영)
11. 생성물: [docs/schema.sql](docs/schema.sql) · [docs/erd.dbml](docs/erd.dbml) (models.py에서 `gen_erd.py`로 생성).

## 3. 결정·운영 (진행 관리)
12. [docs/결정로그-2026-07-07.md](docs/결정로그-2026-07-07.md) — ERD 정규화·API 수정 등 **결정 기록**(최신).
13. [NEXT.md](NEXT.md) — **다음에 할 일** (세션 시작 시 여기부터).
14. [트러블슈팅.md](트러블슈팅.md) — 문제→원인→해결 기록 (작업 끝날 때마다 갱신).

## 4. 옛 문서 (참고용, 지우지 않음)
- deprecated(최신본으로 대체됨): [docs/ERD.md](docs/ERD.md) · [docs/ERD-가이드.md](docs/ERD-가이드.md) · [docs/API.md](docs/API.md)
- [_archive/](_archive/) — 초기 기획(PLANNING·기획서·AI레드팀-기획 + 옛 docs). 방향 참고용.

---

## 폴더 지도 (프로젝트 전체)
```
ai-redteam/
├─ 기획/            ← 이 폴더: 모든 기획·설계·스펙 + PoC
│  ├─ README.md      (이 차례)
│  ├─ 기획.md / 아키텍처-기술스택.md / 오픈소스-분석.md / AI레드팀-PoC-발표.md
│  ├─ NEXT.md / 트러블슈팅.md
│  ├─ docs/          (ERD·API·디자인 스펙 + assets + 설계문서 + 결정로그)
│  ├─ poc/           (PoC 코드·실데이터 — corpus.py가 여기 CSV 읽음)
│  └─ _archive/      (옛 기획)
├─ app/             ← 실제 구현 (backend FastAPI + frontend React) + progress.txt
└─ docker-compose.yml
```

> 갱신: 2026-07-07 (기획 문서 `기획/`로 통합, poc를 `기획/poc/`로 이동, slides 삭제).
