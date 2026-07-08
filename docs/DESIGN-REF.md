# AI 레드팀 도구 — 디자인 참고 (Figma)

> 팀 Figma 와이어프레임 + 마스코트 결정을 기록. 프론트 개선 시 이 문서를 기준으로.

## Figma 파일
- **URL**: https://www.figma.com/design/117A3LStS4zttMU5Lai8Fn/%EC%A0%9C%EB%AA%A9-%EC%97%86%EC%9D%8C?node-id=11-2
- 페이지: **"AI Read Team"** (Page 1 하위)
- 접근: 팀 계정 로그인 필요(무료 플랜). 확인일 2026-07-05.
- **저장된 와이어프레임 이미지**: [`assets/wireframe.png`](./assets/wireframe.png) (2026-07-06 Figma export 저장)

## 전체 무드 (확정 방향)
**다크 테마 + 레드/코랄 포인트**의 "보안 회사 같은 프로" 느낌.
- 레퍼런스: **SK쉴더스**("안녕을 지키는 기술 / Total Security Innovator") 랜딩 + **Vercel**의 깔끔한 컴포넌트 + **OpenClaw** 로그인.

## 마스코트 (확정)
- **너구리 해커** — 다크 후드 입고 **노트북(초록 터미널 화면)** 든 픽셀아트 스타일.
- 생성 방식: **Claude 디자인으로 뽑을 예정** (Nano Banana 등 후보였으나 너구리+Claude로 확정).
- 지금 코드엔 임시로 빨간 블롭(`src/components/Mascot.tsx`) → 너구리 이미지 나오면 교체.

## 화면 흐름 (와이어프레임 — `assets/wireframe.png`)
1. **랜딩** — 다크 히어로("안녕을 지키는 기술 / Total Security Innovator·SK쉴더스") + 상단 nav(로고/분석/결과/로그인) + "테스트 해보기"(레드 CTA) + MDR 2개월 무료 카드 + 하단 보안뉴스 카드 3개(BAS Attack Validation / Ransomware / Apache HTTP/2 DoS CVE-2026-49075). *주석: 분석/결과는 비로그인 시 로그인창으로, 뉴스는 부가기능.*
2. **로그인** — 화이트 카드 + "로그인하기"(레드) + **GitHub**(주 — "깃허브 로그인 정도만") + Google(옵션). (다크 버전도 존재)
3. **Import Git Repository** — **Vercel 스타일**: 검색 + 리포 목록(webprogramming_project / daily_algorithm / Linux_project56) + 각 **Import 버튼** = 대상 등록(`target_projects.repo_url`).
4. **동의 페이지 + 액터 구성 정보 입력** — 동의 후 액터(URL/모델 등) 설정 폼.
5. **AI Red Teaming Analysis** (핵심 실행 화면) — 좌: **Attack Type 체크박스 13개**(Direct/Indirect Prompt Injection, Jailbreak, System Prompt Extraction, Prompt/Data/PII Leakage, Tool/Function Abuse, Tool Manipulation, Side-play/Persona, Encoding&Obfuscation, Hallucination, DoS) / 중: **Target Model 드롭다운**(GPT-4o/Claude/Current/Local LLM) + **Start Scan** + Progress바 + Current Attack(기법·상태) + **Live Analysis Log**(실시간) / 우: **Summary**(Completed 8/13, Success 5, Failed 3, Running 1).
6. **결과 대시보드** — 상단 URL + **통계 숫자 4개**(예 68/121/41/14) + **MITRE ATLAS 히트맵**(색상 그리드) + **Top Findings** + 프로젝트 선택 대시보드.

> API 매핑은 [API-명세.md](./API-명세.md) §화면↔API 표 참고. 공격유형 13개 → `GET /attack-types`, 실시간 → SSE(log/progress/finding), 통계 → `GET /scans/{id}/report`.

## 마스코트 후보 (와이어프레임에 여러 안)
빨간 블롭(현재 코드) / **너구리 해커(후드+노트북 초록터미널)** ✅확정방향 / 로봇 마법사 / RED TEAM·SECURE AI·TEST PROTECT 3캐릭터 세트. → 너구리로 확정, Claude로 생성 예정.

## 우리 구현과의 매핑 / 남은 작업
| 와이어프레임 | 현재 코드 | 할 일 |
|---|---|---|
| 다크+레드 톤 | ✅ 적용됨 | 유지 |
| GitHub 로그인 | ✅ OAuth 있음 | Google 로그인 추가(옵션) |
| Vercel식 Import Git Repository | ⚠️ 단순 폼 | 리포 목록 선택 UI로 개선 |
| SK쉴더스식 랜딩/온보딩 | ❌ 없음(바로 로그인) | 랜딩 페이지 신설 |
| 너구리 마스코트 | 🔄 빨간 블롭 | 너구리 이미지로 교체 |

> 참고: [ARCHITECTURE.md](./ARCHITECTURE.md) · 프론트 `app/frontend/src/pages` · `app/frontend/src/components/Mascot.tsx`
