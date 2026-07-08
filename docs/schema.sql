-- AI 레드팀 도구 — 스키마 DDL (MySQL 방언, ERDCloud Import용) · 11개 테이블
-- 컬럼 COMMENT = 한글 논리명(ERDCloud가 '이름'으로 표시). 물리명은 영어.
-- 모든 테이블에 생성일시/수정일시/삭제일시(soft-delete).
-- Prod(PostgreSQL)에선 attack_cases.embedding 을 vector(384)(pgvector)로 교체.

CREATE TABLE `users` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '사용자ID',
  `github_id` VARCHAR(64) NOT NULL COMMENT '깃허브ID',
  `github_login` VARCHAR(128) NOT NULL COMMENT '깃허브로그인',
  `name` VARCHAR(128) NULL COMMENT '이름',
  `avatar_url` VARCHAR(512) NULL COMMENT '프로필이미지',
  `access_token_enc` VARCHAR(512) NULL COMMENT '액세스토큰(암호화)',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`)
) COMMENT='사용자';

CREATE TABLE `targets` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '대상ID',
  `user_id` INT NOT NULL COMMENT '사용자ID',
  `name` VARCHAR(200) NOT NULL COMMENT '대상명',
  `actor_type` VARCHAR(16) NOT NULL COMMENT '액터유형',
  `config` JSON NOT NULL COMMENT '액터설정',
  `model_hint` VARCHAR(64) NULL COMMENT '추정모델',
  `purpose` VARCHAR(256) NULL COMMENT '용도',
  `system_prompt` TEXT NULL COMMENT '시스템프롬프트',
  `repo_url` VARCHAR(512) NULL COMMENT '리포주소',
  `ownership_verified` TINYINT(1) NOT NULL COMMENT '소유확인여부',
  `verify_method` VARCHAR(32) NULL COMMENT '확인방식',
  `verify_token` VARCHAR(64) NULL COMMENT '확인토큰',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`)
) COMMENT='공격대상';

CREATE TABLE `atlas_techniques` (
  `id` VARCHAR(32) NOT NULL COMMENT '기법ID',
  `name` VARCHAR(128) NOT NULL COMMENT '기법명',
  `tactic` VARCHAR(64) NULL COMMENT '전술',
  `category` VARCHAR(32) NULL COMMENT '분류',
  `description` TEXT NULL COMMENT '설명',
  `mitigation` TEXT NULL COMMENT '완화책',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`)
) COMMENT='ATLAS기법마스터';

CREATE TABLE `scans` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '스캔ID',
  `target_id` INT NOT NULL COMMENT '대상ID',
  `status` VARCHAR(16) NOT NULL COMMENT '상태',
  `config` JSON NOT NULL COMMENT '스캔설정',
  `progress` JSON NOT NULL COMMENT '진행상황',
  `started_at` TIMESTAMP NULL COMMENT '시작일시',
  `finished_at` TIMESTAMP NULL COMMENT '종료일시',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`target_id`) REFERENCES `targets`(`id`)
) COMMENT='스캔';

CREATE TABLE `recon_profiles` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '정찰ID',
  `scan_id` INT NOT NULL COMMENT '스캔ID',
  `target_id` INT NOT NULL COMMENT '대상ID',
  `model` VARCHAR(64) NULL COMMENT '모델',
  `purpose` VARCHAR(256) NULL COMMENT '용도',
  `defenses` JSON NOT NULL COMMENT '방어수단',
  `tools` JSON NOT NULL COMMENT '도구',
  `rag_sources` JSON NOT NULL COMMENT 'RAG소스',
  `source` VARCHAR(16) NULL COMMENT '정보출처',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`),
  FOREIGN KEY (`target_id`) REFERENCES `targets`(`id`)
) COMMENT='정찰프로파일';

CREATE TABLE `objectives` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '목표ID',
  `scan_id` INT NOT NULL COMMENT '스캔ID',
  `atlas_technique_id` VARCHAR(32) NULL COMMENT '기법ID',
  `name` VARCHAR(128) NULL COMMENT '목표명',
  `category` VARCHAR(32) NULL COMMENT '분류',
  `status` VARCHAR(16) NOT NULL COMMENT '상태',
  `best_score` FLOAT NOT NULL COMMENT '최고점수',
  `stop_reason` VARCHAR(32) NULL COMMENT '종료사유',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`),
  FOREIGN KEY (`atlas_technique_id`) REFERENCES `atlas_techniques`(`id`)
) COMMENT='공격목표';

CREATE TABLE `attempts` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '시도ID',
  `objective_id` INT NOT NULL COMMENT '목표ID',
  `parent_attempt_id` INT NULL COMMENT '부모시도ID',
  `seed_case_id` INT NULL COMMENT '씨앗공격ID',
  `generation` INT NOT NULL COMMENT '세대',
  `prompt_text` TEXT NOT NULL COMMENT '공격프롬프트',
  `response_text` TEXT NULL COMMENT '대상응답',
  `score` FLOAT NOT NULL COMMENT '점수',
  `verdict` VARCHAR(16) NULL COMMENT '판정',
  `judge_detail` JSON NULL COMMENT '판정상세',
  `mutation_op` VARCHAR(32) NULL COMMENT '변이연산',
  `improvement` TEXT NULL COMMENT '개선근거',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`objective_id`) REFERENCES `objectives`(`id`),
  FOREIGN KEY (`parent_attempt_id`) REFERENCES `attempts`(`id`),
  FOREIGN KEY (`seed_case_id`) REFERENCES `attack_cases`(`id`)
) COMMENT='공격시도';

CREATE TABLE `findings` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '발견ID',
  `scan_id` INT NOT NULL COMMENT '스캔ID',
  `objective_id` INT NOT NULL COMMENT '목표ID',
  `attempt_id` INT NOT NULL COMMENT '시도ID',
  `atlas_technique_id` VARCHAR(32) NULL COMMENT '기법ID',
  `severity` VARCHAR(16) NULL COMMENT '심각도',
  `title` VARCHAR(256) NULL COMMENT '제목',
  `evidence` JSON NULL COMMENT '증거',
  `mitigation` TEXT NULL COMMENT '완화책',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`),
  FOREIGN KEY (`objective_id`) REFERENCES `objectives`(`id`),
  FOREIGN KEY (`attempt_id`) REFERENCES `attempts`(`id`),
  FOREIGN KEY (`atlas_technique_id`) REFERENCES `atlas_techniques`(`id`)
) COMMENT='발견취약점';

CREATE TABLE `attack_cases` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '공격사례ID',
  `prompt_text` TEXT NOT NULL COMMENT '공격프롬프트',
  `attack_type` VARCHAR(64) NULL COMMENT '공격유형',
  `atlas_technique_id` VARCHAR(32) NULL COMMENT '기법ID',
  `source` VARCHAR(64) NULL COMMENT '출처',
  `worked_on` JSON NOT NULL COMMENT '성공모델',
  `verified` TINYINT(1) NOT NULL COMMENT '검증여부',
  `tags` JSON NOT NULL COMMENT '태그',
  `embedding` TEXT NULL COMMENT '임베딩벡터',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`atlas_technique_id`) REFERENCES `atlas_techniques`(`id`)
) COMMENT='공격코퍼스';

CREATE TABLE `scan_events` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '이벤트ID',
  `scan_id` INT NOT NULL COMMENT '스캔ID',
  `objective_id` INT NULL COMMENT '목표ID',
  `event_type` VARCHAR(16) NOT NULL COMMENT '이벤트유형',
  `payload` JSON NULL COMMENT '페이로드',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`),
  FOREIGN KEY (`objective_id`) REFERENCES `objectives`(`id`)
) COMMENT='스캔이벤트로그';

CREATE TABLE `scan_reports` (
  `id` INT NOT NULL AUTO_INCREMENT COMMENT '리포트ID',
  `scan_id` INT NOT NULL COMMENT '스캔ID',
  `total_objectives` INT NOT NULL COMMENT '총목표수',
  `breached_count` INT NOT NULL COMMENT '뚫린수',
  `coverage_pct` FLOAT NOT NULL COMMENT '커버리지(%)',
  `severity_counts` JSON NOT NULL COMMENT '심각도분포',
  `risk_score` FLOAT NOT NULL COMMENT '위험도점수',
  `generated_at` TIMESTAMP NOT NULL COMMENT '생성리포트일시',
  `created_at` TIMESTAMP NOT NULL COMMENT '생성일시',
  `updated_at` TIMESTAMP NOT NULL COMMENT '수정일시',
  `deleted_at` TIMESTAMP NULL COMMENT '삭제일시',
  PRIMARY KEY (`id`),
  FOREIGN KEY (`scan_id`) REFERENCES `scans`(`id`)
) COMMENT='스캔통계리포트';

