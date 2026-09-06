-- 1. 공격이벤트
CREATE TABLE "공격이벤트" (
    "공격id" BIGSERIAL PRIMARY KEY,
    "발생시간" TIMESTAMPTZ NOT NULL DEFAULT CURRENTTIMESTAMP,
    "요청구분" VARCHAR(20) NOT NULL,       -- 공격, 정상
    "공격주체" VARCHAR(50) NOT NULL,       -- AI, 사용자, 시뮬레이터
    "공격유형" VARCHAR(100),              -- XSS, SQL Injection 등
    "공격시나리오" VARCHAR(200),          -- 시나리오명
    "대상엔드포인트" VARCHAR(300) NOT NULL, -- /login, /search 등
    "HTTP메서드" VARCHAR(10) NOT NULL,     -- GET, POST 등
    "요청파라미터" JSONB,                 -- query/form/json 데이터
    "공격페이로드" TEXT,                  -- 테스트 입력 내용
    "HTTP상태코드" INTEGER,               -- 응답 코드
    "응답시간ms" INTEGER,               -- 응답 시간
    "요청로그" TEXT,                      -- 요청 관련 로그
    "애플리케이션로그" TEXT                -- Flask 로그 등
);

-- 2. 공격정답
CREATE TABLE "공격정답" (
    "정답id" BIGSERIAL PRIMARY KEY,
    "공격id" BIGINT NOT NULL UNIQUE REFERENCES "공격이벤트"("공격id") ON DELETE CASCADE,
    "실제공격여부" BOOLEAN NOT NULL,
    "실제공격유형" VARCHAR(100),
    "실제위험도" VARCHAR(20),             -- LOW, MEDIUM, HIGH, CRITICAL
    "MITRE기술id" VARCHAR(30),
    "MITRE전술" VARCHAR(100),
    "공격성공여부" BOOLEAN,              -- VulnBank 공격 성공 여부
    "정답검증여부" BOOLEAN DEFAULT FALSE,
    "정답출처" VARCHAR(50) NOT NULL       -- scenario, manual 등
);

-- 3. 방어AI분석
CREATE TABLE "방어AI분석" (
    "분석id" BIGSERIAL PRIMARY KEY,
    "공격id" BIGINT NOT NULL REFERENCES "공격이벤트"("공격id") ON DELETE CASCADE,
    "모델이름" VARCHAR(100) NOT NULL,
    "모델버전" VARCHAR(50) NOT NULL,
    "탐지여부" BOOLEAN NOT NULL,
    "예측공격유형" VARCHAR(100),
    "예측위험도" VARCHAR(20),
    "신뢰도" NUMERIC(5, 4),                 -- 0~1 (예: 0.9500)
    "예측MITRE기술id" VARCHAR(30),
    "공격분석" TEXT,                      -- AI 분석 결과
    "대응방안" JSONB,                     -- 권장 대응 목록
    "분석시간ms" INTEGER,                 -- 추론 시간
    "생성시간" TIMESTAMPTZ NOT NULL DEFAULT CURRENTTIMESTAMP
);

-- 4. RAG검색기록
CREATE TABLE "RAG검색기록" (
    "검색id" BIGSERIAL PRIMARY KEY,
    "분석id" BIGINT NOT NULL REFERENCES "방어AI분석"("분석id") ON DELETE CASCADE,
    "지식유형" VARCHAR(30) NOT NULL,      -- MITRE, 과거경험 등
    "문서id" VARCHAR(200) NOT NULL,
    "문서내용" TEXT NOT NULL,             -- 실제 제공한 Context
    "유사도" NUMERIC(6, 5),                 -- Vector similarity (예: 0.93000)
    "검색순위" INTEGER NOT NULL,            -- Top-K 순위
    "검색시간" TIMESTAMPTZ NOT NULL DEFAULT CURRENTTIMESTAMP
);

-- 5. 방어결과
CREATE TABLE "방어결과" (
    "방어id" BIGSERIAL PRIMARY KEY,
    "공격id" BIGINT NOT NULL REFERENCES "공격이벤트"("공격id") ON DELETE CASCADE,
    "분석id" BIGINT REFERENCES "방어AI분석"("분석id") ON DELETE SET NULL,
    "대응유형" VARCHAR(50) NOT NULL,       -- BLOCK, ALLOW, RATELIMIT 등
    "실행내용" TEXT,                      -- 실제 수행한 대응
    "자동대응여부" BOOLEAN DEFAULT FALSE,
    "방어성공여부" BOOLEAN,
    "처리시간ms" INTEGER,                 -- 대응 소요시간
    "결과설명" TEXT,
    "실행시간" TIMESTAMPTZ NOT NULL DEFAULT CURRENTTIMESTAMP
);

-- 6. AI평가결과
CREATE TABLE "AI평가결과" (
    "라운드id" BIGINT REFERENCES "대결라운드"("라운드id"),
    "평가id" BIGSERIAL PRIMARY KEY,
    "공격id" BIGINT NOT NULL REFERENCES "공격이벤트"("공격id") ON DELETE CASCADE,
    "분석id" BIGINT NOT NULL REFERENCES "방어AI분석"("분석id") ON DELETE CASCADE,
    "탐지정확" BOOLEAN NOT NULL,           -- 정상/공격 판별
    "공격유형정확" BOOLEAN,                -- 공격 분류
    "위험도정확" BOOLEAN,                  -- Severity
    "MITRE정확" BOOLEAN,                  -- MITRE Mapping
    "대응점수" NUMERIC(5, 4),              -- 대응 품질
    "종합점수" NUMERIC(5, 4) NOT NULL,     -- 전체 평가
    "평가시간" TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- =================================================================
-- Index 설정 (조회 성능 최적화)
-- =================================================================

-- CREATE INDEX "idx공격이벤트발생시간" ON "공격이벤트"("발생시간");
-- CREATE INDEX "idx공격이벤트요청구분" ON "공격이벤트"("요청구분");
-- CREATE INDEX "idx방어AI분석공격id" ON "방어AI분석"("공격id");
-- CREATE INDEX "idxRAG검색기록분석id" ON "RAG검색기록"("분석id");
-- CREATE INDEX "idx방어결과공격id" ON "방어결과"("공격id");
-- CREATE INDEX "idxAI평가결과공격id" ON "AI평가결과"("공격id");

CREATE TABLE 대결라운드 (
    라운드id BIGSERIAL PRIMARY KEY,

    공격자모델 VARCHAR(100),
    공격자버전 VARCHAR(50),

    방어자모델 VARCHAR(100),
    방어자버전 VARCHAR(50),

    공격이벤트id BIGINT
        REFERENCES 공격이벤트(공격id)
        ON DELETE SET NULL,

    승자 VARCHAR(20),

    공격자보상 NUMERIC(6,3),
    방어자보상 NUMERIC(6,3),

    시작시간 TIMESTAMPTZ DEFAULT NOW(),
    종료시간 TIMESTAMPTZ
);


CREATE TABLE 공격AI행동 (
    행동id BIGSERIAL PRIMARY KEY,

    라운드id BIGINT NOT NULL
        REFERENCES 대결라운드(라운드id)
        ON DELETE CASCADE,

    모델이름 VARCHAR(100),
    모델버전 VARCHAR(50),

    공격전략 VARCHAR(100),
    선택시나리오 VARCHAR(200),
    목표엔드포인트 VARCHAR(300),

    참고경험 JSONB,

    공격성공여부 BOOLEAN,
    탐지회피여부 BOOLEAN,

    보상점수 NUMERIC(6,3),

    생성시간 TIMESTAMPTZ DEFAULT NOW()
);
