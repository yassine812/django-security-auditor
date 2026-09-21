-- PostgreSQL schema for the multi-user deployment (spec 33).
-- The JSON artifact store (AuditStore) implements the same entities for
-- single-machine/CLI use.

CREATE TABLE users (
    id            BIGSERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL CHECK (role IN ('admin','analyst','viewer')),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE projects (
    id          BIGSERIAL PRIMARY KEY,
    name        TEXT NOT NULL,
    source_type TEXT NOT NULL CHECK (source_type IN ('github','local','zip')),
    path        TEXT,
    repo_url    TEXT,
    branch      TEXT,
    commit_sha  TEXT,
    profile     JSONB NOT NULL DEFAULT '{}',
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audits (
    id                       BIGSERIAL PRIMARY KEY,
    audit_uid                TEXT UNIQUE NOT NULL,
    project_id               BIGINT REFERENCES projects(id),
    status                   TEXT NOT NULL,
    config                   JSONB NOT NULL DEFAULT '{}',
    authorization_confirmed  BOOLEAN NOT NULL DEFAULT FALSE,
    score                    JSONB,
    retest_of                BIGINT REFERENCES audits(id),
    comparison               JSONB,
    created_at               TIMESTAMPTZ NOT NULL DEFAULT now(),
    finished_at              TIMESTAMPTZ
);

CREATE TABLE requirements (
    id               TEXT PRIMARY KEY,             -- REQ-001
    name             TEXT NOT NULL,
    description      TEXT NOT NULL,
    category         TEXT NOT NULL,
    severity         TEXT NOT NULL,
    verification     TEXT[] NOT NULL,
    automation_level TEXT NOT NULL,
    cwe              TEXT[] NOT NULL DEFAULT '{}',
    owasp            TEXT NOT NULL DEFAULT '',
    remediation      TEXT NOT NULL,
    scanner_mapping  JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE scan_jobs (
    id         BIGSERIAL PRIMARY KEY,
    audit_id   BIGINT REFERENCES audits(id),
    name       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('QUEUED','RUNNING','SUCCESS','FAILED','SKIPPED')),
    error      TEXT,
    started_at TIMESTAMPTZ,
    finished_at TIMESTAMPTZ
);

CREATE TABLE evidence (
    id              BIGSERIAL PRIMARY KEY,
    audit_id        BIGINT REFERENCES audits(id),
    source          TEXT NOT NULL,                 -- sast|dast|network|configuration|dependencies|automated|internal
    rule_id         TEXT NOT NULL,
    polarity        TEXT NOT NULL CHECK (polarity IN ('vuln','ok','info')),
    confidence      TEXT NOT NULL DEFAULT 'High',
    summary         TEXT NOT NULL,
    location        JSONB NOT NULL DEFAULT '{}',   -- file/line OR url/request/response OR target/port
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE findings (
    id              BIGSERIAL PRIMARY KEY,
    audit_id        BIGINT REFERENCES audits(id),
    title           TEXT NOT NULL,
    description     TEXT NOT NULL,
    severity        TEXT NOT NULL,
    confidence      TEXT NOT NULL,
    category        TEXT NOT NULL,
    cwe             TEXT[] NOT NULL DEFAULT '{}',
    owasp           TEXT NOT NULL DEFAULT '',
    sources         TEXT[] NOT NULL DEFAULT '{}',
    file            TEXT,
    line            INT,
    endpoint        TEXT,
    request         TEXT,
    response        TEXT,
    proof           TEXT,
    remediation     TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'OPEN',
    retest_status   TEXT,
    dedup_key       TEXT NOT NULL,
    first_seen      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX findings_dedup_idx ON findings (dedup_key);

CREATE TABLE requirement_results (
    id             BIGSERIAL PRIMARY KEY,
    audit_id       BIGINT REFERENCES audits(id),
    requirement_id TEXT REFERENCES requirements(id),
    status         TEXT NOT NULL CHECK (status IN ('PASS','FAIL','PARTIAL','NOT_TESTED','NOT_APPLICABLE','MANUAL_REVIEW')),
    notes          TEXT[] NOT NULL DEFAULT '{}',
    UNIQUE (audit_id, requirement_id)
);

CREATE TABLE finding_requirements (
    finding_id     BIGINT REFERENCES findings(id) ON DELETE CASCADE,
    requirement_id TEXT REFERENCES requirements(id),
    PRIMARY KEY (finding_id, requirement_id)
);

CREATE TABLE finding_evidence (
    finding_id  BIGINT REFERENCES findings(id) ON DELETE CASCADE,
    evidence_id BIGINT REFERENCES evidence(id) ON DELETE CASCADE,
    PRIMARY KEY (finding_id, evidence_id)
);

CREATE TABLE endpoints (
    id         BIGSERIAL PRIMARY KEY,
    audit_id   BIGINT REFERENCES audits(id),
    method     TEXT NOT NULL,
    path       TEXT NOT NULL,
    view       TEXT,
    source_file TEXT,
    note       TEXT
);

CREATE TABLE test_executions (
    id         BIGSERIAL PRIMARY KEY,
    audit_id   BIGINT REFERENCES audits(id),
    test_id    TEXT NOT NULL,
    name       TEXT NOT NULL,
    status     TEXT NOT NULL CHECK (status IN ('PASS','FAIL','NOT_TESTED')),
    expected   TEXT,
    actual     TEXT,
    detail     TEXT,
    location   JSONB NOT NULL DEFAULT '{}'
);

CREATE TABLE reports (
    id         BIGSERIAL PRIMARY KEY,
    audit_id   BIGINT REFERENCES audits(id),
    format     TEXT NOT NULL CHECK (format IN ('pdf','html','json','csv')),
    path       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE audit_logs (
    id         BIGSERIAL PRIMARY KEY,
    actor      TEXT,
    action     TEXT NOT NULL,
    detail     JSONB NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
