-- Schema fuer cluster-log-ai Analyse-Ergebnisse
-- Wird beim ersten Start des Postgres-Containers automatisch ausgefuehrt
-- (Mount nach /docker-entrypoint-initdb.d/). Die App stellt das gleiche
-- Schema beim Start nochmal idempotent sicher (siehe db.py), inkl.
-- ADD COLUMN IF NOT EXISTS fuer existierende Volumes.

-- ---------------------------------------------------------------
-- projects: ein Eintrag pro Log-Quelle / Cluster / Kunde.
-- Mehrere Analyzer-Instanzen schreiben in dieselbe DB; jede ist
-- per project_slug fest einem Eintrag zugeordnet (Auto-Upsert).
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS projects (
    id          BIGSERIAL PRIMARY KEY,
    slug        TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ---------------------------------------------------------------
-- analysis_runs: ein Eintrag pro Analyzer-Lauf
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS analysis_runs (
    id              BIGSERIAL PRIMARY KEY,
    project_id      BIGINT      REFERENCES projects(id) ON DELETE SET NULL,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    duration        TEXT        NOT NULL,
    namespaces      TEXT[],
    model           TEXT,
    log_count       INTEGER     NOT NULL DEFAULT 0,
    error_count     INTEGER     NOT NULL DEFAULT 0,
    warning_count   INTEGER     NOT NULL DEFAULT 0,
    error_pods      TEXT[],
    report          TEXT,
    stats           JSONB,
    status          TEXT        NOT NULL DEFAULT 'success',  -- success | failed | empty
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_run_at  ON analysis_runs (run_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status  ON analysis_runs (status);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_project ON analysis_runs (project_id, run_at DESC);

-- ---------------------------------------------------------------
-- security_findings: strukturiert extrahierte Security-Erkenntnisse
-- project_id ist redundant zu analysis_runs.project_id, aber
-- denormalisiert fuer schnelle Filter ueber alle Runs eines Projekts.
-- ---------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_findings (
    id          BIGSERIAL PRIMARY KEY,
    project_id  BIGINT      REFERENCES projects(id) ON DELETE SET NULL,
    run_id      BIGINT      NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity    TEXT        NOT NULL,  -- info | warning | critical
    category    TEXT,                  -- z.B. brute_force, rbac_change, priv_esc
    summary     TEXT        NOT NULL,
    details     TEXT,
    metadata    JSONB
);

CREATE INDEX IF NOT EXISTS idx_security_findings_run_id    ON security_findings (run_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_severity  ON security_findings (severity);
CREATE INDEX IF NOT EXISTS idx_security_findings_project   ON security_findings (project_id, severity, detected_at DESC);

-- ---------------------------------------------------------------
-- Migration fuer existierende Volumes: Spalten nachziehen falls
-- die Tabellen bereits ohne project_id existieren.
-- ---------------------------------------------------------------
ALTER TABLE analysis_runs     ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL;
