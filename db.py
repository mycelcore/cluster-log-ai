"""Persistierung der Analyse-Ergebnisse in PostgreSQL.

Verbindung wird primaer aus DATABASE_URL gelesen, faellt auf einzelne
ENV-Variablen (POSTGRES_HOST etc.) und dann auf den database-Block
in der config.yaml zurueck.

Beim Modul-Init wird das Schema idempotent sichergestellt (inkl. ADD
COLUMN IF NOT EXISTS fuer existierende Volumes), damit das auch dann
funktioniert, wenn die DB nicht ueber init.sql initialisiert wurde.

Die DB ist bewusst multi-projekt-faehig: jede Analyzer-Instanz upserted
beim Start ihren project_slug; alle Runs und Findings haengen daran.
"""

from __future__ import annotations

import os
from contextlib import contextmanager
from typing import Iterable

import psycopg
from psycopg.types.json import Jsonb


SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS projects (
    id          BIGSERIAL PRIMARY KEY,
    slug        TEXT        NOT NULL UNIQUE,
    name        TEXT        NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

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
    status          TEXT        NOT NULL DEFAULT 'success',
    error_message   TEXT
);

CREATE INDEX IF NOT EXISTS idx_analysis_runs_run_at  ON analysis_runs (run_at DESC);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_status  ON analysis_runs (status);
CREATE INDEX IF NOT EXISTS idx_analysis_runs_project ON analysis_runs (project_id, run_at DESC);

CREATE TABLE IF NOT EXISTS security_findings (
    id          BIGSERIAL PRIMARY KEY,
    project_id  BIGINT      REFERENCES projects(id) ON DELETE SET NULL,
    run_id      BIGINT      NOT NULL REFERENCES analysis_runs(id) ON DELETE CASCADE,
    detected_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    severity    TEXT        NOT NULL,
    category    TEXT,
    summary     TEXT        NOT NULL,
    details     TEXT,
    metadata    JSONB
);

CREATE INDEX IF NOT EXISTS idx_security_findings_run_id    ON security_findings (run_id);
CREATE INDEX IF NOT EXISTS idx_security_findings_severity  ON security_findings (severity);
CREATE INDEX IF NOT EXISTS idx_security_findings_project   ON security_findings (project_id, severity, detected_at DESC);

-- Migration fuer existierende Volumes
ALTER TABLE analysis_runs     ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL;
ALTER TABLE security_findings ADD COLUMN IF NOT EXISTS project_id BIGINT REFERENCES projects(id) ON DELETE SET NULL;
"""


def _build_dsn(db_conf: dict | None) -> str:
    """DSN aus ENV oder config.yaml zusammenbauen."""
    url = os.environ.get("DATABASE_URL")
    if url:
        return url

    host = os.environ.get("POSTGRES_HOST")
    if host:
        port = os.environ.get("POSTGRES_PORT", "5432")
        user = os.environ.get("POSTGRES_USER", "postgres")
        password = os.environ.get("POSTGRES_PASSWORD", "")
        dbname = os.environ.get("POSTGRES_DB", "clusterlogai")
        return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

    if db_conf:
        host = db_conf.get("host", "localhost")
        port = db_conf.get("port", 5432)
        user = db_conf.get("user", "postgres")
        password = db_conf.get("password", "")
        dbname = db_conf.get("name", "clusterlogai")
        return f"postgresql://{user}:{password}@{host}:{port}/{dbname}"

    raise RuntimeError(
        "Keine DB-Konfiguration gefunden. Setze DATABASE_URL, "
        "POSTGRES_* ENV-Variablen oder einen 'database'-Block in config.yaml."
    )


class Database:
    """Schmaler Wrapper um psycopg fuer die paar Inserts, die wir brauchen."""

    def __init__(self, db_conf: dict | None = None):
        self.dsn = _build_dsn(db_conf)

    @contextmanager
    def _conn(self):
        with psycopg.connect(self.dsn) as conn:
            yield conn

    # -- Schema -------------------------------------------------------

    def ensure_schema(self) -> None:
        """Tabellen + Migrationen idempotent sicherstellen."""
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)
            conn.commit()

    # -- Projects -----------------------------------------------------

    def upsert_project(
        self,
        slug: str,
        name: str | None = None,
        description: str | None = None,
    ) -> int:
        """Projekt anlegen oder Metadaten aktualisieren. Gibt project_id zurueck."""
        if not slug:
            raise ValueError("project slug darf nicht leer sein")
        name = name or slug
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO projects (slug, name, description)
                VALUES (%s, %s, %s)
                ON CONFLICT (slug) DO UPDATE
                  SET name        = EXCLUDED.name,
                      description = COALESCE(EXCLUDED.description, projects.description),
                      updated_at  = NOW()
                RETURNING id
                """,
                (slug, name, description),
            )
            project_id = cur.fetchone()[0]
            conn.commit()
            return project_id

    # -- Runs ---------------------------------------------------------

    def save_run(
        self,
        *,
        project_id: int | None,
        duration: str,
        namespaces: list[str] | None,
        model: str | None,
        report: str | None,
        stats: dict | None,
        status: str = "success",
        error_message: str | None = None,
    ) -> int:
        """Einen Analyse-Run speichern. Gibt die run_id zurueck."""
        stats = stats or {}
        with self._conn() as conn, conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO analysis_runs
                    (project_id, duration, namespaces, model, log_count,
                     error_count, warning_count, error_pods, report,
                     stats, status, error_message)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING id
                """,
                (
                    project_id,
                    duration,
                    namespaces or None,
                    model,
                    int(stats.get("total", 0)),
                    int(stats.get("errors", 0)),
                    int(stats.get("warnings", 0)),
                    list(stats.get("error_pods", []) or []) or None,
                    report,
                    Jsonb(stats),
                    status,
                    error_message,
                ),
            )
            run_id = cur.fetchone()[0]
            conn.commit()
            return run_id

    # -- Security Findings -------------------------------------------

    def save_security_findings(
        self,
        *,
        run_id: int,
        project_id: int | None,
        findings: Iterable[dict],
    ) -> int:
        """Liste von Findings speichern. Erwartete Felder pro Eintrag:
        severity (str), category (str|None), summary (str),
        details (str|None), metadata (dict|None).
        """
        rows = []
        for f in findings:
            rows.append(
                (
                    project_id,
                    run_id,
                    (f.get("severity") or "info").lower(),
                    f.get("category"),
                    f.get("summary", "")[:1000] if f.get("summary") else "",
                    f.get("details"),
                    Jsonb(f.get("metadata")) if f.get("metadata") else None,
                )
            )

        if not rows:
            return 0

        with self._conn() as conn, conn.cursor() as cur:
            cur.executemany(
                """
                INSERT INTO security_findings
                    (project_id, run_id, severity, category, summary, details, metadata)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                rows,
            )
            conn.commit()
            return len(rows)
