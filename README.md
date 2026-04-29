# cluster-log-ai

Holt Logs aus einem Kubernetes-Cluster (ueber eine eigene Log-API mit Keycloak-Auth),
laesst sie durch ein lokales Ollama-Modell laufen, schickt den Report per Telegram
und persistiert Run-Statistiken sowie strukturierte Security-Findings in PostgreSQL.

Mehrere Projekte (Cluster, Kunden) koennen parallel auf dieselbe DB schreiben — pro
Projekt laeuft ein eigener Analyzer-Container mit eigener Config. Differenziert wird
ueber `project.slug`.

## Komponenten

```
   Loki/Log-API ──► Analyzer (Python) ──► Ollama ──► Telegram
                         │                  │
                         │                  └──► strukturierte Findings (JSON)
                         ▼
                     PostgreSQL
                     (analysis_runs + security_findings + projects)
```

| Datei                          | Zweck                                                    |
|--------------------------------|----------------------------------------------------------|
| `main.py`                      | Scheduler, orchestriert eine Analyse-Runde              |
| `loki_client.py`               | HTTP-Client gegen die Log-API (mit Keycloak-Token)      |
| `analyzer.py`                  | Ollama-Aufrufe: Markdown-Report + JSON-Findings         |
| `telegram_reporter.py`         | Versand des Reports per Telegram                         |
| `db.py`                        | psycopg-Wrapper, Schema-Sicherung, Inserts              |
| `db/init.sql`                  | Initial-Schema fuer Postgres-Container                  |
| `compose.yaml`                 | DB + analyzer-Service(s)                                |
| `config.yaml.example`          | Template fuer das Hauptprojekt (`ensy-prod`)            |
| `config.firma-xyz.yaml.example`| Template fuer ein zweites Projekt                       |
| `.env.example`                 | Postgres-Credentials und Zeitzone fuer compose          |

## Schnellstart (ein Projekt)

```bash
cp .env.example .env                       # POSTGRES_PASSWORD setzen
cp config.yaml.example config.yaml         # log_api/keycloak/telegram/ollama anpassen
docker compose up -d --build
docker compose logs -f analyzer-ensy-prod
```

Auf Linux sorgt `extra_hosts: host.docker.internal:host-gateway` dafuer, dass
`http://host.docker.internal:11434` aus dem Container den auf dem Host laufenden
Ollama erreicht. Falls Ollama lieber auf einer festen IP laeuft, setze `ollama.url`
in der Config entsprechend.

## Mehrere Projekte

Pro Projekt eine eigene Config, ein eigener Container, gemeinsame DB.

```bash
cp config.firma-xyz.yaml.example config.firma-xyz.yaml
# Werte anpassen (project.slug, log_api, keycloak, optional eigener Telegram-Bot)

# In compose.yaml den auskommentierten analyzer-firma-xyz Service aktivieren, dann:
docker compose up -d --build analyzer-firma-xyz
docker compose logs -f analyzer-firma-xyz
```

Der Analyzer macht beim Start ein Upsert auf `projects` anhand des `slug` aus der
Config — das Projekt taucht also automatisch in der DB auf, sobald es zum ersten
Mal laeuft.

## Datenbank-Schema

```
projects                       analysis_runs                     security_findings
-----------------------        ----------------------            ----------------------
id          BIGSERIAL PK       id            BIGSERIAL PK        id           BIGSERIAL PK
slug        TEXT UNIQUE        project_id    FK -> projects      project_id   FK -> projects  (denormalisiert)
name        TEXT               run_at        TIMESTAMPTZ         run_id       FK -> analysis_runs ON DELETE CASCADE
description TEXT               duration      TEXT                detected_at  TIMESTAMPTZ
created_at  TIMESTAMPTZ        namespaces    TEXT[]              severity     TEXT  (info|warning|critical)
updated_at  TIMESTAMPTZ        model         TEXT                category     TEXT
                               log_count     INT                 summary      TEXT
                               error_count   INT                 details      TEXT
                               warning_count INT                 metadata     JSONB
                               error_pods    TEXT[]
                               report        TEXT  (Markdown)
                               stats         JSONB
                               status        TEXT  (success|failed|empty)
                               error_message TEXT
```

`security_findings.project_id` ist redundant zu `analysis_runs.project_id` — Absicht,
damit Filter "alle critical findings fuer Projekt X" ohne Join laufen.

Schema-Migration: `init.sql` und `db.ensure_schema()` enthalten am Ende
`ALTER TABLE ... ADD COLUMN IF NOT EXISTS project_id`. Ein bestehendes Volume aus
einer Vorversion wird beim Container-Start automatisch nachgezogen.

## Schedule und Telegram-Verhalten

Pro Tag laufen zwei Arten von Jobs:

- **Stuendlicher Silent-Check** (`schedule.hourly_minute`, default Min 00):
  Analyse laeuft, Run + Findings landen in der DB. Telegram-Nachricht
  wird **nur** verschickt, wenn ein Finding eine Severity in
  `analysis.alert_severities` (default `warning`/`critical`) hat — und
  dann als kompakte Findings-Liste, nicht als voller Report.
- **Taeglicher Vollbericht** (`schedule.daily_report_at`, default `09:00`):
  Analyse laeuft, voller Markdown-Report geht per Telegram raus, plus
  DB-Persistierung wie immer.

Der Startup-Run beim Container-Start verhaelt sich wie der hourly-Check
(silent ausser bei Alerts) — Container-Restarts fluten den Chat also nicht.

```yaml
schedule:
  hourly_minute: 0          # jede Stunde zu Minute 00
  daily_report_at: "09:00"  # HH:MM in der Container-TZ (.env: TZ)

analysis:
  alert_severities: ["warning", "critical"]  # was als problematisch gilt
```

Zeitzone des Containers wird in `.env` ueber `TZ` gesetzt
(default `Europe/Berlin`). `daily_report_at` versteht sich in dieser TZ.

## Strukturierte Security-Findings

Nach dem Markdown-Report macht der Analyzer einen zweiten Ollama-Call mit JSON-Schema
(`format=FINDINGS_SCHEMA` aus `analyzer.py`) und extrahiert die Security-Anteile als
Liste:

```json
{
  "findings": [
    {"severity": "warning", "category": "auth_failure",
     "summary": "Mehrere fehlgeschlagene Logins von 10.0.0.5",
     "details": "Im namespace auth 24x 401 in 30min."}
  ]
}
```

Wenn die Extraktion mal hakt (LLM-Schemafehler, Netzwerk), wird das geloggt und
der Hauptpfad laeuft trotzdem durch (Telegram-Versand, Run-Persistierung). Ueber
`analysis.extract_findings: false` deaktivierbar.

## Beispiel-Queries

```sql
-- Letzte 10 Runs eines Projekts
SELECT run_at, status, log_count, error_count, warning_count
FROM analysis_runs
WHERE project_id = (SELECT id FROM projects WHERE slug = 'ensy-prod')
ORDER BY run_at DESC LIMIT 10;

-- Alle critical findings der letzten 24h, projektuebergreifend
SELECT p.slug, sf.detected_at, sf.category, sf.summary
FROM security_findings sf JOIN projects p ON p.id = sf.project_id
WHERE sf.severity = 'critical' AND sf.detected_at > NOW() - INTERVAL '24 hours'
ORDER BY sf.detected_at DESC;

-- Run-Uebersicht pro Projekt der letzten 24h
SELECT p.slug, COUNT(*) AS runs, SUM(error_count) AS errors
FROM analysis_runs r JOIN projects p ON p.id = r.project_id
WHERE run_at > NOW() - INTERVAL '24 hours'
GROUP BY p.slug
ORDER BY errors DESC;

-- Volltext im Markdown-Report durchsuchen
SELECT p.slug, r.run_at, substring(r.report, 1, 300)
FROM analysis_runs r JOIN projects p ON p.id = r.project_id
WHERE r.report ILIKE '%CrashLoop%'
ORDER BY r.run_at DESC LIMIT 20;
```

## Konfiguration

Pflicht-Felder in der Config:

```yaml
project:
  slug: "ensy-prod"           # eindeutig pro DB
  name: "Energiesynergie Prod"

log_api:    { url, query_range, namespaces }
keycloak:   { url, client_id, client_secret }
ollama:     { url, model, timeout }
schedule:   { hourly_minute, daily_report_at }
```

Optional: `telegram`, `analysis`, `database` (Letzteres wird im Compose durch
`DATABASE_URL` ueberschrieben — nur fuer lokalen Direkt-Betrieb relevant).

DB-Verbindung Reihenfolge in `db.py`:

1. `DATABASE_URL` ENV
2. `POSTGRES_HOST` / `POSTGRES_PORT` / `POSTGRES_USER` / `POSTGRES_PASSWORD` / `POSTGRES_DB` ENVs
3. `database`-Block in der Config

## Lokal entwickeln (ohne Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# Postgres separat starten oder den db-Container des compose nutzen
docker compose up -d db
python main.py config.yaml
```

## Bekannte Limitierungen / TODO

- Es gibt aktuell kein Read-Only-UI/API auf der DB. Zugriff geht via psql /
  pgAdmin / eigener Query.
- `extract_findings` schreibt `metadata: NULL`; sobald das Schema erweitert wird
  (z.B. betroffene Pods/Namespaces strukturiert), kann der Prompt entsprechend
  ergaenzt werden.
- Keine Alembic-Migrationen — Schema-Aenderungen laufen ueber idempotente
  `CREATE/ALTER ... IF NOT EXISTS` Statements in `db.py` und `db/init.sql`.
