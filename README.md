# cluster-log-ai

Kubernetes-Cluster-Logs automatisiert analysieren: Logs ueber eine eigene Log-API (mit Keycloak-Auth) aus Loki ziehen, durch ein lokales Ollama-Modell schicken, Security-Findings per Telegram melden und alles in PostgreSQL persistieren.

Multi-Projekt-faehig — pro Cluster/Kunde ein eigener Analyzer-Container mit eigener Config, alle schreiben in dieselbe DB (differenziert ueber `project.slug`).

## Architektur

```
                        K8s Cluster                          Mac Mini (Buero)
                   ┌─────────────────────┐            ┌─────────────────────────────┐
                   │  Loki ◄── Promtail  │            │                             │
                   │    │                │            │  Analyzer (Python)           │
                   │    ▼                │   HTTPS    │    │                         │
                   │  Log-API (FastAPI) ─┼───────────►│    ├──► Ollama (lokal)       │
                   │  (Keycloak-Auth)    │            │    │     └─► Markdown-Report │
                   └─────────────────────┘            │    │     └─► JSON-Findings   │
                                                      │    │                         │
                                                      │    ├──► PostgreSQL           │
                                                      │    └──► Telegram-Alert       │
                                                      └─────────────────────────────┘
```

Die Log-API laeuft im jeweiligen K8s-Cluster vor Loki. Der Analyzer laeuft auf dem Mac Mini, zieht Logs ueber die oeffentliche Domain der Log-API und analysiert sie lokal mit Ollama.

## Projektstruktur

### Analyzer (Root-Verzeichnis)

| Datei | Zweck |
|---|---|
| `main.py` | Scheduler, orchestriert Analyse-Runden |
| `loki_client.py` | HTTP-Client gegen die Log-API (Keycloak-Token) |
| `analyzer.py` | Ollama-Aufrufe: Markdown-Report + JSON-Findings-Extraktion |
| `telegram_reporter.py` | Versand von Reports und Alerts per Telegram |
| `db.py` | psycopg-Wrapper, Schema-Migration, Queries |
| `compose.yaml` | PostgreSQL + Analyzer-Service(s) |
| `Dockerfile` | Analyzer-Container-Image |
| `requirements.txt` | Python-Dependencies |

### Log-API (`log-api/`)

| Datei | Zweck |
|---|---|
| `main.py` | FastAPI-App, Health-Endpoint |
| `api.py` | Endpoints: `/api/query`, `/api/errors`, `/api/namespaces`, `/api/stats` |
| `auth.py` | Keycloak JWT-Validierung |
| `config.py` | Pydantic-Settings (Loki-URL, Keycloak-URL, Loki-Selector) |
| `Dockerfile` | Container-Image (ARM64-kompatibel) |

### K8s-Manifeste (`k8s/hosting/`)

ArgoCD-Deployment der Log-API im Hosting-Cluster. Manifeste liegen im separaten Repo `mycelcore/k8s-manifests` unter `internal-tools/cluster-log-api/`.

### CI/CD (`.github/workflows/`)

| Workflow | Trigger | Aktion |
|---|---|---|
| `build-log-api.yaml` | Push auf `main` (Pfad `log-api/**`) | ARM64-Image bauen und nach `ghcr.io/mycelcore/log-api:latest` pushen |

## Schnellstart

```bash
cp .env.example .env                       # POSTGRES_PASSWORD setzen
cp config.yaml.example config.yaml         # log_api/keycloak/telegram/ollama anpassen
docker compose up -d --build
docker compose logs -f analyzer-ensy-prod
```

Auf Linux sorgt `extra_hosts: host.docker.internal:host-gateway` dafuer, dass der Container den auf dem Host laufenden Ollama unter `http://host.docker.internal:11434` erreicht.

## Mehrere Projekte

Pro Projekt eine eigene Config und ein eigener Container, gemeinsame DB.

```bash
cp config.hosting.yaml.example config.hosting.yaml
# Werte anpassen (project.slug, log_api, keycloak, telegram)

# In compose.yaml den analyzer-hosting Service einkommentieren, dann:
docker compose up -d --build analyzer-hosting
```

Der Analyzer macht beim Start ein Upsert auf `projects` anhand des `slug` — das Projekt erscheint automatisch in der DB.

### Aktive Instanzen

| Projekt | Log-API Domain | Keycloak Realm | Schedule |
|---|---|---|---|
| `ensy-prod` | `logs.energiesynergie.de` | `auth.energiesynergie.de/realms/ensy` | :00 / 09:00 |
| `hosting` | `cluster.logs.mycelcore.de` | `auth.mycelcore.de/realms/internal-tools` | :30 / 09:15 |

## Analyse-Pipeline

### 1. Log-Priorisierung

Logs werden vor dem LLM-Aufruf priorisiert, damit das Kontextfenster (`max_context_chars`, default 8000) optimal genutzt wird:

1. **Security-relevante Logs** — keyword-basiert (z.B. `shadow`, `token`, `nsenter`, `cryptominer`, `privilege escalation`), unabhaengig vom Log-Level
2. **Error/Fatal/Panic/Critical** — konfigurierbar ueber `analysis.priority_levels`
3. **Warnings**
4. **Rest**

### 2. LLM-Analyse (Ollama)

Zwei Ollama-Aufrufe pro Run:

- **Markdown-Report**: Cluster-Health + Security-Bewertung. Klare Trennung zwischen Ops-Problemen und echten Security-Findings. Explicit Negativliste verhindert False Positives (Reconciler-Fehler, Vault-Issues, CrashLoops werden nicht als Security klassifiziert).
- **JSON-Findings-Extraktion**: Strukturierte Security-Findings mit Severity (`info`/`warning`/`critical`) und Kategorie (`brute_force`, `auth_failure`, `rbac_change`, `priv_esc`, `suspicious_pod`, `port_scan`, `secret_access`, `unauthorized_access`).

### 3. Deduplizierung

Findings werden vor dem Speichern gegen die DB geprüft: gleiche Kategorie + aehnliche Summary innerhalb des Cooldown-Zeitraums (`dedup_cooldown_hours`, default 8) werden unterdrueckt.

### 4. Alerting

- **Stuendlicher Silent-Check** (`schedule.hourly_minute`): Telegram-Alert nur bei Findings mit Severity in `alert_severities` (default: nur `critical`).
- **Taeglicher Vollbericht** (`schedule.daily_report_at`): Kompletter Markdown-Report per Telegram.
- **Startup-Run**: Verhaelt sich wie der hourly-Check — Container-Restarts fluten den Chat nicht.

## Konfiguration

```yaml
project:
  slug: "ensy-prod"           # eindeutig pro DB
  name: "Energiesynergie Prod"

log_api:
  url: "https://logs.energiesynergie.de"
  query_range: "1h"
  namespaces: []               # leer = alle

keycloak:
  url: "https://auth.energiesynergie.de/realms/ensy"
  client_id: "log-analyzer"
  client_secret: "..."

ollama:
  url: "http://host.docker.internal:11434"
  model: "llama3.1:8b"
  timeout: 120

schedule:
  hourly_minute: 0
  daily_report_at: "09:00"

analysis:
  priority_levels: ["error", "fatal", "panic"]
  max_context_chars: 8000
  extract_findings: true
  alert_severities: ["critical"]
  dedup_cooldown_hours: 8

telegram:
  bot_token: "..."
  chat_id: "..."

database:
  enabled: true
  host: "localhost"
  port: 5432
  user: "clusterlogai"
  password: "..."
  name: "clusterlogai"
```

DB-Verbindung (Prioritaet): `DATABASE_URL` ENV > einzelne `POSTGRES_*` ENVs > `database`-Block in Config.

### Log-API Konfiguration

Die Log-API wird ueber Environment-Variablen konfiguriert (Prefix `LOG_API_`):

| Variable | Default | Beschreibung |
|---|---|---|
| `LOG_API_LOKI_URL` | `http://loki.monitoring.svc.cluster.local:3100` | Loki-Adresse im Cluster |
| `LOG_API_KEYCLOAK_URL` | `https://auth.energiesynergie.de/realms/ensy` | Keycloak Realm URL |
| `LOG_API_LOKI_SELECTOR` | `{job=~".+"}` | Default LogQL-Selector (alle Jobs) |

## Datenbank-Schema

```
projects                       analysis_runs                     security_findings
-----------------------        ----------------------            ----------------------
id          BIGSERIAL PK       id            BIGSERIAL PK        id           BIGSERIAL PK
slug        TEXT UNIQUE        project_id    FK -> projects      project_id   FK -> projects
name        TEXT               run_at        TIMESTAMPTZ         run_id       FK -> analysis_runs
description TEXT               duration      TEXT                detected_at  TIMESTAMPTZ
created_at  TIMESTAMPTZ        namespaces    TEXT[]              severity     TEXT
updated_at  TIMESTAMPTZ        model         TEXT                category     TEXT
                               log_count     INT                 summary      TEXT
                               error_count   INT                 details      TEXT
                               warning_count INT                 metadata     JSONB
                               error_pods    TEXT[]
                               report        TEXT
                               stats         JSONB
                               status        TEXT
                               error_message TEXT
```

Schema-Migration laeuft ueber idempotente `CREATE/ALTER ... IF NOT EXISTS` in `db.ensure_schema()`.

## Beispiel-Queries

```sql
-- Letzte 10 Runs eines Projekts
SELECT run_at, status, log_count, error_count, warning_count
FROM analysis_runs
WHERE project_id = (SELECT id FROM projects WHERE slug = 'ensy-prod')
ORDER BY run_at DESC LIMIT 10;

-- Alle critical findings der letzten 24h
SELECT p.slug, sf.detected_at, sf.category, sf.summary
FROM security_findings sf JOIN projects p ON p.id = sf.project_id
WHERE sf.severity = 'critical' AND sf.detected_at > NOW() - INTERVAL '24 hours'
ORDER BY sf.detected_at DESC;
```

## Lokal entwickeln (ohne Docker)

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
docker compose up -d db
python main.py config.yaml
```
