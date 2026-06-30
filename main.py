import sys
import time
import yaml
import schedule as sched
from datetime import datetime

from loki_client import LogAPIClient
from analyzer import LogAnalyzer
from telegram_reporter import TelegramReporter
from db import Database


# Default-Severities, die eine sofortige Telegram-Nachricht ausloesen.
DEFAULT_ALERT_SEVERITIES = ("critical",)


def load_config(path: str = "config.yaml") -> dict:
    """Konfiguration laden."""
    with open(path) as f:
        return yaml.safe_load(f)


def _get_db(config: dict) -> Database | None:
    """Database-Instanz holen (oder None wenn explizit deaktiviert)."""
    db_conf = config.get("database") or {}
    if db_conf.get("enabled") is False:
        return None
    try:
        return Database(db_conf)
    except Exception as e:
        print(f"WARNUNG: DB-Konfiguration nicht nutzbar ({e}). Persistierung deaktiviert.")
        return None


def _get_telegram(config: dict) -> TelegramReporter | None:
    """Telegram-Reporter falls konfiguriert."""
    tg = config.get("telegram") or {}
    if tg.get("bot_token") and tg.get("bot_token") != "YOUR_BOT_TOKEN":
        return TelegramReporter(bot_token=tg["bot_token"], chat_id=tg["chat_id"])
    return None


def run_analysis(
    config: dict,
    db: Database | None = None,
    project_id: int | None = None,
    *,
    force_send_full_report: bool = False,
):
    """Eine Analyse-Runde ausfuehren.

    Telegram-Verhalten:
      - force_send_full_report=True  -> immer den vollen Report schicken
                                        (z.B. taeglich um 09:00)
      - force_send_full_report=False -> nur ein kompakter Findings-Alert,
                                        wenn Findings mit alert-Severity da sind
                                        (z.B. stuendlicher Silent-Check)
    """
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyse gestartet"
          f"{' (Morgenbericht)' if force_send_full_report else ''}...")

    api_conf = config["log_api"]
    keycloak_conf = config["keycloak"]
    ollama_conf = config["ollama"]
    analysis_conf = config.get("analysis", {})

    duration = api_conf.get("query_range", "1h")
    namespaces = api_conf.get("namespaces") or None
    model = ollama_conf.get("model")
    project_conf = config.get("project") or {}
    project_label = project_conf.get("name") or project_conf.get("slug")

    alert_severities = {
        s.lower() for s in analysis_conf.get("alert_severities", DEFAULT_ALERT_SEVERITIES)
    }
    reporter = _get_telegram(config)

    # 1. Logs ueber die Log API holen
    client = LogAPIClient(
        api_url=api_conf["url"],
        keycloak_url=keycloak_conf["url"],
        client_id=keycloak_conf["client_id"],
        client_secret=keycloak_conf["client_secret"],
    )

    try:
        logs = client.get_all_logs(duration=duration, namespaces=namespaces)
    except Exception as e:
        msg = f"Log API nicht erreichbar: {e}"
        print(f"Fehler beim Abrufen der Logs: {e}")
        if reporter:
            reporter.send_alert(msg)
        if db:
            try:
                db.save_run(
                    project_id=project_id,
                    duration=duration, namespaces=namespaces, model=model,
                    report=None, stats=None, status="failed", error_message=msg,
                )
            except Exception as db_e:
                print(f"WARNUNG: Konnte Fehler-Run nicht in DB speichern: {db_e}")
        return

    print(f"  {len(logs)} Log-Eintraege abgerufen")

    if not logs:
        print("  Keine Logs gefunden, ueberspringe Analyse.")
        if db:
            try:
                db.save_run(
                    project_id=project_id,
                    duration=duration, namespaces=namespaces, model=model,
                    report=None, stats={"total": 0}, status="empty",
                )
            except Exception as db_e:
                print(f"WARNUNG: Konnte leeren Run nicht in DB speichern: {db_e}")
        if force_send_full_report and reporter:
            reporter.send_alert(f"Morgenbericht: keine Logs in den letzten {duration}.")
        return

    # 2. Durch Ollama analysieren
    analyzer = LogAnalyzer(
        url=ollama_conf["url"],
        model=ollama_conf["model"],
        timeout=ollama_conf.get("timeout", 120),
        priority_levels=analysis_conf.get("priority_levels"),
    )

    stats = analyzer.compute_stats(logs)

    try:
        max_chars = analysis_conf.get("max_context_chars", 8000)
        report = analyzer.analyze(logs, max_chars=max_chars)
    except Exception as e:
        msg = f"Ollama Analyse fehlgeschlagen: {e}"
        print(f"Fehler bei der Analyse: {e}")
        if reporter:
            reporter.send_alert(msg)
        if db:
            try:
                db.save_run(
                    project_id=project_id,
                    duration=duration, namespaces=namespaces, model=model,
                    report=None, stats=stats, status="failed", error_message=msg,
                )
            except Exception as db_e:
                print(f"WARNUNG: Konnte Fehler-Run nicht in DB speichern: {db_e}")
        return

    print(f"  Analyse abgeschlossen ({len(report)} Zeichen)")

    # 3. Run persistieren
    run_id: int | None = None
    if db:
        try:
            run_id = db.save_run(
                project_id=project_id,
                duration=duration, namespaces=namespaces, model=model,
                report=report, stats=stats, status="success",
            )
            print(f"  Run gespeichert (run_id={run_id})")
        except Exception as db_e:
            print(f"WARNUNG: DB-Schreibvorgang (run) fehlgeschlagen: {db_e}")

    # 4. Strukturierte Findings extrahieren
    findings: list[dict] = []
    if analysis_conf.get("extract_findings", True):
        try:
            findings = analyzer.extract_findings(report)
        except Exception as e:
            print(f"WARNUNG: Findings-Extraktion fehlgeschlagen: {e}")
            findings = []

        if not findings:
            print("  Keine Security-Findings extrahiert")

    # 5. Deduplizierung VOR dem Speichern — sonst dedupt sich jeder Run selbst
    problematic: list[dict] = []
    if findings:
        problematic = [f for f in findings if (f.get("severity") or "").lower() in alert_severities]

        if problematic and db:
            cooldown = int(analysis_conf.get("dedup_cooldown_hours", 8))
            before = len(problematic)
            problematic = db.filter_new_findings(
                project_id=project_id,
                findings=problematic,
                cooldown_hours=cooldown,
            )
            suppressed = before - len(problematic)
            if suppressed:
                print(f"  {suppressed} Finding(s) durch Deduplizierung unterdrueckt (Cooldown: {cooldown}h)")

    # 6. Findings in DB persistieren (nach Dedup, damit der Cooldown greift)
    if findings and db and run_id is not None:
        try:
            count = db.save_security_findings(
                run_id=run_id, project_id=project_id, findings=findings,
            )
            print(f"  {count} Security-Finding(s) gespeichert")
        except Exception as e:
            print(f"WARNUNG: Findings-DB-Schreibvorgang fehlgeschlagen: {e}")

    # 7. Telegram: voller Report ODER kompakter Alert ODER nichts
    if not reporter:
        print("\n" + "=" * 60)
        print(report)
        print("=" * 60 + "\n")
        return

    if force_send_full_report:
        title = f"Morgenbericht — {project_label} ({duration})"
        ok = reporter.send_report(report, title=title)
        print(f"  Morgenbericht per Telegram: {'OK' if ok else 'FEHLER'}")
        return

    if problematic:
        ok = reporter.send_findings_alert(problematic, project_label=project_label)
        print(f"  {len(problematic)} Findings als Alert gesendet: {'OK' if ok else 'FEHLER'}")
    else:
        print("  Keine alert-relevanten Findings — kein Telegram-Versand.")


def main():
    config_path = sys.argv[1] if len(sys.argv) > 1 else "config.yaml"

    try:
        config = load_config(config_path)
    except FileNotFoundError:
        print(f"Config nicht gefunden: {config_path}")
        print("Kopiere config.yaml.example nach config.yaml und passe die Werte an.")
        sys.exit(1)

    project_conf = config.get("project") or {}
    project_slug = project_conf.get("slug")
    if not project_slug:
        print("FEHLER: 'project.slug' fehlt in der Config. Pflichtfeld fuer Multi-Projekt-DB.")
        sys.exit(1)

    schedule_conf = config.get("schedule") or {}
    hourly_minute = int(schedule_conf.get("hourly_minute", 0))
    daily_at = schedule_conf.get("daily_report_at", "09:00")
    # Backward-Compat: altes "interval" wird ignoriert, aber freundlich kommentiert
    if "interval" in schedule_conf:
        print("  Hinweis: 'schedule.interval' wird nicht mehr genutzt — "
              "stuendlicher Silent-Check + taeglicher Bericht via "
              "'hourly_minute'/'daily_report_at'.")

    print("cluster-log-ai gestartet")
    print(f"  Projekt:  {project_slug} ({project_conf.get('name', project_slug)})")
    print(f"  Log API:  {config['log_api']['url']}")
    print(f"  Ollama:   {config['ollama']['url']} ({config['ollama']['model']})")
    print(f"  Schedule: stuendlich um Min {hourly_minute:02d} (silent), "
          f"taeglich um {daily_at} (Vollbericht)")

    db = _get_db(config)
    project_id: int | None = None
    if db:
        try:
            db.ensure_schema()
            project_id = db.upsert_project(
                slug=project_slug,
                name=project_conf.get("name"),
                description=project_conf.get("description"),
            )
            print(f"  Database: verbunden, Schema OK, project_id={project_id}")
        except Exception as e:
            print(f"  WARNUNG: DB-Init fehlgeschlagen ({e}). Laeuft ohne Persistierung.")
            db = None
    else:
        print("  Database: nicht konfiguriert (laeuft ohne Persistierung)")
    print()

    # Startup-Run: silent (kein voller Report ausser hourly-Alerts greifen)
    run_analysis(config, db, project_id, force_send_full_report=False)

    # Stuendlicher Silent-Check
    sched.every().hour.at(f":{hourly_minute:02d}").do(
        run_analysis, config, db, project_id, force_send_full_report=False
    )
    # Taeglicher Vollbericht
    sched.every().day.at(daily_at).do(
        run_analysis, config, db, project_id, force_send_full_report=True
    )

    print(f"Scheduler aktiv. Beenden mit Ctrl+C\n")

    try:
        while True:
            sched.run_pending()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nBeendet.")


if __name__ == "__main__":
    main()
