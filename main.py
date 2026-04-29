import sys
import time
import yaml
import schedule as sched
from datetime import datetime

from loki_client import LogAPIClient
from analyzer import LogAnalyzer
from telegram_reporter import TelegramReporter
from db import Database


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


def run_analysis(config: dict, db: Database | None = None, project_id: int | None = None):
    """Eine Analyse-Runde ausfuehren."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyse gestartet...")

    api_conf = config["log_api"]
    keycloak_conf = config["keycloak"]
    ollama_conf = config["ollama"]
    analysis_conf = config.get("analysis", {})

    duration = api_conf.get("query_range", "1h")
    namespaces = api_conf.get("namespaces") or None
    model = ollama_conf.get("model")

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
        send_error_alert(config, msg)
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
        return

    # 2. Durch Ollama analysieren
    analyzer = LogAnalyzer(
        url=ollama_conf["url"],
        model=ollama_conf["model"],
        timeout=ollama_conf.get("timeout", 120),
    )

    stats = analyzer._compute_stats(logs)

    try:
        max_chars = analysis_conf.get("max_context_chars", 8000)
        report = analyzer.analyze(logs, max_chars=max_chars)
    except Exception as e:
        msg = f"Ollama Analyse fehlgeschlagen: {e}"
        print(f"Fehler bei der Analyse: {e}")
        send_error_alert(config, msg)
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

    # 3. Persistieren: Run + (optional) strukturierte Findings
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

    if db and run_id is not None and analysis_conf.get("extract_findings", True):
        try:
            findings = analyzer.extract_findings(report)
            if findings:
                count = db.save_security_findings(
                    run_id=run_id, project_id=project_id, findings=findings,
                )
                print(f"  {count} Security-Finding(s) gespeichert")
            else:
                print("  Keine Security-Findings extrahiert")
        except Exception as e:
            print(f"WARNUNG: Findings-Extraktion/Speicherung fehlgeschlagen: {e}")

    # 4. Report senden
    if "telegram" in config and config["telegram"].get("bot_token") != "YOUR_BOT_TOKEN":
        reporter = TelegramReporter(
            bot_token=config["telegram"]["bot_token"],
            chat_id=config["telegram"]["chat_id"],
        )
        title = f"Log Report ({duration})"
        success = reporter.send_report(report, title=title)
        if success:
            print("  Report per Telegram gesendet.")
        else:
            print("  WARNUNG: Telegram-Versand fehlgeschlagen.")
    else:
        print("\n" + "=" * 60)
        print(report)
        print("=" * 60 + "\n")


def send_error_alert(config: dict, message: str):
    """Fehler-Alert senden falls Telegram konfiguriert."""
    if "telegram" in config and config["telegram"].get("bot_token") != "YOUR_BOT_TOKEN":
        reporter = TelegramReporter(
            bot_token=config["telegram"]["bot_token"],
            chat_id=config["telegram"]["chat_id"],
        )
        reporter.send_alert(message)


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

    print("cluster-log-ai gestartet")
    print(f"  Projekt: {project_slug} ({project_conf.get('name', project_slug)})")
    print(f"  Log API: {config['log_api']['url']}")
    print(f"  Ollama:  {config['ollama']['url']} ({config['ollama']['model']})")
    print(f"  Intervall: {config['schedule']['interval']}")

    # DB initialisieren + Projekt upserten
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

    # Einmal sofort ausfuehren
    run_analysis(config, db, project_id)

    # Danach nach Schedule
    interval = config["schedule"]["interval"]
    if interval.endswith("m"):
        minutes = int(interval[:-1])
        sched.every(minutes).minutes.do(run_analysis, config, db, project_id)
    elif interval.endswith("h"):
        hours = int(interval[:-1])
        sched.every(hours).hours.do(run_analysis, config, db, project_id)
    else:
        sched.every(1).hours.do(run_analysis, config, db, project_id)

    print(f"Scheduler aktiv (naechste Ausfuehrung in {interval})")
    print("Beenden mit Ctrl+C\n")

    try:
        while True:
            sched.run_pending()
            time.sleep(10)
    except KeyboardInterrupt:
        print("\nBeendet.")


if __name__ == "__main__":
    main()
