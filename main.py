import sys
import time
import yaml
import schedule as sched
from datetime import datetime

from loki_client import LogAPIClient
from analyzer import LogAnalyzer
from telegram_reporter import TelegramReporter


def load_config(path: str = "config.yaml") -> dict:
    """Konfiguration laden."""
    with open(path) as f:
        return yaml.safe_load(f)


def run_analysis(config: dict):
    """Eine Analyse-Runde ausfuehren."""
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Analyse gestartet...")

    api_conf = config["log_api"]
    keycloak_conf = config["keycloak"]
    ollama_conf = config["ollama"]
    analysis_conf = config.get("analysis", {})

    # 1. Logs ueber die Log API holen
    client = LogAPIClient(
        api_url=api_conf["url"],
        keycloak_url=keycloak_conf["url"],
        client_id=keycloak_conf["client_id"],
        client_secret=keycloak_conf["client_secret"],
    )

    duration = api_conf.get("query_range", "1h")
    namespaces = api_conf.get("namespaces") or None

    try:
        logs = client.get_all_logs(duration=duration, namespaces=namespaces)
    except Exception as e:
        print(f"Fehler beim Abrufen der Logs: {e}")
        send_error_alert(config, f"Log API nicht erreichbar: {e}")
        return

    print(f"  {len(logs)} Log-Eintraege abgerufen")

    if not logs:
        print("  Keine Logs gefunden, ueberspringe Analyse.")
        return

    # 2. Durch Ollama analysieren
    analyzer = LogAnalyzer(
        url=ollama_conf["url"],
        model=ollama_conf["model"],
        timeout=ollama_conf.get("timeout", 120),
    )

    try:
        max_chars = analysis_conf.get("max_context_chars", 8000)
        report = analyzer.analyze(logs, max_chars=max_chars)
    except Exception as e:
        print(f"Fehler bei der Analyse: {e}")
        send_error_alert(config, f"Ollama Analyse fehlgeschlagen: {e}")
        return

    print(f"  Analyse abgeschlossen ({len(report)} Zeichen)")

    # 3. Report senden
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
        # Ohne Telegram: Report auf stdout ausgeben
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

    print(f"cluster-log-ai gestartet")
    print(f"  Log API: {config['log_api']['url']}")
    print(f"  Ollama: {config['ollama']['url']} ({config['ollama']['model']})")
    print(f"  Intervall: {config['schedule']['interval']}")
    print()

    # Einmal sofort ausfuehren
    run_analysis(config)

    # Danach nach Schedule
    interval = config["schedule"]["interval"]
    if interval.endswith("m"):
        minutes = int(interval[:-1])
        sched.every(minutes).minutes.do(run_analysis, config)
    elif interval.endswith("h"):
        hours = int(interval[:-1])
        sched.every(hours).hours.do(run_analysis, config)
    else:
        sched.every(1).hours.do(run_analysis, config)

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
