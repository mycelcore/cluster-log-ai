import ollama


SYSTEM_PROMPT = """Du bist ein erfahrener DevOps-Engineer, Kubernetes-Administrator und IT-Security-Analyst.
Du analysierst Kubernetes-Cluster-Logs aus zwei Perspektiven:

## Teil 1: Cluster Operations
1. Identifiziere kritische Fehler, CrashLoops, OOMKills und Anomalien
2. Erkenne wiederkehrende Muster und schleichende Degradation
3. Bewerte den allgemeinen Cluster-Gesundheitszustand
4. Pruefe auf Ressourcenprobleme (CPU/Memory Pressure, Disk, Evictions)
5. Gib konkrete Handlungsempfehlungen wenn noetig

## Teil 2: Security Analyse
1. Erkenne Anzeichen von Angriffen oder unbefugtem Zugriff:
   - Brute-Force-Versuche (wiederholte Auth-Fehler)
   - Ungewoehnliche API-Server-Zugriffe oder verbotene Requests (403/401 Haeufungen)
   - Privilege Escalation Versuche
   - Verdaechtige Pod-Erstellungen oder Container-Starts
   - Port-Scanning oder ungewoehnliche Netzwerkaktivitaet
   - Zugriffe von unbekannten Service Accounts
   - Aenderungen an RBAC, Secrets oder Security Policies
2. Bewerte ob Muster auf gezielte Angriffe oder normale Fehlkonfiguration hindeuten
3. Bei Verdacht: Dringlichkeit einschaetzen (Info / Warnung / Kritisch)

## Format
- Kurz und praegnant (max 600 Woerter)
- Zwei klar getrennte Abschnitte: OPERATIONS und SECURITY
- Wichtigstes zuerst
- Bei Problemen: was, wo, moegliche Ursache, empfohlene Aktion
- Security-Findings mit Dringlichkeit kennzeichnen
- Wenn alles ok ist, sag das kurz pro Abschnitt
"""


class LogAnalyzer:
    def __init__(self, url: str = "http://localhost:11434", model: str = "llama3.1:8b", timeout: int = 120):
        self.client = ollama.Client(host=url, timeout=timeout)
        self.model = model

    def analyze(self, logs: list[dict], max_chars: int = 8000) -> str:
        """Logs analysieren und Zusammenfassung zurueckgeben."""
        if not logs:
            return "Keine Logs im analysierten Zeitraum gefunden."

        # Logs fuer den Prompt vorbereiten
        log_text = self._prepare_log_text(logs, max_chars)

        # Statistiken erstellen
        stats = self._compute_stats(logs)

        user_prompt = f"""Analysiere die folgenden Kubernetes-Cluster-Logs der letzten Stunde.

Statistik:
- Gesamt: {stats['total']} Log-Eintraege
- Errors: {stats['errors']}
- Warnings: {stats['warnings']}
- Namespaces: {', '.join(stats['namespaces'])}
- Pods mit Fehlern: {', '.join(stats['error_pods'][:10])}

Logs (gekuerzt auf relevante Eintraege):
{log_text}
"""

        response = self.client.chat(
            model=self.model,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
        )

        return response["message"]["content"]

    def _prepare_log_text(self, logs: list[dict], max_chars: int) -> str:
        """Logs in einen Text-Block umwandeln, priorisiert nach Schwere."""
        # Errors und Warnings zuerst
        priority_logs = [l for l in logs if l["level"] in ("error", "fatal", "panic", "critical")]
        warning_logs = [l for l in logs if l["level"] == "warn"]
        other_logs = [l for l in logs if l["level"] not in ("error", "fatal", "panic", "critical", "warn")]

        lines = []
        char_count = 0

        for log in priority_logs + warning_logs + other_logs:
            line = f"[{log['namespace']}/{log['pod']}] {log['level'].upper()}: {log['line']}"
            if char_count + len(line) > max_chars:
                break
            lines.append(line)
            char_count += len(line)

        return "\n".join(lines)

    @staticmethod
    def _compute_stats(logs: list[dict]) -> dict:
        """Basis-Statistiken ueber die Logs berechnen."""
        namespaces = set()
        error_pods = set()
        errors = 0
        warnings = 0

        for log in logs:
            namespaces.add(log["namespace"])
            if log["level"] in ("error", "fatal", "panic", "critical"):
                errors += 1
                error_pods.add(log["pod"])
            elif log["level"] == "warn":
                warnings += 1

        return {
            "total": len(logs),
            "errors": errors,
            "warnings": warnings,
            "namespaces": sorted(namespaces),
            "error_pods": sorted(error_pods),
        }
