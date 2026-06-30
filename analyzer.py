import json

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
1. Erkenne Anzeichen von ECHTEN Angriffen oder unbefugtem Zugriff:
   - Brute-Force-Versuche (viele Auth-Fehler von derselben IP in kurzer Zeit)
   - Ungewoehnliche API-Server-Zugriffe von unbekannten Quellen
   - Privilege Escalation Versuche (z.B. exec in privilegierte Pods)
   - Verdaechtige Pod-Erstellungen mit hostPID/hostNetwork/privileged
   - Port-Scanning oder ungewoehnliche Netzwerkaktivitaet
   - Zugriffe von unbekannten oder neuen Service Accounts
   - Unautorisierte Aenderungen an RBAC, Secrets oder Security Policies
2. Bewerte ob Muster auf gezielte Angriffe hindeuten

WICHTIG — Das sind KEINE Security-Findings, sondern normale Ops-Probleme:
- Reconciler-Fehler oder Retry-Loops (z.B. external-secrets, cert-manager)
- Vault/ClusterSecretStore nicht bereit oder Permission-Denied bei Operatoren
- CrashLoopBackOff, OOMKill, Readiness/Liveness-Probe-Fehler
- Fehlgeschlagene Deployments, Image-Pull-Fehler
- Ressourcen-Limits, Evictions, Scheduling-Fehler
- DNS-Aufloesung, Service-Konnektivitaet
- Token-Ablauf oder -Erneuerung bei Operatoren und Controllern
Diese gehoeren in den OPERATIONS-Abschnitt, auch wenn sie 403/401 enthalten.

## Format
- Kurz und praegnant (max 600 Woerter)
- Zwei klar getrennte Abschnitte: OPERATIONS und SECURITY
- Wichtigstes zuerst
- Bei Problemen: was, wo, moegliche Ursache, empfohlene Aktion
- Security-Findings mit Dringlichkeit kennzeichnen
- Wenn alles ok ist, sag das kurz pro Abschnitt
"""


# JSON Schema fuer die strukturierte Findings-Extraktion.
# Ollama-Python (>=0.4) akzeptiert ein dict als format-Parameter und
# erzwingt strukturierte Ausgabe.
FINDINGS_SCHEMA = {
    "type": "object",
    "properties": {
        "findings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "severity": {
                        "type": "string",
                        "enum": ["info", "warning", "critical"],
                    },
                    "category": {
                        "type": "string",
                        "enum": [
                            "brute_force",
                            "auth_failure",
                            "rbac_change",
                            "priv_esc",
                            "suspicious_pod",
                            "port_scan",
                            "secret_access",
                            "unauthorized_access",
                        ],
                        "description": "Kategorie des Security-Findings. NUR eine der vorgegebenen Kategorien.",
                    },
                    "summary": {
                        "type": "string",
                        "description": "Eine Zeile, was beobachtet wurde",
                    },
                    "details": {
                        "type": "string",
                        "description": "Mehr Kontext: wo, wann, evtl. betroffene Pods/Namespaces",
                    },
                },
                "required": ["severity", "summary"],
            },
        }
    },
    "required": ["findings"],
}


FINDINGS_SYSTEM_PROMPT = """Du extrahierst aus einem bereits erstellten Cluster-Log-Analyse-Report
die SECURITY-relevanten Findings als strukturierte Liste.

Regeln:
- NUR echte Security-Findings. Bei Zweifeln: lieber weglassen.
- Wenn der Report keine Security-Auffaelligkeiten hat: gib eine LEERE Liste zurueck.
- Severity: 'info' fuer Beobachtungen, 'warning' fuer verdaechtig, 'critical' fuer wahrscheinlichen Angriff.
- 'critical' ist reserviert fuer klare Angriffsindikatoren (Brute-Force, Privilege Escalation, unautorisierter Zugriff). Verwende es NICHT fuer operationale Fehler.
- summary kurz (max ~150 Zeichen), details darf ausfuehrlicher sein.
- Antworte ausschliesslich mit JSON im vorgegebenen Schema.

Das sind KEINE Security-Findings (NICHT extrahieren):
- Reconciler-Fehler, Controller-Restart-Loops, Retry-Fehler
- Vault/SecretStore nicht bereit, Token abgelaufen bei Operatoren
- CrashLoopBackOff, OOMKill, Probe-Fehler, Scheduling-Probleme
- 403/401 von Kubernetes-Operatoren (external-secrets, cert-manager etc.)
- Image-Pull-Fehler, DNS-Probleme, Service-Konnektivitaet
Diese sind operationale Probleme und gehoeren NICHT in die Findings-Liste.
"""


class LogAnalyzer:
    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "llama3.1:8b",
        timeout: int = 120,
        priority_levels: list[str] | None = None,
    ):
        self.client = ollama.Client(host=url, timeout=timeout)
        self.model = model
        self.priority_levels = priority_levels or ["error", "fatal", "panic", "critical"]

    def analyze(self, logs: list[dict], max_chars: int = 8000) -> str:
        """Logs analysieren und Zusammenfassung als Text zurueckgeben."""
        if not logs:
            return "Keine Logs im analysierten Zeitraum gefunden."

        log_text = self._prepare_log_text(logs, max_chars)
        stats = self.compute_stats(logs)

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

    def extract_findings(self, report_text: str) -> list[dict]:
        """Aus dem Markdown-Report die SECURITY-Findings als strukturierte
        Liste extrahieren. Nutzt Ollama mit JSON-Schema-Format.

        Gibt im Fehlerfall eine leere Liste zurueck (best-effort, Hauptpfad
        soll nicht scheitern wenn die Extraktion mal hakt).
        """
        if not report_text or not report_text.strip():
            return []

        try:
            response = self.client.chat(
                model=self.model,
                format=FINDINGS_SCHEMA,
                messages=[
                    {"role": "system", "content": FINDINGS_SYSTEM_PROMPT},
                    {
                        "role": "user",
                        "content": (
                            "Hier der Analyse-Report. Extrahiere Security-Findings.\n\n"
                            + report_text
                        ),
                    },
                ],
            )
        except Exception as e:
            print(f"  WARNUNG: Findings-Extraktion fehlgeschlagen: {e}")
            return []

        content = response.get("message", {}).get("content", "")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            print(f"  WARNUNG: Konnte Findings-JSON nicht parsen: {e}")
            return []

        findings = data.get("findings", [])
        # Defensive Kopie + Schema-Mindestanforderung pruefen
        cleaned = []
        for f in findings:
            if not isinstance(f, dict):
                continue
            summary = (f.get("summary") or "").strip()
            if not summary:
                continue
            cleaned.append({
                "severity": (f.get("severity") or "info").lower(),
                "category": f.get("category"),
                "summary": summary,
                "details": f.get("details"),
                "metadata": None,  # Platzhalter fuer spaeter
            })
        return cleaned

    def _prepare_log_text(self, logs: list[dict], max_chars: int) -> str:
        """Logs in einen Text-Block umwandeln, priorisiert nach Schwere."""
        prio_set = set(self.priority_levels)
        priority_logs = [l for l in logs if l["level"] in prio_set]
        warning_logs = [l for l in logs if l["level"] == "warn"]
        other_logs = [l for l in logs if l["level"] not in prio_set and l["level"] != "warn"]

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
    def compute_stats(logs: list[dict]) -> dict:
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
