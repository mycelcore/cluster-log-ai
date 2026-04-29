import httpx


class TelegramReporter:
    # Telegram-Limit pro Nachricht
    MESSAGE_LIMIT = 4096

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"

    def send_report(self, report: str, title: str = "Cluster Log Report") -> bool:
        """Report per Telegram senden (Plain-Text, kein Markdown).

        Wir senden bewusst ohne parse_mode, weil Ollama-Output haeufig
        Markdown-Sonderzeichen enthaelt (**bold**, ##, _, [...]) die
        Telegrams Markdown-Parser zum Stolpern bringen.
        """
        header = f"{title}\n{'-' * 30}\n\n"
        max_length = self.MESSAGE_LIMIT - len(header) - 20

        if len(report) > max_length:
            chunks = self._split_message(report, max_length)
            success = True
            for i, chunk in enumerate(chunks):
                if i == 0:
                    msg = header + chunk
                else:
                    msg = f"(Fortsetzung {i+1})\n\n{chunk}"
                success = self._send_message(msg) and success
            return success

        return self._send_message(header + report)

    def send_alert(self, message: str) -> bool:
        """Kurze Alert-Nachricht senden."""
        return self._send_message(f"[ALERT] {message}")

    def send_findings_alert(
        self,
        findings: list[dict],
        project_label: str | None = None,
    ) -> bool:
        """Kompakte Telegram-Nachricht mit den problematischen Findings.

        Bewusst knapp gehalten — landet ggf. mitten in der Nacht im Chat.
        Format pro Eintrag:
            [SEVERITY/category] summary
            details...
        """
        if not findings:
            return True

        header = "[Security Alert]"
        if project_label:
            header += f" {project_label}"
        header += f" — {len(findings)} problematische Finding(s)"

        lines = [header, "-" * 30, ""]
        for f in findings:
            sev = (f.get("severity") or "info").upper()
            cat = f.get("category") or "?"
            summary = (f.get("summary") or "").strip()
            details = (f.get("details") or "").strip()
            lines.append(f"[{sev}/{cat}] {summary}")
            if details:
                lines.append(f"  {details}")
            lines.append("")

        text = "\n".join(lines).rstrip()
        # Auf Telegram-Limit zuschneiden falls noetig
        if len(text) > self.MESSAGE_LIMIT:
            text = text[: self.MESSAGE_LIMIT - 20] + "\n... (gekuerzt)"
        return self._send_message(text)

    def _send_message(self, text: str) -> bool:
        """Nachricht an Telegram API senden. Loggt bei Fehler den Body
        der Telegram-Antwort fuer schnelle Diagnose.
        """
        try:
            response = httpx.post(
                f"{self.base_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    # bewusst kein parse_mode: Plain-Text ist robust gegen
                    # alle LLM-Formatierungen.
                    "disable_web_page_preview": True,
                },
                timeout=10,
            )
            if response.status_code != 200:
                # Telegram gibt im JSON-Body "ok"/"description" zurueck —
                # das ist die wirklich nuetzliche Info.
                body = ""
                try:
                    body = response.json().get("description", response.text)
                except Exception:
                    body = response.text
                print(f"Telegram {response.status_code}: {body}")
                return False
            return True
        except httpx.HTTPError as e:
            print(f"Telegram Netzwerkfehler: {e}")
            return False

    @staticmethod
    def _split_message(text: str, max_length: int) -> list[str]:
        """Text in Chunks aufteilen ohne Woerter zu trennen."""
        chunks = []
        while text:
            if len(text) <= max_length:
                chunks.append(text)
                break
            split_at = text.rfind("\n", 0, max_length)
            if split_at == -1:
                split_at = text.rfind(" ", 0, max_length)
            if split_at == -1:
                split_at = max_length
            chunks.append(text[:split_at])
            text = text[split_at:].lstrip()
        return chunks
