import httpx


class TelegramReporter:
    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id
        self.base_url = f"https://api.telegram.org/bot{bot_token}"

    def send_report(self, report: str, title: str = "Cluster Log Report") -> bool:
        """Report per Telegram senden."""
        # Telegram hat ein 4096 Zeichen Limit pro Nachricht
        header = f"*{title}*\n{'—' * 20}\n\n"
        max_length = 4096 - len(header) - 10

        if len(report) > max_length:
            # Aufteilen in mehrere Nachrichten
            chunks = self._split_message(report, max_length)
            success = True
            for i, chunk in enumerate(chunks):
                if i == 0:
                    msg = header + chunk
                else:
                    msg = f"_(Fortsetzung {i+1})_\n\n{chunk}"
                success = success and self._send_message(msg)
            return success

        return self._send_message(header + report)

    def send_alert(self, message: str) -> bool:
        """Kurze Alert-Nachricht senden."""
        return self._send_message(f"⚠ *Alert*\n\n{message}")

    def _send_message(self, text: str) -> bool:
        """Nachricht an Telegram API senden."""
        try:
            response = httpx.post(
                f"{self.base_url}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "Markdown",
                },
                timeout=10,
            )
            response.raise_for_status()
            return True
        except Exception as e:
            print(f"Telegram Fehler: {e}")
            return False

    @staticmethod
    def _split_message(text: str, max_length: int) -> list[str]:
        """Text in Chunks aufteilen ohne Woerter zu trennen."""
        chunks = []
        while text:
            if len(text) <= max_length:
                chunks.append(text)
                break
            # Am letzten Newline vor dem Limit trennen
            split_at = text.rfind("\n", 0, max_length)
            if split_at == -1:
                split_at = text.rfind(" ", 0, max_length)
            if split_at == -1:
                split_at = max_length
            chunks.append(text[:split_at])
            text = text[split_at:].lstrip()
        return chunks
