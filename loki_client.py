import httpx
from datetime import datetime, timezone, timedelta


class LogAPIClient:
    """Client fuer die Cluster Log API (authentifiziert via Keycloak)."""

    def __init__(
        self,
        api_url: str,
        keycloak_url: str,
        client_id: str,
        client_secret: str,
        timeout: int = 30,
    ):
        self.api_url = api_url.rstrip("/")
        self.keycloak_url = keycloak_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.timeout = timeout
        self._token: str | None = None
        self._token_expires: datetime | None = None

    def _get_token(self) -> str:
        """Token von Keycloak holen (Client Credentials Flow)."""
        if self._token and self._token_expires and datetime.now(timezone.utc) < self._token_expires:
            return self._token

        response = httpx.post(
            f"{self.keycloak_url}/protocol/openid-connect/token",
            data={
                "grant_type": "client_credentials",
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()

        self._token = data["access_token"]
        # Token 30 Sekunden vor Ablauf erneuern
        expires_in = data.get("expires_in", 300)
        self._token_expires = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 30)

        return self._token

    def _headers(self) -> dict:
        return {"Authorization": f"Bearer {self._get_token()}"}

    def get_all_logs(
        self,
        duration: str = "1h",
        namespaces: list[str] | None = None,
    ) -> list[dict]:
        """Alle Logs eines Zeitraums abrufen."""
        if namespaces:
            ns_filter = "|".join(namespaces)
            query = f'{{namespace=~"{ns_filter}"}}'
        else:
            query = '{job="loki.source.kubernetes.pods"}'

        return self._query(query, duration)

    def get_errors(
        self,
        duration: str = "1h",
        namespaces: list[str] | None = None,
    ) -> list[dict]:
        """Nur Error-Logs abrufen (ueber den /errors Endpoint)."""
        params = {"duration": duration}
        if namespaces:
            params["namespaces"] = ",".join(namespaces)

        response = httpx.get(
            f"{self.api_url}/api/errors",
            params=params,
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return self._flatten_streams(response.json())

    def get_stats(self, duration: str = "1h") -> dict:
        """Statistiken abrufen."""
        response = httpx.get(
            f"{self.api_url}/api/stats",
            params={"duration": duration},
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return response.json()

    def _query(self, query: str, duration: str, limit: int = 5000) -> list[dict]:
        """Logs ueber die Log API abfragen."""
        params = {
            "query": query,
            "duration": duration,
            "limit": limit,
        }

        response = httpx.get(
            f"{self.api_url}/api/query",
            params=params,
            headers=self._headers(),
            timeout=self.timeout,
        )
        response.raise_for_status()
        return self._flatten_streams(response.json())

    @staticmethod
    def _flatten_streams(data: dict) -> list[dict]:
        """Loki Streams in eine flache Liste umwandeln."""
        logs = []
        results = data.get("data", {}).get("result", [])

        for stream in results:
            labels = stream.get("stream", {})
            for ts, line in stream.get("values", []):
                logs.append({
                    "timestamp": ts,
                    "line": line.strip(),
                    "namespace": labels.get("namespace", ""),
                    "pod": labels.get("pod", ""),
                    "container": labels.get("container", ""),
                    "node": labels.get("node", ""),
                    "level": labels.get("detected_level", ""),
                })

        logs.sort(key=lambda x: x["timestamp"])
        return logs
