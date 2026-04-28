import httpx
from fastapi import APIRouter, Depends, HTTPException, Query
from datetime import datetime, timezone, timedelta

from auth import verify_token
from config import settings

router = APIRouter(prefix="/api", tags=["logs"])


@router.get("/query")
async def query_logs(
    query: str = Query(default='{job="loki.source.kubernetes.pods"}', description="LogQL Query"),
    duration: str = Query(default="1h", description="Zeitraum (z.B. 15m, 1h, 6h, 24h)"),
    limit: int = Query(default=5000, ge=1, le=50000),
    token: dict = Depends(verify_token),
):
    """Logs aus Loki abfragen per LogQL."""
    now = datetime.now(timezone.utc)
    start = now - _parse_duration(duration)

    params = {
        "query": query,
        "start": str(int(start.timestamp())),
        "end": str(int(now.timestamp())),
        "limit": limit,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.loki_url}/loki/api/v1/query_range",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Loki nicht erreichbar")
    except httpx.HTTPStatusError as e:
        raise HTTPException(status_code=e.response.status_code, detail="Loki Fehler")


@router.get("/namespaces")
async def list_namespaces(
    duration: str = Query(default="1h"),
    token: dict = Depends(verify_token),
):
    """Alle Namespaces mit Logs im Zeitraum auflisten."""
    now = datetime.now(timezone.utc)
    start = now - _parse_duration(duration)

    params = {
        "query": '{job="loki.source.kubernetes.pods"}',
        "start": str(int(start.timestamp())),
        "end": str(int(now.timestamp())),
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.loki_url}/loki/api/v1/series",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            namespaces = set()
            for series in data.get("data", []):
                ns = series.get("namespace")
                if ns:
                    namespaces.add(ns)

            return {"namespaces": sorted(namespaces)}
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Loki nicht erreichbar")


@router.get("/errors")
async def get_errors(
    duration: str = Query(default="1h"),
    namespaces: str = Query(default="", description="Komma-separierte Namespaces (leer = alle)"),
    limit: int = Query(default=1000, ge=1, le=10000),
    token: dict = Depends(verify_token),
):
    """Nur Error/Fatal/Panic Logs abrufen."""
    if namespaces:
        ns_filter = "|".join(namespaces.split(","))
        query = f'{{namespace=~"{ns_filter}"}} |~ "(?i)(error|fatal|panic|critical)"'
    else:
        query = '{job="loki.source.kubernetes.pods"} |~ "(?i)(error|fatal|panic|critical)"'

    now = datetime.now(timezone.utc)
    start = now - _parse_duration(duration)

    params = {
        "query": query,
        "start": str(int(start.timestamp())),
        "end": str(int(now.timestamp())),
        "limit": limit,
    }

    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.loki_url}/loki/api/v1/query_range",
                params=params,
                timeout=30,
            )
            response.raise_for_status()
            return response.json()
    except httpx.ConnectError:
        raise HTTPException(status_code=503, detail="Loki nicht erreichbar")


@router.get("/stats")
async def get_stats(
    duration: str = Query(default="1h"),
    token: dict = Depends(verify_token),
):
    """Statistiken ueber die Logs im Zeitraum."""
    now = datetime.now(timezone.utc)
    start = now - _parse_duration(duration)

    stats = {}

    async with httpx.AsyncClient() as client:
        # Gesamtanzahl Streams
        try:
            response = await client.get(
                f"{settings.loki_url}/loki/api/v1/series",
                params={
                    "query": '{job="loki.source.kubernetes.pods"}',
                    "start": str(int(start.timestamp())),
                    "end": str(int(now.timestamp())),
                },
                timeout=30,
            )
            response.raise_for_status()
            series = response.json().get("data", [])

            namespaces = set()
            pods = set()
            nodes = set()
            for s in series:
                namespaces.add(s.get("namespace", ""))
                pods.add(s.get("pod", ""))
                nodes.add(s.get("node", ""))

            stats["active_streams"] = len(series)
            stats["namespaces"] = sorted(namespaces - {""})
            stats["pods"] = len(pods - {""})
            stats["nodes"] = sorted(nodes - {""})

        except Exception:
            stats["error"] = "Loki nicht erreichbar"

    return stats


def _parse_duration(duration: str) -> timedelta:
    """Duration-String in timedelta umwandeln."""
    value = int(duration[:-1])
    unit = duration[-1]
    if unit == "m":
        return timedelta(minutes=value)
    elif unit == "h":
        return timedelta(hours=value)
    elif unit == "d":
        return timedelta(days=value)
    raise HTTPException(status_code=400, detail=f"Ungueltiges Zeitformat: {duration}")
