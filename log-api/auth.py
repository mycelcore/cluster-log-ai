import httpx
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError

from config import settings

security = HTTPBearer()

_jwks_cache: dict | None = None


async def _get_jwks() -> dict:
    """JWKS von Keycloak abrufen und cachen."""
    global _jwks_cache
    if _jwks_cache is None:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"{settings.keycloak_url}/protocol/openid-connect/certs",
                timeout=10,
            )
            response.raise_for_status()
            _jwks_cache = response.json()
    return _jwks_cache


async def _refresh_jwks() -> dict:
    """JWKS-Cache invalidieren und neu laden."""
    global _jwks_cache
    _jwks_cache = None
    return await _get_jwks()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Depends(security),
) -> dict:
    """JWT-Token gegen Keycloak validieren."""
    token = credentials.credentials

    try:
        jwks = await _get_jwks()
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Keycloak nicht erreichbar",
        )

    try:
        # Header lesen um den richtigen Key zu finden
        unverified_header = jwt.get_unverified_header(token)
        kid = unverified_header.get("kid")

        # Passenden Key aus JWKS suchen
        rsa_key = None
        for key in jwks.get("keys", []):
            if key["kid"] == kid:
                rsa_key = key
                break

        # Key nicht gefunden — JWKS refreshen (Key-Rotation)
        if rsa_key is None:
            jwks = await _refresh_jwks()
            for key in jwks.get("keys", []):
                if key["kid"] == kid:
                    rsa_key = key
                    break

        if rsa_key is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token-Key nicht gefunden",
            )

        # Token verifizieren
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=["RS256"],
            audience="account",
            issuer=settings.keycloak_url,
        )

        return payload

    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token ungueltig oder abgelaufen",
        )
