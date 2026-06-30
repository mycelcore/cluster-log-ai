from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    # Loki
    loki_url: str = "http://loki.monitoring.svc.cluster.local:3100"
    # LogQL-Selector fuer alle Logs. Default matcht alle Jobs.
    # Fuer Alloy/loki.source: '{job="loki.source.kubernetes.pods"}'
    # Fuer Promtail (namespace/app): '{job=~".+"}'
    loki_selector: str = '{job=~".+"}'

    # Keycloak
    keycloak_url: str = "https://auth.energiesynergie.de/realms/ensy"

    class Config:
        env_prefix = "LOG_API_"


settings = Settings()
