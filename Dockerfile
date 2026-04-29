FROM python:3.12-slim

WORKDIR /app

# System-Pakete (psycopg[binary] braucht eigentlich nichts, aber libpq ist
# trotzdem hilfreich falls wir mal auf das non-binary Wheel umsteigen).
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpq5 \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py ./

RUN useradd --create-home appuser
USER appuser

# config.yaml wird per Volume-Mount bereitgestellt (siehe compose.yaml)
ENTRYPOINT ["python", "-u", "main.py"]
CMD ["/app/config/config.yaml"]
