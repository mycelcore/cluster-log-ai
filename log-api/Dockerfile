FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY *.py .

RUN useradd --create-home appuser
USER appuser

EXPOSE 8000

ENTRYPOINT ["python", "main.py"]
