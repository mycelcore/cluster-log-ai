import uvicorn
from fastapi import FastAPI

from api import router

app = FastAPI(
    title="Cluster Log API",
    description="Authentifizierter Zugang zu Cluster-Logs via Loki",
    version="0.1.0",
)

app.include_router(router)


@app.get("/health")
def health():
    return {"status": "ok"}


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
