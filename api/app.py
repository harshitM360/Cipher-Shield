from __future__ import annotations

from fastapi import FastAPI

from api.routes import router

app = FastAPI(
    title="Ransomware Copilot API",
    version="0.1.0",
    description="FastAPI layer for the explainable ransomware SOC copilot pipeline.",
)

app.include_router(router)
