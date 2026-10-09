"""API du moteur IA TriageX."""
import logging
from typing import Any

import httpx
from fastapi import FastAPI
from pydantic import BaseModel, Field

from .engine import Settings, run_triage
from .report import render_html

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")

settings = Settings.from_env()
app = FastAPI(title="TriageX AI Engine", version="1.0.0")


class TriageRequest(BaseModel):
    project: str = "triagex"
    build: str | None = None
    reports: dict[str, Any] = Field(default_factory=dict)
    sources: dict[str, str] = Field(default_factory=dict)


@app.get("/health")
def health() -> dict:
    try:
        response = httpx.get(f"{settings.ollama_url}/api/tags", timeout=5)
        models = [m.get("name") for m in response.json().get("models", [])]
        ollama_ok = True
    except Exception:
        models, ollama_ok = [], False
    return {
        "status": "ok",
        "ollama": ollama_ok,
        "model": settings.model,
        "model_available": settings.model in models,
    }


@app.post("/triage")
def triage(request: TriageRequest) -> dict:
    # Fonction synchrone : FastAPI l'exécute dans un thread, l'API reste disponible
    result = run_triage(request.reports, request.sources, settings)
    result["project"] = request.project
    result["build"] = request.build
    result["html"] = render_html(result)
    return result
