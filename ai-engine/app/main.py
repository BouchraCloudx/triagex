"""API du moteur IA TriageX."""
import logging
from typing import Any

import httpx
from fastapi import FastAPI
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field

from .engine import Settings, run_triage
from .metrics import MetricsState
from .report import render_html

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s : %(message)s")

settings = Settings.from_env()
metrics = MetricsState(settings.data_dir)
app = FastAPI(title="TriageX AI Engine", version="1.2.0")


class TriageRequest(BaseModel):
    project: str = "triagex"
    build: str | None = None
    reports: dict[str, Any] = Field(default_factory=dict)
    sources: dict[str, str] = Field(default_factory=dict)


class ComplianceRequest(BaseModel):
    build: str | None = None
    drift_corrected: int = Field(ge=0)
    passed: bool


class DeploymentRequest(BaseModel):
    build: str
    image: str
    success: bool


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
    metrics.record_triage(result)
    result["html"] = render_html(result)
    return result


@app.post("/compliance")
def compliance(request: ComplianceRequest) -> dict:
    """Résultat du contrôle de conformité nocturne, publié par Jenkins."""
    metrics.record_compliance(request.build, request.drift_corrected, request.passed)
    return {"status": "recorded"}


@app.post("/deployment")
def deployment(request: DeploymentRequest) -> dict:
    """Résultat du déploiement Ansible, publié par Jenkins."""
    metrics.record_deployment(request.build, request.image, request.success)
    return {"status": "recorded"}


@app.get("/metrics", response_class=PlainTextResponse)
def prometheus_metrics() -> str:
    return metrics.render()
