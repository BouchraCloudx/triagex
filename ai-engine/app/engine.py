"""Orchestration du triage : normaliser, dédupliquer, enrichir, second avis de l'IA, prioriser, décider."""
import logging
import os
import time
from dataclasses import dataclass

from .context import code_context
from .enrich import fetch_epss, load_kev
from .llm import analyze
from .models import PRIORITY_ORDER
from .normalize import dedupe, normalize_all
from .scoring import score_finding

log = logging.getLogger("triagex.engine")

# Seules les alertes sur le code de l'équipe passent par l'IA. Les contrôles Checkov sont des
# règles déterministes, et les CVE des dépendances sont mieux classées par EPSS, KEV et la
# disponibilité d'un correctif : mesuré sur TriageX, le petit modèle les rejetait toutes à tort.
AI_CATEGORIES = ("secret", "sast")


@dataclass
class Settings:
    ollama_url: str = "http://127.0.0.1:11434"
    model: str = "qwen2.5-coder:3b"
    max_llm_findings: int = 20
    llm_timeout: float = 300
    data_dir: str = "/data"

    @classmethod
    def from_env(cls) -> "Settings":
        return cls(
            ollama_url=os.environ.get("OLLAMA_URL", cls.ollama_url).rstrip("/"),
            model=os.environ.get("OLLAMA_MODEL", cls.model),
            max_llm_findings=int(os.environ.get("MAX_LLM_FINDINGS", cls.max_llm_findings)),
            llm_timeout=float(os.environ.get("LLM_TIMEOUT", cls.llm_timeout)),
            data_dir=os.environ.get("DATA_DIR", cls.data_dir),
        )


def run_triage(reports: dict, sources: dict, settings: Settings) -> dict:
    started = time.time()

    # 1. Normalisation et déduplication
    raw, raw_counts = normalize_all(reports)
    findings = dedupe(raw)

    # 2. Enrichissement des CVE
    kev = load_kev(settings.data_dir)
    epss = fetch_epss([f.cve for f in findings if f.cve])
    for f in findings:
        if f.cve:
            f.epss = epss.get(f.cve)
            f.kev = f.cve in kev

    # 3. Second avis de l'IA sur le code (les plus graves d'abord si le budget est atteint)
    code = [f for f in findings if f.category in AI_CATEGORIES]
    for f in code:
        score_finding(f)
    code.sort(key=lambda f: -f.score)
    candidates = code[: settings.max_llm_findings]
    for index, f in enumerate(candidates, start=1):
        log.info("Analyse IA %d/%d : %s %s", index, len(candidates), f.id, f.rule_id)
        analyze(f, code_context(sources, f.file, f.line), settings.ollama_url,
                settings.model, settings.llm_timeout)

    # 4. Score final et tri
    for f in findings:
        score_finding(f)
    findings.sort(key=lambda f: (PRIORITY_ORDER.get(f.priority, 9), -f.score, f.id))

    # 5. Quality gate : bloquer uniquement les risques réellement critiques
    blocking = [f for f in findings if f.priority == "critique"]
    by_priority = {p: sum(1 for f in findings if f.priority == p) for p in PRIORITY_ORDER}
    raw_total = sum(raw_counts.values())
    actionable = by_priority["critique"] + by_priority["haute"]

    summary = {
        "raw_counts": raw_counts,
        "raw_total": raw_total,
        "unique_total": len(findings),
        "by_priority": by_priority,
        "actionable": actionable,
        "reduction_percent": round(100 * (1 - actionable / raw_total), 1) if raw_total else 0.0,
        "ai_analyzed": len(candidates),
        "ai_confirmed": sum(1 for f in candidates if f.ai_verdict == "true_positive"),
        "ai_contested": sum(1 for f in candidates if f.ai_verdict == "false_positive"),
        "ai_undecided": sum(1 for f in candidates if f.ai_verdict == "needs_review"),
        "kev_loaded": bool(kev),
        "epss_scores": len(epss),
        "model": settings.model,
        "duration_seconds": round(time.time() - started, 1),
    }
    gate = {
        "passed": not blocking,
        "blocking": [f"{f.id} {f.title}" for f in blocking],
        "rule": "Échec si au moins une alerte est de priorité critique (secrets toujours critiques).",
    }
    return {"summary": summary, "gate": gate, "findings": [f.to_dict() for f in findings]}
