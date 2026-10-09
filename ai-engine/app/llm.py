"""Analyse d'une alerte par le LLM local (Ollama). Le code ne quitte jamais l'infrastructure."""
import json
import logging

import httpx

from .models import Finding

log = logging.getLogger("triagex.llm")

VERDICTS = {"true_positive", "false_positive", "needs_review"}

SYSTEM_PROMPT = """You are an application security expert helping a DevSecOps team triage scanner findings.
For each finding, decide whether it is a real and exploitable issue in the code shown.
- true_positive: the issue is real and reachable in this code.
- false_positive: the scanner is wrong, or the vulnerable code is never used.
- needs_review: you cannot decide from the information given.
Answer ONLY with a JSON object containing exactly these keys:
"verdict": "true_positive" | "false_positive" | "needs_review",
"confidence": a number between 0 and 1,
"explanation": one or two short sentences in French explaining your decision,
"fix": one short sentence in French describing how to fix the issue."""


def build_prompt(f: Finding, context: str) -> str:
    lines = [
        f"Outil : {f.tool}",
        f"Catégorie : {f.category}",
        f"Règle : {f.rule_id}",
        f"Titre : {f.title}",
        f"Sévérité déclarée : {f.severity}",
    ]
    if f.file:
        lines.append(f"Fichier : {f.file} (ligne {f.line})")
    if f.packages:
        lines.append(f"Paquet : {', '.join(f.packages)} {f.installed_version or ''} "
                     f"(corrigé en : {f.fixed_version or 'aucun correctif'})")
    if f.description:
        lines.append(f"Description : {f.description[:600]}")
    lines.append("Code concerné :")
    lines.append(context or "(non disponible)")
    return "\n".join(lines)


def analyze(f: Finding, context: str, ollama_url: str, model: str, timeout: float = 300) -> None:
    """Complète l'alerte avec le verdict de l'IA. En cas d'échec : needs_review."""
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        "options": {"temperature": 0, "num_ctx": 2048},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(f, context)},
        ],
    }
    try:
        response = httpx.post(f"{ollama_url}/api/chat", json=payload, timeout=timeout)
        response.raise_for_status()
        data = json.loads(response.json()["message"]["content"])
        verdict = str(data.get("verdict", "")).strip().lower()
        if verdict not in VERDICTS:
            verdict = "needs_review"
        try:
            confidence = min(max(float(data.get("confidence", 0.5)), 0.0), 1.0)
        except (TypeError, ValueError):
            confidence = 0.5
        f.ai_verdict = verdict
        f.ai_confidence = round(confidence, 2)
        f.ai_explanation = str(data.get("explanation", ""))[:500]
        f.ai_fix = str(data.get("fix", ""))[:300]
    except Exception as exc:
        log.warning("Analyse IA impossible pour %s : %s", f.id, exc)
        f.ai_verdict = "needs_review"
        f.ai_confidence = None
        f.ai_explanation = f"Analyse IA indisponible ({type(exc).__name__}) : vérification humaine requise."
