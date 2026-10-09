"""Second avis du LLM local (Ollama) sur une alerte de code. Le code ne quitte jamais l'infrastructure.

Leçons tirées des mesures sur TriageX, appliquées ici :
- un petit modèle répond mieux à UNE question factuelle qu'à un classement "vrai/faux positif" ;
- la question dépend du type de règle (trajet d'une donnée utilisateur, ou présence d'un motif) ;
- le prompt doit être neutre : dire "les scanners ont souvent raison" pousse le modèle à tout
  confirmer, dire l'inverse le pousse à tout rejeter ;
- le modèle explique AVANT de répondre (l'ordre des clés JSON guide son raisonnement) ;
- sa confiance déclarée n'est pas fiable : elle n'est jamais utilisée pour cacher une alerte
  (voir scoring.py).
"""
import json
import logging
import time

import httpx

from .models import Finding

log = logging.getLogger("triagex.llm")

SYSTEM_PROMPT = """You are a senior application security engineer reviewing findings from automated security scanners.
Scanners report both real problems and false alarms. Judge each finding only from the code shown, without assuming either outcome.
Answer ONLY with a JSON object containing exactly these keys, in this order:
"explanation": one or two short sentences in French describing what the code actually does,
"real_issue": true or false, your answer to the question,
"confidence": a number between 0 and 1,
"fix": one short sentence in French describing how to fix the issue, or an empty string if there is no issue."""

# Règles qui portent sur le trajet d'une donnée (source utilisateur -> opération dangereuse)
INJECTION_MARKERS = ("injection", "sqli", "sql", "tainted", "xss", "ssrf", "traversal",
                     "command", "subprocess", "deserializ", "pickle", "yaml", "eval", "exec",
                     "redirect", "template")

QUESTIONS = {
    "sast": (
        "Question: in the code shown, can text controlled by a user (for example request.args, "
        "request.form, request.data or a URL parameter) reach the dangerous operation described "
        "by the rule in a form an attacker can exploit? Check where the value comes from and "
        "whether it is validated, escaped, converted to a safe type or replaced by a constant "
        "before it is used."
    ),
    "sast_config": (
        "Question: does the code shown contain the insecure pattern described by the rule AND is "
        "it used in a security-sensitive way? For example a weak hash is a problem for passwords, "
        "tokens or signatures, but not for a cache key or a file checksum; debug mode or binding "
        "to 0.0.0.0 is a problem for a server that can be reached by others."
    ),
    "secret": (
        "Question: is this a real credential written directly in the code (not an empty value, "
        "an obvious placeholder, a test value, or a value read from the environment)?"
    ),
}

VERDICT_FROM_ANSWER = {True: "true_positive", False: "false_positive"}


def question_key(f: Finding) -> str:
    if f.category == "secret":
        return "secret"
    rule = f.rule_id.lower()
    return "sast" if any(marker in rule for marker in INJECTION_MARKERS) else "sast_config"


def build_prompt(f: Finding, context: str) -> str:
    lines = [
        f"Tool: {f.tool}",
        f"Rule: {f.rule_id}",
        f"Title: {f.title}",
        f"Declared severity: {f.severity}",
    ]
    if f.file:
        lines.append(f"File: {f.file} (line {f.line})")
    if f.description:
        lines.append(f"Scanner message: {f.description[:500]}")
    lines += ["Code:", context or "(not available)", "", QUESTIONS[question_key(f)]]
    return "\n".join(lines)


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        text = value.strip().lower()
        if text in ("true", "yes", "oui"):
            return True
        if text in ("false", "no", "non"):
            return False
    return None


def _chat(ollama_url: str, payload: dict, timeout: float, retries: int = 2) -> dict:
    """Appel à Ollama, avec nouvelles tentatives si le service redémarre."""
    for attempt in range(retries + 1):
        try:
            response = httpx.post(f"{ollama_url}/api/chat", json=payload, timeout=timeout)
            response.raise_for_status()
            return json.loads(response.json()["message"]["content"])
        except (httpx.ConnectError, httpx.RemoteProtocolError) as exc:
            if attempt == retries:
                raise
            log.warning("Ollama indisponible (%s), nouvelle tentative dans 15 s", exc)
            time.sleep(15)
    raise RuntimeError("unreachable")


def analyze(f: Finding, context: str, ollama_url: str, model: str, timeout: float = 300) -> None:
    """Complète l'alerte avec le second avis de l'IA. En cas d'échec : needs_review."""
    payload = {
        "model": model,
        "stream": False,
        "format": "json",
        # num_predict plafonne la longueur de la réponse : analyses plus rapides sur CPU
        "options": {"temperature": 0, "num_ctx": 2048, "num_predict": 300},
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": build_prompt(f, context)},
        ],
    }
    try:
        data = _chat(ollama_url, payload, timeout)
        f.ai_verdict = VERDICT_FROM_ANSWER.get(_to_bool(data.get("real_issue")), "needs_review")
        try:
            f.ai_confidence = round(min(max(float(data.get("confidence", 0.5)), 0.0), 1.0), 2)
        except (TypeError, ValueError):
            f.ai_confidence = 0.5
        f.ai_explanation = str(data.get("explanation", ""))[:500]
        f.ai_fix = str(data.get("fix", ""))[:300]
    except Exception as exc:
        log.warning("Analyse IA impossible pour %s : %s", f.id, exc)
        f.ai_verdict = "needs_review"
        f.ai_confidence = None
        f.ai_explanation = f"Analyse IA indisponible ({type(exc).__name__}) : vérification humaine requise."
