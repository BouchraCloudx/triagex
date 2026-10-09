"""Analyse d'une alerte par le LLM local (Ollama). Le code ne quitte jamais l'infrastructure."""
import json
import logging
import time

import httpx

from .models import Finding

log = logging.getLogger("triagex.llm")

VERDICTS = {"true_positive", "false_positive", "needs_review"}

# Un petit modèle confond facilement "la règle est violée" et "la règle est fausse".
# On ne lui demande donc plus de classer l'alerte, mais de répondre à UNE question
# factuelle et simple sur le code (oui / non), adaptée à chaque catégorie.
SYSTEM_PROMPT = """You are a senior application security engineer who verifies findings from security scanners.
Scanners are usually right: on real code, most findings are real.
Only answer false if the code shown clearly proves the finding is wrong.
Answer ONLY with a JSON object containing exactly these keys:
"real_issue": true or false (your answer to the question),
"confidence": a number between 0 and 1,
"explanation": one or two short sentences in French justifying your answer,
"fix": one short sentence in French describing how to fix the issue."""

INJECTION_MARKERS = ("injection", "sqli", "sql", "tainted", "xss", "ssrf", "path-traversal",
                     "command", "subprocess", "deserializ", "eval", "exec")

QUESTIONS = {
    "sast_config": ("Question: does the code shown really contain the insecure pattern or "
                    "configuration described by the rule and its message (for example "
                    "debug=True, binding to 0.0.0.0, a weak algorithm, a disabled check)? "
                    "Answer true if the pattern is present in the code."),
    "sast": ("Question: in the code shown, does data controlled by the user (for example "
             "request.args, request.form or request.data) reach the dangerous operation "
             "described by the rule without proper validation or escaping? "
             "String concatenation into a SQL query or a shell command is NOT safe."),
    "secret": ("Question: is this a real credential written directly in the code "
               "(not an empty value, a placeholder like 'changeme', or an environment variable)?"),
    "dependency": ("Question: is this library used by the application? Answer true if it is "
                   "imported in the code, listed in requirements.txt, or used by a framework the "
                   "application uses (Flask uses Werkzeug, Jinja2, MarkupSafe and itsdangerous)."),
}


def question_key(f: Finding) -> str:
    """Les règles d'injection portent sur le trajet d'une donnée utilisateur ;
    les règles d'audit (debug, host, cryptographie...) portent sur la présence d'un motif."""
    if f.category != "sast":
        return f.category if f.category in QUESTIONS else "sast_config"
    rule = f.rule_id.lower()
    return "sast" if any(marker in rule for marker in INJECTION_MARKERS) else "sast_config"


def build_prompt(f: Finding, context: str) -> str:
    lines = [
        f"Outil : {f.tool}",
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
    lines.append("")
    lines.append(QUESTIONS[question_key(f)])
    return "\n".join(lines)


def _to_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "yes", "oui"):
        return True
    if isinstance(value, str) and value.strip().lower() in ("false", "no", "non"):
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
        data = _chat(ollama_url, payload, timeout)
        real_issue = _to_bool(data.get("real_issue"))
        verdict = {True: "true_positive", False: "false_positive"}.get(real_issue, "needs_review")
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
