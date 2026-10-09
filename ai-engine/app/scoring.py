"""Calcul du score de risque réel (0 à 100) et de la priorité de chaque alerte.

Règles volontairement simples et explicables :
- secrets : toujours critiques, l'IA ne peut jamais lever ce blocage ;
- code (SAST, IaC) : sévérité + confiance de l'IA ; un faux positif confirmé est ignoré ;
- vulnérabilités (CVE) : la sévérité théorique compte moins que la probabilité réelle
  d'exploitation (EPSS), l'exploitation avérée (CISA KEV) et la confirmation par l'IA
  que le code vulnérable est réellement utilisé par l'application.
"""
from .models import CODE_CATEGORIES, Finding

SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 5}
VULN_SEVERITY_WEIGHT = 0.8   # la sévérité seule ne suffit pas à rendre une CVE prioritaire
EPSS_WEIGHT = 60             # EPSS de 0,5 = +30 points
DIRECT_DEPENDENCY_BONUS = 5  # bibliothèque déclarée par l'équipe, qu'elle peut corriger elle-même
AI_CONFIRMED_BONUS = 15      # l'IA confirme que le code vulnérable est utilisé
# Garde-fou : l'IA ne peut écarter une alerte que si elle est presque certaine.
# Dans le doute, l'alerte reste visible : cacher une vraie faille est pire qu'une alerte de trop.
MIN_CONFIDENCE_TO_DISMISS = 0.9
UNCERTAIN_CODE_BONUS = 10    # alerte de code non confirmée : on garde la sévérité du scanner


def ai_dismisses(f: Finding) -> bool:
    return f.ai_verdict == "false_positive" and (f.ai_confidence or 0) >= MIN_CONFIDENCE_TO_DISMISS


def priority_from_score(score: float) -> str:
    if score >= 60:
        return "critique"
    if score >= 40:
        return "haute"
    if score >= 20:
        return "moyenne"
    return "basse"


def score_finding(f: Finding) -> None:
    f.notes = []
    base = SEVERITY_POINTS.get(f.severity, 5)

    if f.category == "secret":
        f.score, f.priority = 100, "critique"
        if f.ai_verdict == "false_positive":
            f.notes.append("L'IA pense à un faux positif, mais un secret n'est jamais levé "
                           "automatiquement : vérification humaine requise.")
        return

    if f.category in CODE_CATEGORIES:
        if ai_dismisses(f):
            f.score, f.priority = 0, "ignorée"
            return
        if f.ai_verdict == "true_positive":
            bonus = 20 * (f.ai_confidence or 0)
        else:
            bonus = UNCERTAIN_CODE_BONUS
            if f.ai_verdict == "false_positive":
                f.notes.append("L'IA doute de cette alerte, mais pas assez pour l'écarter : "
                               "vérification humaine conseillée.")
        f.score = round(base + bonus)
        f.priority = priority_from_score(f.score)
        return

    # Vulnérabilités des dépendances et de l'image
    score = base * VULN_SEVERITY_WEIGHT + EPSS_WEIGHT * (f.epss or 0)
    if f.category == "dependency":
        score += DIRECT_DEPENDENCY_BONUS
    if f.ai_verdict == "true_positive":
        score += AI_CONFIRMED_BONUS * (f.ai_confidence or 0)
        f.notes.append("L'IA confirme que le code vulnérable est utilisé par l'application.")
    if f.kev:
        score = max(score, 60)  # exploitée activement par des attaquants : toujours critique
        f.notes.append("Exploitée activement (catalogue CISA KEV).")
    else:
        if not f.fixed_version:
            score = min(score, 35)
            f.notes.append("Aucun correctif disponible : à surveiller.")
        if ai_dismisses(f):
            score = min(score, 15)
            f.notes.append("L'IA estime la faille non exploitable dans ce code.")
    f.score = round(min(score, 100))
    f.priority = priority_from_score(score)
