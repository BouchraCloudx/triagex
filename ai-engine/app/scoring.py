"""Score de risque réel (0 à 100) et priorité de chaque alerte.

Principe final, tiré des mesures sur TriageX : le second avis d'un petit modèle local n'est pas
assez fiable pour décider seul. L'IA ne cache donc JAMAIS une alerte. Elle peut :
- renforcer une alerte de code qu'elle confirme ;
- contester une alerte : celle-ci reste visible, avec son explication, et seules les alertes
  de sévérité moyenne ou basse perdent un peu de priorité ;
les vulnérabilités des dépendances et de l'image sont classées sans IA, avec des données
fiables : sévérité, probabilité d'exploitation (EPSS), exploitation avérée (CISA KEV) et
existence d'un correctif.
"""
from .models import CODE_CATEGORIES, Finding

SEVERITY_POINTS = {"CRITICAL": 40, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "UNKNOWN": 5}

# Code (Semgrep, Checkov)
AI_CONFIRMED_BONUS = 20      # l'IA confirme : jusqu'à +20 selon sa confiance
NOT_CONFIRMED_BONUS = 10     # pas d'avis, avis indécis, ou faille grave contestée
SEVERE = ("HIGH", "CRITICAL")

# Vulnérabilités (Trivy)
VULN_SEVERITY_WEIGHT = 0.8   # la sévérité théorique seule ne rend pas une CVE prioritaire
EPSS_WEIGHT = 60             # EPSS de 0,5 = +30 points
DIRECT_DEPENDENCY_BONUS = 10  # bibliothèque déclarée par l'équipe, qu'elle peut mettre à jour
NO_FIX_CAP = 35              # sans correctif disponible : à surveiller, pas à traiter en urgence


def priority_from_score(score: float) -> str:
    if score >= 60:
        return "critique"
    if score >= 40:
        return "haute"
    if score >= 20:
        return "moyenne"
    return "basse"


def _score_code(f: Finding, base: int) -> float:
    if f.ai_verdict == "true_positive":
        return base + AI_CONFIRMED_BONUS * (f.ai_confidence or 0)
    if f.ai_verdict == "false_positive":
        if f.severity in SEVERE:
            f.notes.append("L'IA conteste cette alerte, mais une faille grave n'est jamais "
                           "rétrogradée sur son seul avis : vérification humaine conseillée.")
            return base + NOT_CONFIRMED_BONUS
        f.notes.append("L'IA conteste cette alerte : elle reste visible, à vérifier.")
        return base
    return base + NOT_CONFIRMED_BONUS


def _score_vulnerability(f: Finding, base: int) -> float:
    score = base * VULN_SEVERITY_WEIGHT + EPSS_WEIGHT * (f.epss or 0)
    if f.category == "dependency":
        score += DIRECT_DEPENDENCY_BONUS
    if f.kev:
        f.notes.append("Exploitée activement (catalogue CISA KEV).")
        return max(score, 60)  # exploitée par des attaquants : toujours critique
    if not f.fixed_version:
        f.notes.append("Aucun correctif disponible : à surveiller.")
        return min(score, NO_FIX_CAP)
    return score


def score_finding(f: Finding) -> None:
    f.notes = []
    base = SEVERITY_POINTS.get(f.severity, 5)
    if f.category == "secret":
        score = 100  # un secret dans le code est toujours critique, quel que soit l'avis de l'IA
        if f.ai_verdict == "false_positive":
            f.notes.append("L'IA pense à une fausse alerte, mais un secret n'est jamais levé "
                           "automatiquement : vérification humaine requise.")
    elif f.category in CODE_CATEGORIES:
        score = _score_code(f, base)
    else:
        score = _score_vulnerability(f, base)
    f.score = round(min(score, 100))
    f.priority = priority_from_score(score)
