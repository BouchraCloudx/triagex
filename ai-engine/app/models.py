"""Modèle de données commun à tous les scanners."""
from dataclasses import asdict, dataclass, field

SEVERITY_ORDER = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
PRIORITY_ORDER = {"critique": 0, "haute": 1, "moyenne": 2, "basse": 3, "ignorée": 4}
CODE_CATEGORIES = ("secret", "sast", "iac")
VULN_CATEGORIES = ("dependency", "image-os")


@dataclass
class Finding:
    tool: str                      # gitleaks, semgrep, trivy, checkov
    category: str                  # secret, sast, iac, dependency, image-os
    rule_id: str                   # règle, check ou identifiant de vulnérabilité
    title: str
    severity: str = "UNKNOWN"      # CRITICAL / HIGH / MEDIUM / LOW / UNKNOWN
    id: str = ""
    file: str | None = None
    line: int | None = None
    cve: str | None = None
    packages: list[str] = field(default_factory=list)
    installed_version: str | None = None
    fixed_version: str | None = None
    description: str = ""
    occurrences: int = 1
    related_rules: list[str] = field(default_factory=list)
    # Enrichissement
    epss: float | None = None
    kev: bool = False
    # Analyse IA
    ai_verdict: str | None = None  # true_positive / false_positive / needs_review
    ai_confidence: float | None = None
    ai_explanation: str = ""
    ai_fix: str = ""
    # Décision
    score: int = 0
    priority: str = ""
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)
