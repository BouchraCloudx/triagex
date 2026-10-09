"""Conversion des rapports des scanners vers un format commun, puis déduplication."""
from .models import SEVERITY_ORDER, VULN_CATEGORIES, Finding

PATH_PREFIXES = ("/repo/", "/src/")
SEMGREP_SEVERITY = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


def clean_path(path: str | None) -> str | None:
    """Retire le préfixe du conteneur (/repo, /src) pour obtenir un chemin relatif au dépôt."""
    if not path:
        return None
    for prefix in PATH_PREFIXES:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break
    return path.lstrip("/")


def _severity(value, default="MEDIUM") -> str:
    value = str(value or "").upper()
    return value if value in SEVERITY_ORDER else default


def from_gitleaks(data) -> list[Finding]:
    findings = []
    for item in data or []:
        secret = str(item.get("Secret", ""))
        masked = f"{secret[:4]}****" if secret else "****"
        rule = item.get("RuleID", "secret")
        findings.append(Finding(
            tool="gitleaks", category="secret", rule_id=rule,
            title=item.get("Description") or "Secret détecté dans le code",
            severity="CRITICAL",
            file=clean_path(item.get("File")), line=item.get("StartLine"),
            description=f"Secret potentiel ({masked}) détecté par la règle {rule}.",
        ))
    return findings


def from_semgrep(data) -> list[Finding]:
    findings = []
    for result in (data or {}).get("results", []) or []:
        extra = result.get("extra", {}) or {}
        check_id = result.get("check_id", "semgrep")
        findings.append(Finding(
            tool="semgrep", category="sast", rule_id=check_id,
            title=check_id.split(".")[-1].replace("-", " "),
            severity=SEMGREP_SEVERITY.get(str(extra.get("severity", "")).upper(), "MEDIUM"),
            file=clean_path(result.get("path")),
            line=(result.get("start") or {}).get("line"),
            description=str(extra.get("message", ""))[:800],
        ))
    return findings


def from_trivy(data) -> list[Finding]:
    """Fonctionne pour le scan des dépendances (fs) comme pour celui de l'image."""
    findings = []
    for result in (data or {}).get("Results", []) or []:
        category = "image-os" if result.get("Class") == "os-pkgs" else "dependency"
        for vuln in result.get("Vulnerabilities") or []:
            vuln_id = vuln.get("VulnerabilityID", "UNKNOWN")
            findings.append(Finding(
                tool="trivy", category=category, rule_id=vuln_id,
                title=vuln.get("Title") or vuln_id,
                severity=_severity(vuln.get("Severity"), "UNKNOWN"),
                cve=vuln_id if vuln_id.startswith("CVE-") else None,
                packages=[vuln.get("PkgName", "?")],
                installed_version=vuln.get("InstalledVersion"),
                fixed_version=vuln.get("FixedVersion") or None,
                description=str(vuln.get("Description", ""))[:800],
            ))
    return findings


def from_checkov(data) -> list[Finding]:
    blocks = data if isinstance(data, list) else ([data] if data else [])
    findings = []
    for block in blocks:
        for check in ((block or {}).get("results") or {}).get("failed_checks", []) or []:
            line_range = check.get("file_line_range") or [None]
            findings.append(Finding(
                tool="checkov", category="iac", rule_id=check.get("check_id", "checkov"),
                title=check.get("check_name") or check.get("check_id", "Checkov"),
                severity=_severity(check.get("severity"), "MEDIUM"),
                file=clean_path(check.get("repo_file_path") or check.get("file_path")),
                line=line_range[0],
                description=str(check.get("guideline") or ""),
            ))
    return findings


PARSERS = {
    "gitleaks": from_gitleaks,
    "semgrep": from_semgrep,
    "trivy_fs": from_trivy,
    "checkov": from_checkov,
    "trivy_image": from_trivy,
}


def normalize_all(reports: dict) -> tuple[list[Finding], dict]:
    """Retourne toutes les alertes brutes et leur nombre par rapport."""
    findings, raw_counts = [], {}
    for name, parser in PARSERS.items():
        try:
            items = parser(reports.get(name))
        except Exception:  # un rapport illisible ne doit pas bloquer les autres
            items = []
        raw_counts[name] = len(items)
        findings.extend(items)
    return findings, raw_counts


def _dedup_key(f: Finding) -> tuple:
    if f.category in VULN_CATEGORIES:
        # Une même CVE dans plusieurs paquets système = un seul problème à corriger
        # Une même CVE de bibliothèque vue par le scan fs ET le scan image = un seul problème
        target = f.packages[0] if f.category == "dependency" else "os"
        return ("vuln", f.category, f.rule_id, target)
    if f.category == "sast":
        # Plusieurs règles qui signalent la même ligne = une seule faille
        return ("sast", f.file, f.line)
    return (f.tool, f.rule_id, f.file, f.line)


def dedupe(findings: list[Finding]) -> list[Finding]:
    merged: dict[tuple, Finding] = {}
    for f in findings:
        key = _dedup_key(f)
        existing = merged.get(key)
        if existing is None:
            merged[key] = f
            continue
        existing.occurrences += 1
        for pkg in f.packages:
            if pkg not in existing.packages:
                existing.packages.append(pkg)
        if f.rule_id != existing.rule_id and f.rule_id not in existing.related_rules:
            existing.related_rules.append(f.rule_id)
        if SEVERITY_ORDER[f.severity] > SEVERITY_ORDER[existing.severity]:
            existing.severity = f.severity
        if not existing.fixed_version and f.fixed_version:
            existing.fixed_version = f.fixed_version
    result = list(merged.values())
    for index, f in enumerate(result, start=1):
        f.id = f"TX-{index:04d}"
    return result
