"""Tests unitaires du moteur IA (sans réseau ni LLM : ils sont simulés)."""
import pytest

from app import engine as engine_module
from app.context import code_context
from app.engine import Settings, run_triage
from app.models import Finding
from app.normalize import clean_path, dedupe, normalize_all
from app.report import render_html
from app.scoring import score_finding

SOURCES = {
    "demo-app/app.py": "\n".join([
        "import sqlite3",
        "import subprocess",
        'API_TOKEN = "Zx9fK2mQ7xLp4RtV8nZ3wB6yHcT1aE5u"',
        "def ping(host):",
        '    return subprocess.check_output("ping -c 1 " + host, shell=True)',
    ]),
    "demo-app/requirements.txt": "pyyaml==5.3.1\n",
    "demo-app/Dockerfile": "FROM python:3.8-slim\nCMD [\"python\", \"app.py\"]\n",
}

REPORTS = {
    "gitleaks": [{"RuleID": "generic-api-key", "Description": "Generic API Key",
                  "File": "/repo/demo-app/app.py", "StartLine": 3,
                  "Secret": "Zx9fK2mQ7xLp4RtV8nZ3wB6yHcT1aE5u"}],
    "semgrep": {"results": [
        {"check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
         "path": "/src/demo-app/app.py", "start": {"line": 5},
         "extra": {"severity": "ERROR", "message": "shell=True is dangerous"}},
        {"check_id": "python.flask.security.injection.os-system-injection.os-system-injection",
         "path": "/src/demo-app/app.py", "start": {"line": 5},
         "extra": {"severity": "ERROR", "message": "command injection"}},
    ]},
    "trivy_fs": {"Results": [{"Target": "requirements.txt", "Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-14343", "PkgName": "PyYAML", "InstalledVersion": "5.3.1",
         "FixedVersion": "5.4", "Severity": "CRITICAL", "Title": "arbitrary code execution"}]}]},
    "checkov": [{"check_type": "dockerfile", "results": {"failed_checks": [
        {"check_id": "CKV_DOCKER_3", "check_name": "Ensure that a user for the container has been created",
         "file_path": "/Dockerfile", "repo_file_path": "/src/demo-app/Dockerfile",
         "file_line_range": [1, 2], "severity": None}]}}],
    "trivy_image": {"Results": [
        {"Target": "triagex-demo (debian 12)", "Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-0001", "PkgName": "libssl3", "InstalledVersion": "1",
             "Severity": "HIGH", "Title": "openssl issue"},
            {"VulnerabilityID": "CVE-2023-0001", "PkgName": "openssl", "InstalledVersion": "1",
             "Severity": "HIGH", "Title": "openssl issue"},
            {"VulnerabilityID": "CVE-2021-3999", "PkgName": "libc6", "InstalledVersion": "2.36",
             "FixedVersion": "2.36-9", "Severity": "HIGH", "Title": "glibc off-by-one"},
        ]},
        {"Target": "Python", "Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2020-14343", "PkgName": "PyYAML", "InstalledVersion": "5.3.1",
             "FixedVersion": "5.4", "Severity": "CRITICAL", "Title": "arbitrary code execution"}]},
    ]},
}


def fake_llm(verdicts):
    """Remplace l'appel à Ollama par des réponses prédéfinies (par règle)."""
    def _analyze(f, context, url, model, timeout=300):
        verdict = verdicts.get(f.rule_id, "true_positive")
        f.ai_verdict, f.ai_confidence = verdict, 0.9
        f.ai_explanation, f.ai_fix = f"verdict simulé : {verdict}", "correctif simulé"
    return _analyze


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_module, "load_kev", lambda data_dir: {"CVE-2021-3999"})
    monkeypatch.setattr(engine_module, "fetch_epss",
                        lambda cves: {"CVE-2020-14343": 0.05, "CVE-2023-0001": 0.001})
    return Settings(data_dir=str(tmp_path))


def test_clean_path():
    assert clean_path("/repo/demo-app/app.py") == "demo-app/app.py"
    assert clean_path("/src/demo-app/app.py") == "demo-app/app.py"
    assert clean_path(None) is None


def test_normalize_counts_every_raw_alert():
    findings, counts = normalize_all(REPORTS)
    assert counts == {"gitleaks": 1, "semgrep": 2, "trivy_fs": 1, "checkov": 1, "trivy_image": 4}
    assert len(findings) == 9


def test_dedupe_merges_duplicates():
    findings, _ = normalize_all(REPORTS)
    unique = dedupe(findings)
    # 2 règles Semgrep sur la même ligne -> 1 ; même CVE dans 2 paquets OS -> 1 ;
    # PyYAML vue par le scan fs et le scan image -> 1
    assert len(unique) == 6
    os_vuln = next(f for f in unique if f.rule_id == "CVE-2023-0001")
    assert sorted(os_vuln.packages) == ["libssl3", "openssl"]
    assert all(f.id.startswith("TX-") for f in unique)


def test_secret_is_always_critical_even_if_ai_disagrees():
    f = Finding(tool="gitleaks", category="secret", rule_id="x", title="t", severity="CRITICAL",
                ai_verdict="false_positive", ai_confidence=0.99)
    score_finding(f)
    assert f.priority == "critique"
    assert f.notes


def test_minor_sast_false_positive_is_ignored():
    f = Finding(tool="semgrep", category="sast", rule_id="x", title="t", severity="MEDIUM",
                ai_verdict="false_positive", ai_confidence=0.9)
    score_finding(f)
    assert f.priority == "ignorée"


def test_kev_vulnerability_is_critical():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="HIGH",
                cve="CVE-1", fixed_version="2", kev=True, epss=0.2)
    score_finding(f)
    assert f.priority == "critique"


def test_vulnerability_without_fix_is_capped():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", epss=0.9)
    score_finding(f)
    assert f.priority == "moyenne"


def test_critical_os_vulnerability_unlikely_to_be_exploited_is_not_urgent():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", fixed_version="2", epss=0.0005)
    score_finding(f)
    assert f.priority == "moyenne"


def test_critical_os_vulnerability_likely_to_be_exploited_is_high():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", fixed_version="2", epss=0.2)
    score_finding(f)
    assert f.priority == "haute"


def test_dependency_confirmed_by_ai_becomes_high():
    f = Finding(tool="trivy", category="dependency", rule_id="CVE-2020-14343", title="t",
                severity="CRITICAL", cve="CVE-2020-14343", fixed_version="5.4", epss=0.02,
                ai_verdict="true_positive", ai_confidence=0.9)
    score_finding(f)
    assert f.priority == "haute"


def test_code_context_finds_file_by_basename():
    ctx = code_context(SOURCES, "Dockerfile", 1)
    assert "FROM python:3.8-slim" in ctx


def test_full_triage_blocks_on_secret(monkeypatch, offline):
    monkeypatch.setattr(engine_module, "analyze", fake_llm({}))
    result = run_triage(REPORTS, SOURCES, offline)
    s = result["summary"]
    assert s["raw_total"] == 9 and s["unique_total"] == 6
    assert result["gate"]["passed"] is False
    assert result["findings"][0]["category"] == "secret"
    assert "<html" in render_html({**result, "build": "42"})


def test_full_triage_passes_without_secret_and_counts_false_positives(monkeypatch, offline):
    reports = {**REPORTS, "gitleaks": []}
    rule = REPORTS["semgrep"]["results"][0]["check_id"]
    monkeypatch.setattr(engine_module, "analyze", fake_llm({rule: "false_positive"}))
    result = run_triage(reports, SOURCES, offline)
    # La CVE glibc est dans KEV -> critique : le gate reste bloqué, ce qui est le comportement voulu
    blocking = result["gate"]["blocking"]
    assert len(blocking) == 1 and "glibc" in blocking[0]
    assert result["summary"]["ai_false_positives"] == 1


def test_llm_failure_falls_back_to_needs_review(monkeypatch):
    from app import llm

    def boom(*args, **kwargs):
        raise ConnectionError("ollama down")
    monkeypatch.setattr(llm.httpx, "post", boom)
    f = Finding(tool="semgrep", category="sast", rule_id="x", title="t", severity="HIGH")
    llm.analyze(f, "", "http://127.0.0.1:11434", "llama3.2:3b")
    assert f.ai_verdict == "needs_review"


def test_dedupe_ignores_package_name_case():
    reports = {"trivy_fs": {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-14343", "PkgName": "pyyaml", "Severity": "CRITICAL"}]}]},
               "trivy_image": {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-14343", "PkgName": "PyYAML", "Severity": "CRITICAL"}]}]}}
    findings, _ = normalize_all(reports)
    assert len(dedupe(findings)) == 1


def test_llm_retries_when_ollama_restarts(monkeypatch):
    import httpx as real_httpx
    from app import llm
    calls = {"n": 0}

    class Resp:
        def raise_for_status(self): pass
        def json(self):
            return {"message": {"content": '{"real_issue": true, "confidence": 0.8}'}}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise real_httpx.ConnectError("refused")
        return Resp()
    monkeypatch.setattr(llm.httpx, "post", flaky)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    f = Finding(tool="semgrep", category="sast", rule_id="x", title="t", severity="HIGH")
    llm.analyze(f, "", "http://127.0.0.1:11434", "m")
    assert f.ai_verdict == "true_positive" and calls["n"] == 2


def test_low_confidence_false_positive_is_not_dismissed():
    """Rejoue le build #5 : l'IA classait l'injection SQL en faux positif avec 0.8 de confiance."""
    f = Finding(tool="semgrep", category="sast", rule_id="tainted-sql-string", title="t",
                severity="HIGH", ai_verdict="false_positive", ai_confidence=0.8)
    score_finding(f)
    assert f.priority == "haute"
    assert f.notes


def test_iac_findings_are_never_sent_to_the_llm(monkeypatch, offline):
    seen = []

    def spy(f, *args, **kwargs):
        seen.append(f.category)
        f.ai_verdict, f.ai_confidence = "false_positive", 0.99
    monkeypatch.setattr(engine_module, "analyze", spy)
    result = run_triage(REPORTS, SOURCES, offline)
    assert "iac" not in seen
    iac = [f for f in result["findings"] if f["category"] == "iac"]
    assert iac and all(f["priority"] != "ignorée" for f in iac)


def test_prompt_asks_a_factual_question():
    from app.llm import build_prompt
    f = Finding(tool="semgrep", category="sast", rule_id="x", title="t", severity="HIGH")
    assert "request.args" in build_prompt(f, "code")


def test_real_issue_false_maps_to_false_positive(monkeypatch):
    from app import llm

    class Resp:
        def raise_for_status(self): pass
        def json(self):
            return {"message": {"content": '{"real_issue": "false", "confidence": 0.95}'}}
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: Resp())
    f = Finding(tool="semgrep", category="sast", rule_id="x", title="t", severity="HIGH")
    llm.analyze(f, "", "http://x", "m")
    assert f.ai_verdict == "false_positive" and f.ai_confidence == 0.95


def test_severe_sast_finding_is_never_dismissed_even_with_full_confidence():
    """Rejoue le build #6 : injection SQL classée faux positif avec une confiance de 1.0."""
    f = Finding(tool="semgrep", category="sast", rule_id="tainted-sql-string", title="t",
                severity="HIGH", ai_verdict="false_positive", ai_confidence=1.0)
    score_finding(f)
    assert f.priority == "haute"
