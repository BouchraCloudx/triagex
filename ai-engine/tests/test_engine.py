"""Tests du moteur IA TriageX (sans réseau ni LLM réel : ils sont simulés).

Plusieurs tests rejouent des erreurs réellement observées sur l'infrastructure TriageX,
pour garantir qu'elles ne peuvent plus avoir de conséquence.
"""
import pytest

from app import engine as engine_module
from app import llm
from app.context import code_context
from app.engine import Settings, run_triage
from app.models import Finding
from app.normalize import clean_path, dedupe, normalize_all
from app.report import render_html
from app.scoring import score_finding

SOURCES = {
    "demo-app/app.py": "\n".join([
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
                  "File": "/repo/demo-app/app.py", "StartLine": 2, "Secret": "Zx9fK2mQ7x"}],
    "semgrep": {"results": [
        {"check_id": "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true",
         "path": "/src/demo-app/app.py", "start": {"line": 4},
         "extra": {"severity": "ERROR", "message": "shell=True"}},
        {"check_id": "python.flask.security.injection.subprocess-injection.subprocess-injection",
         "path": "/src/demo-app/app.py", "start": {"line": 4},
         "extra": {"severity": "ERROR", "message": "command injection"}},
    ]},
    "trivy_fs": {"Results": [{"Class": "lang-pkgs", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2020-14343", "PkgName": "pyyaml", "InstalledVersion": "5.3.1",
         "FixedVersion": "5.4", "Severity": "CRITICAL", "Title": "arbitrary code execution"}]}]},
    "checkov": [{"results": {"failed_checks": [
        {"check_id": "CKV_DOCKER_3", "check_name": "Ensure a user is created",
         "file_path": "/Dockerfile", "repo_file_path": "/src/demo-app/Dockerfile",
         "file_line_range": [1, 2], "severity": None}]}}],
    "trivy_image": {"Results": [
        {"Class": "os-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2023-0001", "PkgName": "libssl3", "Severity": "HIGH", "Title": "x"},
            {"VulnerabilityID": "CVE-2023-0001", "PkgName": "openssl", "Severity": "HIGH", "Title": "x"},
            {"VulnerabilityID": "CVE-2021-3999", "PkgName": "libc6", "FixedVersion": "2.36-9",
             "Severity": "HIGH", "Title": "glibc"}]},
        {"Class": "lang-pkgs", "Vulnerabilities": [
            {"VulnerabilityID": "CVE-2020-14343", "PkgName": "PyYAML", "InstalledVersion": "5.3.1",
             "FixedVersion": "5.4", "Severity": "CRITICAL", "Title": "arbitrary code execution"}]},
    ]},
}


def fake_llm(verdict="true_positive", confidence=1.0, seen=None):
    def _analyze(f, context, url, model, timeout=300):
        if seen is not None:
            seen.append(f.category)
        f.ai_verdict, f.ai_confidence = verdict, confidence
        f.ai_explanation, f.ai_fix = f"avis simulé : {verdict}", "correctif simulé"
    return _analyze


@pytest.fixture
def offline(monkeypatch, tmp_path):
    monkeypatch.setattr(engine_module, "load_kev", lambda data_dir: {"CVE-2021-3999"})
    monkeypatch.setattr(engine_module, "fetch_epss",
                        lambda cves: {"CVE-2020-14343": 0.02, "CVE-2023-0001": 0.001})
    return Settings(data_dir=str(tmp_path))


# --- Normalisation et déduplication -------------------------------------------------------

def test_clean_path():
    assert clean_path("/repo/demo-app/app.py") == "demo-app/app.py"
    assert clean_path("/src/demo-app/app.py") == "demo-app/app.py"
    assert clean_path(None) is None


def test_every_raw_alert_is_counted():
    _, counts = normalize_all(REPORTS)
    assert counts == {"gitleaks": 1, "semgrep": 2, "trivy_fs": 1, "checkov": 1, "trivy_image": 4}


def test_dedupe_merges_same_problem():
    unique = dedupe(normalize_all(REPORTS)[0])
    # 2 règles Semgrep sur la même ligne -> 1 ; même CVE dans 2 paquets OS -> 1 ;
    # PyYAML (scan fs) et PyYAML (scan image, autre casse) -> 1
    assert len(unique) == 6
    os_vuln = next(f for f in unique if f.rule_id == "CVE-2023-0001")
    assert sorted(os_vuln.packages) == ["libssl3", "openssl"]


# --- Garde-fous : l'IA ne peut jamais cacher ni enterrer une faille -------------------------

@pytest.mark.parametrize("severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
def test_ai_never_hides_a_code_finding(severity):
    f = Finding(tool="semgrep", category="sast", rule_id="r", title="t", severity=severity,
                ai_verdict="false_positive", ai_confidence=1.0)
    score_finding(f)
    assert f.priority in ("critique", "haute", "moyenne", "basse") and f.notes


def test_build6_sql_injection_contested_with_full_confidence_stays_high():
    """Build #6 : injection SQL contestée avec une confiance de 1.0."""
    f = Finding(tool="semgrep", category="sast", rule_id="tainted-sql-string", title="t",
                severity="HIGH", ai_verdict="false_positive", ai_confidence=1.0)
    score_finding(f)
    assert f.priority == "haute"


def test_secret_is_always_critical_even_if_ai_disagrees():
    f = Finding(tool="gitleaks", category="secret", rule_id="x", title="t", severity="CRITICAL",
                ai_verdict="false_positive", ai_confidence=1.0)
    score_finding(f)
    assert f.priority == "critique"


def test_dependencies_and_iac_are_never_sent_to_the_llm(monkeypatch, offline):
    """Build #10 : le modèle rejetait toutes les CVE de dépendances, PyYAML comprise."""
    seen = []
    monkeypatch.setattr(engine_module, "analyze", fake_llm("false_positive", 1.0, seen))
    result = run_triage(REPORTS, SOURCES, offline)
    assert set(seen) <= {"secret", "sast"}
    pyyaml = next(f for f in result["findings"] if f["rule_id"] == "CVE-2020-14343")
    assert pyyaml["ai_verdict"] is None and pyyaml["priority"] == "haute"


# --- Calcul du risque des vulnérabilités ----------------------------------------------------

def test_critical_direct_dependency_with_fix_is_high():
    f = Finding(tool="trivy", category="dependency", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", fixed_version="2", epss=0.01, packages=["pyyaml"])
    score_finding(f)
    assert f.priority == "haute"


def test_critical_os_vulnerability_unlikely_to_be_exploited_is_medium():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", fixed_version="2", epss=0.0005)
    score_finding(f)
    assert f.priority == "moyenne"


def test_critical_os_vulnerability_likely_to_be_exploited_is_high():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", fixed_version="2", epss=0.2)
    score_finding(f)
    assert f.priority == "haute"


def test_kev_vulnerability_is_always_critical():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="LOW",
                cve="CVE-1", kev=True)
    score_finding(f)
    assert f.priority == "critique"


def test_vulnerability_without_fix_is_capped():
    f = Finding(tool="trivy", category="image-os", rule_id="CVE-1", title="t", severity="CRITICAL",
                cve="CVE-1", epss=0.9)
    score_finding(f)
    assert f.priority == "moyenne"


# --- Triage complet ---------------------------------------------------------------------------

def test_full_triage_blocks_on_secret_and_kev(monkeypatch, offline):
    monkeypatch.setattr(engine_module, "analyze", fake_llm())
    result = run_triage(REPORTS, SOURCES, offline)
    s = result["summary"]
    assert s["raw_total"] == 9 and s["unique_total"] == 6
    assert result["gate"]["passed"] is False
    assert len(result["gate"]["blocking"]) == 2  # le secret et la CVE glibc présente dans KEV
    assert s["ai_analyzed"] == 2 and s["ai_confirmed"] == 2
    html = render_html({**result, "build": "42"})
    assert "<html" in html and "<script" not in html and "<style" not in html


def test_ai_budget_keeps_the_most_severe_code_alerts(monkeypatch, offline):
    seen = []
    monkeypatch.setattr(engine_module, "analyze", fake_llm(seen=seen))
    run_triage(REPORTS, SOURCES, Settings(data_dir=offline.data_dir, max_llm_findings=1))
    assert seen == ["secret"]


# --- Prompt et appel au LLM -----------------------------------------------------------------

def test_prompt_is_neutral():
    assert "usually right" not in llm.SYSTEM_PROMPT


def test_question_depends_on_rule_type():
    injection = Finding(tool="semgrep", category="sast", severity="HIGH", title="t",
                        rule_id="python.flask.security.injection.tainted-sql-string.tainted-sql-string")
    config = Finding(tool="semgrep", category="sast", severity="MEDIUM", title="t",
                     rule_id="python.lang.security.audit.insecure-hash-algorithm-md5")
    secret = Finding(tool="gitleaks", category="secret", severity="CRITICAL", title="t", rule_id="k")
    assert llm.question_key(injection) == "sast"
    assert llm.question_key(config) == "sast_config"
    assert llm.question_key(secret) == "secret"
    assert "cache key" in llm.build_prompt(config, "hashlib.md5(x)")


class _Resp:
    def __init__(self, content):
        self._content = content

    def raise_for_status(self):
        pass

    def json(self):
        return {"message": {"content": self._content}}


def test_llm_answer_is_parsed(monkeypatch):
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: _Resp(
        '{"explanation": "x", "real_issue": "false", "confidence": 0.95, "fix": ""}'))
    f = Finding(tool="semgrep", category="sast", rule_id="r", title="t", severity="HIGH")
    llm.analyze(f, "", "http://x", "m")
    assert f.ai_verdict == "false_positive" and f.ai_confidence == 0.95


def test_llm_garbage_answer_means_undecided(monkeypatch):
    monkeypatch.setattr(llm.httpx, "post", lambda *a, **k: _Resp('{"real_issue": "maybe"}'))
    f = Finding(tool="semgrep", category="sast", rule_id="r", title="t", severity="HIGH")
    llm.analyze(f, "", "http://x", "m")
    assert f.ai_verdict == "needs_review"


def test_llm_retries_when_ollama_restarts(monkeypatch):
    calls = {"n": 0}

    def flaky(*args, **kwargs):
        calls["n"] += 1
        if calls["n"] == 1:
            raise llm.httpx.ConnectError("refused")
        return _Resp('{"real_issue": true, "confidence": 0.8}')
    monkeypatch.setattr(llm.httpx, "post", flaky)
    monkeypatch.setattr(llm.time, "sleep", lambda s: None)
    f = Finding(tool="semgrep", category="sast", rule_id="r", title="t", severity="HIGH")
    llm.analyze(f, "", "http://x", "m")
    assert f.ai_verdict == "true_positive" and calls["n"] == 2


def test_llm_down_means_undecided(monkeypatch):
    def down(*args, **kwargs):
        raise ValueError("boom")
    monkeypatch.setattr(llm.httpx, "post", down)
    f = Finding(tool="semgrep", category="sast", rule_id="r", title="t", severity="HIGH")
    llm.analyze(f, "", "http://x", "m")
    assert f.ai_verdict == "needs_review"


def test_code_context_finds_file_by_basename():
    assert "FROM python:3.8-slim" in code_context(SOURCES, "Dockerfile", 1)
