"""Tests du script d'examen (scripts/evaluate_ai.py)."""
import importlib.util
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("evaluate_ai", ROOT / "scripts" / "evaluate_ai.py")
evaluate_ai = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluate_ai)

SOURCE = """import x
TOKEN = "abc"

@app.route("/a")
def vulnerable():
    return run(user_input)

@app.route("/b")
def trap():
    return run("constant")
"""
TRUTH = {"file": "demo-app/app.py", "functions": {
    "<module>": {"expected": "vuln"}, "vulnerable": {"expected": "vuln"}, "trap": {"expected": "safe"},
    "missed": {"expected": "vuln"}}}


def finding(i, line, verdict, category="sast"):
    return {"id": f"TX-{i}", "category": category, "file": "demo-app/app.py", "line": line,
            "rule_id": "r", "ai_verdict": verdict, "ai_confidence": 1.0, "priority": "haute"}


def test_always_yes_ai_is_exposed():
    """Build #10 : une IA qui confirme tout obtient 0 % de pièges reconnus."""
    triage = {"findings": [finding(1, 2, "true_positive", "secret"),
                           finding(2, 6, "true_positive"), finding(3, 10, "true_positive")]}
    r = evaluate_ai.evaluate(triage, TRUTH, SOURCE)
    assert r["sensitivity_percent"] == 100.0
    assert r["specificity_percent"] == 0.0
    assert r["balanced_accuracy_percent"] == 50.0
    assert r["accuracy_percent"] == r["always_yes_accuracy_percent"]
    assert "aucun piège" in evaluate_ai.interpretation(r)


def test_good_ai_and_scanner_misses():
    triage = {"findings": [finding(2, 5, "true_positive"), finding(3, 9, "false_positive")]}
    r = evaluate_ai.evaluate(triage, TRUTH, SOURCE)
    assert r["balanced_accuracy_percent"] == 100.0
    assert r["real_vulns_contested"] == 0
    assert "missed" in r["missed_by_scanners"]


def test_undecided_and_unanalysed_are_not_counted():
    triage = {"findings": [finding(2, 6, "needs_review"), finding(3, 10, None)]}
    r = evaluate_ai.evaluate(triage, TRUTH, SOURCE)
    assert r["ai_decided"] == 0 and r["ai_undecided_or_missing"] == 2
