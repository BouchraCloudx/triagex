"""Tests de l'API : triage, conformité et métriques Prometheus."""
import importlib

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("DATA_DIR", str(tmp_path))
    from app import main
    importlib.reload(main)

    def fake_triage(reports, sources, settings):
        return {
            "summary": {"raw_counts": {"gitleaks": 1, "semgrep": 20}, "raw_total": 21, "unique_total": 15,
                        "by_priority": {"critique": 1, "haute": 2, "moyenne": 5, "basse": 7},
                        "actionable": 3, "reduction_percent": 85.7, "ai_analyzed": 14,
                        "ai_confirmed": 14, "ai_contested": 0, "ai_undecided": 0,
                        "kev_loaded": True, "epss_scores": 10, "model": "m", "duration_seconds": 12.5},
            "gate": {"passed": False, "blocking": ["TX-0001 secret"], "rule": "r"},
            "findings": [],
        }
    monkeypatch.setattr(main, "run_triage", fake_triage)
    return TestClient(main.app), main, tmp_path


def test_metrics_before_any_build(client):
    c, _, _ = client
    body = c.get("/metrics").text
    assert "triagex_engine_up 1" in body
    assert "triagex_alerts_raw" not in body


def test_triage_updates_metrics_and_survives_restart(client):
    c, main, tmp_path = client
    assert c.post("/triage", json={"build": "12", "reports": {}, "sources": {}}).status_code == 200
    body = c.get("/metrics").text
    assert "triagex_alerts_raw 21" in body
    assert "triagex_alerts_actionable 3" in body
    assert 'triagex_alerts_by_priority{priority="critique"} 1' in body
    assert 'triagex_alerts_by_scanner{scanner="semgrep"} 20' in body
    assert "triagex_gate_passed 0" in body
    assert "triagex_last_build 12" in body
    # Redémarrage du conteneur : l'état est relu depuis le disque
    restarted = main.MetricsState(str(tmp_path))
    assert "triagex_alerts_raw 21" in restarted.render()


def test_compliance_is_recorded(client):
    c, _, _ = client
    assert c.post("/compliance", json={"build": "3", "drift_corrected": 2, "passed": True}).status_code == 200
    body = c.get("/metrics").text
    assert "triagex_compliance_drift_corrected 2" in body
    assert "triagex_compliance_passed 1" in body


def test_compliance_rejects_invalid_payload(client):
    c, _, _ = client
    assert c.post("/compliance", json={"drift_corrected": -1, "passed": True}).status_code == 422
