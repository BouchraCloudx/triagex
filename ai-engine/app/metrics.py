"""Métriques TriageX au format Prometheus : dernier triage et dernier contrôle de conformité.

Prometheus interroge /metrics toutes les 30 secondes : chaque build et chaque contrôle nocturne
devient un point dans le temps, ce qui permet à Grafana de tracer l'évolution de la sécurité.
L'état est enregistré sur disque pour survivre à un redémarrage du conteneur.
"""
import json
import logging
import os
import threading
import time

log = logging.getLogger("triagex.metrics")


def _escape(value) -> str:
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", " ")


class MetricsState:
    def __init__(self, data_dir: str):
        self.path = os.path.join(data_dir, "state.json")
        self.lock = threading.Lock()
        self.state = {"triage": None, "compliance": None}
        try:
            with open(self.path, encoding="utf-8") as fh:
                self.state.update(json.load(fh))
        except FileNotFoundError:
            pass
        except Exception as exc:
            log.warning("État des métriques illisible, remis à zéro : %s", exc)

    def _save(self) -> None:
        try:
            tmp = self.path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(self.state, fh)
            os.replace(tmp, self.path)
        except OSError as exc:
            log.warning("État des métriques non enregistré : %s", exc)

    def record_triage(self, result: dict) -> None:
        with self.lock:
            self.state["triage"] = {
                "summary": result["summary"],
                "gate_passed": result["gate"]["passed"],
                "build": result.get("build"),
                "timestamp": time.time(),
            }
            self._save()

    def record_compliance(self, build, drift_corrected: int, passed: bool) -> None:
        with self.lock:
            self.state["compliance"] = {
                "build": build,
                "drift_corrected": drift_corrected,
                "passed": passed,
                "timestamp": time.time(),
            }
            self._save()

    def render(self) -> str:
        lines = []

        def metric(name, help_text, samples):
            lines.append(f"# HELP {name} {help_text}")
            lines.append(f"# TYPE {name} gauge")
            for labels, value in samples:
                label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in labels.items())
                lines.append(f"{name}{{{label_text}}} {value}" if label_text else f"{name} {value}")

        with self.lock:
            triage, compliance = self.state["triage"], self.state["compliance"]

        if triage:
            s = triage["summary"]
            metric("triagex_alerts_raw", "Alertes brutes des scanners au dernier build",
                   [({}, s["raw_total"])])
            metric("triagex_alerts_unique", "Alertes uniques après déduplication", [({}, s["unique_total"])])
            metric("triagex_alerts_actionable", "Alertes à traiter (critiques et hautes)",
                   [({}, s["actionable"])])
            metric("triagex_alerts_reduction_percent", "Réduction du nombre d'alertes à traiter",
                   [({}, s["reduction_percent"])])
            metric("triagex_alerts_by_priority", "Alertes par priorité",
                   [({"priority": p}, n) for p, n in s["by_priority"].items()])
            metric("triagex_alerts_by_scanner", "Alertes brutes par scanner",
                   [({"scanner": k}, n) for k, n in s["raw_counts"].items()])
            metric("triagex_ai_verdicts", "Avis de l'IA sur les alertes de code",
                   [({"verdict": "confirmée"}, s.get("ai_confirmed", 0)),
                    ({"verdict": "contestée"}, s.get("ai_contested", 0)),
                    ({"verdict": "indécise"}, s.get("ai_undecided", 0))])
            metric("triagex_gate_passed", "Quality gate du dernier build (1 = validé, 0 = bloqué)",
                   [({}, int(bool(triage["gate_passed"])))])
            metric("triagex_triage_duration_seconds", "Durée du dernier triage",
                   [({}, s["duration_seconds"])])
            build = triage.get("build")
            metric("triagex_last_build", "Numéro du dernier build analysé",
                   [({}, int(build) if str(build).isdigit() else 0)])
            metric("triagex_last_triage_timestamp_seconds", "Date du dernier triage (epoch)",
                   [({}, round(triage["timestamp"]))])

        if compliance:
            metric("triagex_compliance_drift_corrected", "Modifications corrigées au dernier contrôle de conformité",
                   [({}, compliance["drift_corrected"])])
            metric("triagex_compliance_passed", "Dernier contrôle de conformité (1 = conforme, 0 = échec)",
                   [({}, int(bool(compliance["passed"])))])
            metric("triagex_compliance_last_run_timestamp_seconds", "Date du dernier contrôle (epoch)",
                   [({}, round(compliance["timestamp"]))])

        metric("triagex_engine_up", "Le moteur IA répond", [({}, 1)])
        return "\n".join(lines) + "\n"
