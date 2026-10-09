#!/usr/bin/env python3
"""Examen du moteur IA TriageX : compare ses avis à la correction (evaluation/ground_truth.json).

Pour chaque alerte de code (Semgrep, Gitleaks) du rapport triage.json, on retrouve la fonction
de app.py qui la contient, on regarde si c'est une vraie faille (vuln) ou un piège (safe), et on
compare à l'avis de l'IA.

Une seule "précision" serait trompeuse : une IA qui répond toujours "oui" aurait un bon score
dès que la plupart des alertes sont vraies. On mesure donc séparément :
- les failles reconnues (sensibilité) : l'IA confirme une vraie faille ;
- les pièges reconnus (spécificité) : l'IA conteste une alerte sur du code sûr ;
- la précision équilibrée (moyenne des deux), comparée au score d'une IA "toujours oui" ;
- les failles contestées à tort : elles restent visibles (l'IA ne cache rien), mais c'est
  l'erreur la plus coûteuse si un humain suivait l'avis de l'IA sans vérifier.
Uniquement la bibliothèque standard Python. Ne fait jamais échouer le build.
"""
import argparse
import ast
import json
import os
import sys

CODE_CATEGORIES = ("sast", "secret")
VERDICT_LABELS = {"true_positive": "confirme", "false_positive": "conteste",
                  "needs_review": "indécise", None: "-"}


def function_ranges(source: str) -> list:
    """(début, fin, nom) de chaque fonction, décorateurs inclus."""
    ranges = []
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([d.lineno for d in node.decorator_list] + [node.lineno])
            ranges.append((start, node.end_lineno, node.name))
    return ranges


def enclosing_function(ranges, line) -> str:
    if not line:
        return "<module>"
    best = None
    for start, end, name in ranges:
        if start <= line <= end and (best is None or start > best[0]):
            best = (start, name)
    return best[1] if best else "<module>"


def pct(part, whole):
    return round(100 * part / whole, 1) if whole else None


def evaluate(triage: dict, truth: dict, source: str) -> dict:
    target = os.path.basename(truth["file"])
    labels = truth["functions"]
    ranges = function_ranges(source)

    rows = []
    for f in triage["findings"]:
        if f["category"] not in CODE_CATEGORIES or os.path.basename(f.get("file") or "") != target:
            continue
        func = enclosing_function(ranges, f.get("line"))
        expected = labels.get(func, {}).get("expected", "non étiquetée")
        verdict = f.get("ai_verdict")
        if verdict in (None, "needs_review") or expected not in ("vuln", "safe"):
            result = "-"
        else:
            result = "juste" if (verdict == "true_positive") == (expected == "vuln") else "fausse"
        rows.append({"id": f["id"], "function": func, "line": f.get("line"), "rule": f["rule_id"],
                     "expected": expected, "ai_verdict": verdict,
                     "ai_confidence": f.get("ai_confidence"), "result": result,
                     "priority": f["priority"], "ai_explanation": f.get("ai_explanation", "")})

    decided = [r for r in rows if r["result"] != "-"]
    on_vulns = [r for r in decided if r["expected"] == "vuln"]
    on_traps = [r for r in decided if r["expected"] == "safe"]
    vulns_ok = sum(1 for r in on_vulns if r["result"] == "juste")
    traps_ok = sum(1 for r in on_traps if r["result"] == "juste")
    sensitivity = pct(vulns_ok, len(on_vulns))
    specificity = pct(traps_ok, len(on_traps))
    balanced = (round((sensitivity + specificity) / 2, 1)
                if sensitivity is not None and specificity is not None else None)
    vuln_functions = {n for n, v in labels.items() if v["expected"] == "vuln"}
    detected = {r["function"] for r in rows if r["expected"] == "vuln"}

    return {
        "model": triage.get("summary", {}).get("model"),
        "build": triage.get("build"),
        "code_alerts": len(rows),
        "ai_decided": len(decided),
        "ai_undecided_or_missing": len(rows) - len(decided),
        "accuracy_percent": pct(vulns_ok + traps_ok, len(decided)),
        "always_yes_accuracy_percent": pct(len(on_vulns), len(decided)),
        "vulns_recognized": vulns_ok, "vulns_total": len(on_vulns), "sensitivity_percent": sensitivity,
        "traps_recognized": traps_ok, "traps_total": len(on_traps), "specificity_percent": specificity,
        "balanced_accuracy_percent": balanced,
        "real_vulns_contested": len(on_vulns) - vulns_ok,
        "real_vulns_hidden": 0,  # par conception : l'IA ne cache jamais une alerte
        "vulnerable_functions": len(vuln_functions),
        "vulnerable_functions_detected": len(detected & vuln_functions),
        "missed_by_scanners": sorted(vuln_functions - detected),
        "details": rows,
    }


def interpretation(r: dict) -> str:
    if r["traps_total"] == 0:
        return "Aucun piège n'a été signalé par les scanners : la spécificité n'est pas mesurable."
    if r["specificity_percent"] == 0:
        return ("L'IA ne reconnaît aucun piège : ses avis n'apportent pas plus d'information "
                "que le scanner seul.")
    if r["balanced_accuracy_percent"] is not None and r["balanced_accuracy_percent"] <= 50:
        return "L'IA ne fait pas mieux que le hasard pour distinguer failles et pièges."
    return ("L'IA distingue en partie failles et pièges. Échantillon petit : à présenter comme "
            "une démonstration de méthode, pas comme une précision générale.")


def print_report(r: dict) -> None:
    line = "=" * 70
    print(line)
    print(f" EXAMEN DU MOTEUR IA - modèle {r['model']}")
    print(line)
    print(f" {'Alerte':<9}{'Fonction':<17}{'Attendu':<9}{'IA':<11}{'Résultat':<9}Priorité")
    for row in sorted(r["details"], key=lambda x: x["line"] or 0):
        print(f" {row['id']:<9}{row['function'][:16]:<17}{row['expected'][:8]:<9}"
              f"{VERDICT_LABELS[row['ai_verdict']]:<11}{row['result']:<9}{row['priority']}")
    print("-" * 70)
    show = lambda v: "-" if v is None else f"{v} %"
    print(f" Failles reconnues (sensibilité)  : {r['vulns_recognized']}/{r['vulns_total']}"
          f" = {show(r['sensitivity_percent'])}")
    print(f" Pièges reconnus (spécificité)    : {r['traps_recognized']}/{r['traps_total']}"
          f" = {show(r['specificity_percent'])}")
    print(f" Précision équilibrée             : {show(r['balanced_accuracy_percent'])}"
          "  (50 % = hasard)")
    print(f" Précision brute                  : {show(r['accuracy_percent'])}"
          f"  (une IA 'toujours oui' aurait {show(r['always_yes_accuracy_percent'])})")
    print(f" Failles contestées à tort        : {r['real_vulns_contested']}"
          "  (restées visibles)")
    print(f" Failles cachées                  : {r['real_vulns_hidden']}  (impossible par conception)")
    print(f" Détectées par les scanners       : {r['vulnerable_functions_detected']}"
          f"/{r['vulnerable_functions']} fonctions vulnérables")
    if r["missed_by_scanners"]:
        print(f" Manquées par les scanners        : {', '.join(r['missed_by_scanners'])}")
    print("-" * 70)
    print(f" {interpretation(r)}")
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--triage", default="reports/triage.json")
    parser.add_argument("--truth", default="evaluation/ground_truth.json")
    parser.add_argument("--source", default="demo-app/app.py")
    parser.add_argument("--out", default="reports/ai-evaluation.json")
    args = parser.parse_args()
    try:
        with open(args.triage, encoding="utf-8") as fh:
            triage = json.load(fh)
        with open(args.truth, encoding="utf-8") as fh:
            truth = json.load(fh)
        with open(args.source, encoding="utf-8") as fh:
            source = fh.read()
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[examen ignoré] {exc}")
        return 0
    result = evaluate(triage, truth, source)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
