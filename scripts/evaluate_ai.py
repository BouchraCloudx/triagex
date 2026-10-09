#!/usr/bin/env python3
"""Évaluation du moteur IA TriageX : compare ses verdicts à la correction (ground_truth.json).

Pour chaque alerte de code (Semgrep, Gitleaks) du rapport triage.json :
- on retrouve la fonction de app.py qui la contient ;
- on regarde si cette fonction est une vraie faille (vuln) ou un piège (safe) ;
- on compare au verdict de l'IA et à la décision finale de TriageX.

Mesures produites :
- précision des verdicts de l'IA (vrai positif sur une faille, faux positif sur un piège) ;
- failles réelles cachées par TriageX (le pire résultat possible) ;
- pièges correctement écartés (le bruit que l'IA fait gagner) ;
- failles que les scanners n'ont même pas détectées (limite des outils, pas de l'IA).
Uniquement la bibliothèque standard Python. Ne fait jamais échouer le build.
"""
import argparse
import ast
import json
import os
import sys

CODE_CATEGORIES = ("sast", "secret")


def function_ranges(source: str) -> list[tuple[int, int, str]]:
    """Lignes (début, fin, nom) de chaque fonction, décorateurs inclus."""
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


def evaluate(triage: dict, truth: dict, source: str) -> dict:
    target = os.path.basename(truth["file"])
    labels = truth["functions"]
    ranges = function_ranges(source)

    rows = []
    for f in triage["findings"]:
        if f["category"] not in CODE_CATEGORIES or os.path.basename(f.get("file") or "") != target:
            continue
        func = enclosing_function(ranges, f.get("line"))
        expected = labels.get(func, {}).get("expected")
        verdict = f.get("ai_verdict")
        if verdict is None:
            ai = "non analysée"
        elif verdict == "needs_review":
            ai = "indécise"
        elif (verdict == "true_positive") == (expected == "vuln"):
            ai = "juste"
        else:
            ai = "fausse"
        hidden = expected == "vuln" and f["priority"] == "ignorée"
        noise_removed = expected == "safe" and f["priority"] == "ignorée"
        rows.append({
            "id": f["id"], "function": func, "line": f.get("line"), "rule": f["rule_id"],
            "expected": expected or "non étiquetée", "ai_verdict": verdict,
            "ai_confidence": f.get("ai_confidence"), "ai_result": ai,
            "priority": f["priority"], "hidden_real_vuln": hidden,
            "noise_removed": noise_removed,
        })

    labelled = [r for r in rows if r["expected"] in ("vuln", "safe")]
    analysed = [r for r in labelled if r["ai_result"] in ("juste", "fausse", "indécise")]
    correct = [r for r in analysed if r["ai_result"] == "juste"]
    on_traps = [r for r in labelled if r["expected"] == "safe"]
    vuln_functions = {name for name, v in labels.items() if v["expected"] == "vuln"}
    detected = {r["function"] for r in labelled if r["expected"] == "vuln"}

    return {
        "model": triage.get("summary", {}).get("model"),
        "build": triage.get("build"),
        "code_alerts": len(rows),
        "labelled_alerts": len(labelled),
        "ai_analysed": len(analysed),
        "ai_correct": len(correct),
        "ai_wrong": sum(1 for r in analysed if r["ai_result"] == "fausse"),
        "ai_undecided": sum(1 for r in analysed if r["ai_result"] == "indécise"),
        "ai_accuracy_percent": round(100 * len(correct) / len(analysed), 1) if analysed else None,
        "alerts_on_traps": len(on_traps),
        "traps_dismissed": sum(1 for r in on_traps if r["noise_removed"]),
        "real_vulns_hidden": sum(1 for r in labelled if r["hidden_real_vuln"]),
        "vulnerable_functions": len(vuln_functions),
        "vulnerable_functions_detected": len(detected & vuln_functions),
        "missed_by_scanners": sorted(vuln_functions - detected),
        "unlabelled_alerts": [r["id"] for r in rows if r["expected"] == "non étiquetée"],
        "details": rows,
    }


def print_report(result: dict) -> None:
    line = "=" * 64
    print(line)
    print(f" ÉVALUATION DU MOTEUR IA - modèle {result['model']}")
    print(line)
    print(f" {'Alerte':<9}{'Fonction':<17}{'Attendu':<9}{'IA':<15}{'Résultat':<10}Priorité")
    for r in sorted(result["details"], key=lambda r: (r["line"] or 0)):
        verdict = {"true_positive": "vrai positif", "false_positive": "faux positif",
                   "needs_review": "à vérifier", None: "-"}[r["ai_verdict"]]
        flag = "  << FAILLE CACHÉE" if r["hidden_real_vuln"] else ""
        print(f" {r['id']:<9}{r['function'][:16]:<17}{r['expected'][:8]:<9}{verdict:<15}"
              f"{r['ai_result'][:9]:<10}{r['priority']}{flag}")
    print("-" * 64)
    acc = result["ai_accuracy_percent"]
    print(f" Précision des verdicts de l'IA : {result['ai_correct']}/{result['ai_analysed']}"
          f" = {acc if acc is not None else '-'} %"
          f"  (fausses : {result['ai_wrong']}, indécises : {result['ai_undecided']})")
    print(f" Failles réelles cachées        : {result['real_vulns_hidden']}")
    print(f" Pièges écartés par l'IA        : {result['traps_dismissed']}/{result['alerts_on_traps']}"
          " alertes sur du code sûr")
    print(f" Failles détectées par scanners : {result['vulnerable_functions_detected']}"
          f"/{result['vulnerable_functions']} fonctions vulnérables")
    if result["missed_by_scanners"]:
        print(f" Non détectées par les scanners : {', '.join(result['missed_by_scanners'])}")
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
        print(f"[évaluation ignorée] {exc}")
        return 0
    result = evaluate(triage, truth, source)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    print_report(result)
    return 0


if __name__ == "__main__":
    sys.exit(main())
