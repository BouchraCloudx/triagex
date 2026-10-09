#!/usr/bin/env python3
"""Client Jenkins du moteur IA TriageX.

Envoie les rapports des scanners et le code source au moteur IA, écrit le rapport
(triage.json et triage.html), affiche le résumé et applique le quality gate :
code de sortie 0 = validé, 1 = bloqué, 2 = moteur IA injoignable.
Uniquement la bibliothèque standard Python : rien à installer sur le serveur CI.
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

REPORT_FILES = {
    "gitleaks": "gitleaks.json",
    "semgrep": "semgrep.json",
    "trivy_fs": "trivy-fs.json",
    "checkov": "checkov.json",
    "trivy_image": "trivy-image.json",
}
LABELS = {
    "gitleaks": "Secrets (Gitleaks)",
    "semgrep": "Code (Semgrep)",
    "trivy_fs": "Dépendances (Trivy)",
    "checkov": "Dockerfile (Checkov)",
    "trivy_image": "Image Docker (Trivy)",
}
SOURCE_EXTENSIONS = (".py", ".txt", ".toml", ".cfg", ".yml", ".yaml", ".js", ".ts")
SOURCE_NAMES = ("Dockerfile",)
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "reports"}
MAX_FILE_SIZE = 200_000
MAX_PRINTED = 15


def load_reports(directory: str) -> dict:
    reports = {}
    for key, name in REPORT_FILES.items():
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                reports[key] = json.load(fh)
        except FileNotFoundError:
            print(f"[avertissement] rapport absent : {path}")
            reports[key] = None
        except json.JSONDecodeError:
            print(f"[avertissement] rapport illisible : {path}")
            reports[key] = None
    return reports


def load_sources(root: str) -> dict:
    sources = {}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not (name.endswith(SOURCE_EXTENSIONS) or name in SOURCE_NAMES):
                continue
            path = os.path.join(dirpath, name)
            if os.path.getsize(path) > MAX_FILE_SIZE:
                continue
            with open(path, encoding="utf-8", errors="replace") as fh:
                sources[os.path.relpath(path)] = fh.read()
    return sources


def post_json(url: str, payload: dict, timeout: int) -> dict:
    data = json.dumps(payload).encode("utf-8")
    request = urllib.request.Request(url, data=data, method="POST",
                                     headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def print_summary(result: dict) -> None:
    s, gate = result["summary"], result["gate"]
    line = "=" * 52
    print(line)
    print(" TRIAGEX - RÉSULTAT DU TRIAGE IA")
    print(line)
    print(" Alertes brutes par scanner :")
    for key, label in LABELS.items():
        print(f"   {label:<26}: {s['raw_counts'].get(key, 0)}")
    print("-" * 52)
    print(f" Alertes brutes (avant IA)     : {s['raw_total']}")
    print(f" Après déduplication           : {s['unique_total']}")
    print(f" À traiter (critiques+hautes)  : {s['actionable']}")
    print(f" Réduction                     : {s['reduction_percent']} %")
    print("-" * 52)
    for priority, count in s["by_priority"].items():
        print(f"   {priority:<12}: {count}")
    print("-" * 52)
    print(f" Code analysé par l'IA         : {s['ai_analyzed']} alertes ({s['model']})")
    print(f" Confirmées / contestées / ?   : {s['ai_confirmed']} / {s['ai_contested']} / {s['ai_undecided']}")
    print(f" Durée du triage               : {s['duration_seconds']} s")
    print(line)
    urgent = [f for f in result["findings"] if f["priority"] in ("critique", "haute")]
    for f in urgent[:MAX_PRINTED]:
        where = f"{f['file']}:{f['line']}" if f["file"] else ", ".join(f["packages"][:3])
        print(f" [{f['priority'].upper():8}] {f['id']} {f['title'][:60]} ({where})")
        if f.get("ai_explanation"):
            print(f"            IA : {f['ai_explanation'][:150]}")
    if len(urgent) > MAX_PRINTED:
        print(f" ... et {len(urgent) - MAX_PRINTED} autres : voir le Rapport TriageX dans Jenkins")
    print(line)
    if gate["passed"]:
        print(" QUALITY GATE : VALIDÉ")
    else:
        print(" QUALITY GATE : BLOQUÉ")
        for item in gate["blocking"]:
            print(f"   - {item}")
    print(line)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, help="URL du moteur IA, ex. http://192.168.138.11:8000")
    parser.add_argument("--reports-dir", default="reports")
    parser.add_argument("--source-dir", default=".")
    parser.add_argument("--out-dir", default="reports")
    parser.add_argument("--build", default=os.environ.get("BUILD_NUMBER"))
    parser.add_argument("--timeout", type=int, default=3000)
    args = parser.parse_args()

    payload = {
        "project": "triagex",
        "build": args.build,
        "reports": load_reports(args.reports_dir),
        "sources": load_sources(args.source_dir),
    }
    print(f"Envoi de {len(payload['sources'])} fichier(s) source et des rapports à {args.url} ...")
    try:
        result = post_json(args.url.rstrip("/") + "/triage", payload, args.timeout)
    except (urllib.error.URLError, TimeoutError, ConnectionError) as exc:
        print(f"[erreur] moteur IA injoignable : {exc}")
        return 2

    os.makedirs(args.out_dir, exist_ok=True)
    html = result.pop("html", "")
    with open(os.path.join(args.out_dir, "triage.json"), "w", encoding="utf-8") as fh:
        json.dump(result, fh, ensure_ascii=False, indent=2)
    with open(os.path.join(args.out_dir, "triage.html"), "w", encoding="utf-8") as fh:
        fh.write(html)

    print_summary(result)
    return 0 if result["gate"]["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
