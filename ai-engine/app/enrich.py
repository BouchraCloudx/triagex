"""Enrichissement des CVE : EPSS (probabilité d'exploitation) et catalogue CISA KEV."""
import json
import logging
import os
import time

import httpx

log = logging.getLogger("triagex.enrich")

EPSS_URL = "https://api.first.org/data/v1/epss"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_MAX_AGE = 24 * 3600


def load_kev(data_dir: str) -> set[str]:
    """Catalogue des vulnérabilités activement exploitées, mis en cache 24 h."""
    path = os.path.join(data_dir, "kev.json")
    data = None
    fresh = os.path.exists(path) and time.time() - os.path.getmtime(path) < KEV_MAX_AGE
    if not fresh:
        try:
            response = httpx.get(KEV_URL, timeout=60, follow_redirects=True)
            response.raise_for_status()
            data = response.json()
            try:
                with open(path, "w", encoding="utf-8") as fh:
                    json.dump(data, fh)
            except OSError as exc:
                log.warning("Cache KEV non écrit : %s", exc)
        except Exception as exc:
            log.warning("Téléchargement KEV impossible : %s", exc)
    if data is None and os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except Exception as exc:
            log.warning("Cache KEV illisible : %s", exc)
    if not data:
        return set()
    return {v.get("cveID") for v in data.get("vulnerabilities", []) if v.get("cveID")}


def fetch_epss(cves: list[str]) -> dict[str, float]:
    """Score EPSS de chaque CVE (0 à 1), interrogé par lots de 50."""
    scores: dict[str, float] = {}
    unique = sorted(set(cves))
    for start in range(0, len(unique), 50):
        chunk = unique[start:start + 50]
        try:
            response = httpx.get(EPSS_URL, params={"cve": ",".join(chunk)}, timeout=30)
            response.raise_for_status()
            for item in response.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])
        except Exception as exc:
            log.warning("EPSS indisponible pour un lot de %d CVE : %s", len(chunk), exc)
    return scores
