"""
unified_findings.py
Normalise les résultats de tous les outils (Semgrep, ZAP, Promptfoo,
PentestGPT) dans un schéma commun unique, base de la couche de
priorisation IA, de la corrélation LLM et du générateur de rapport final.

Usage : python unified_findings.py
Prérequis (tous dans le même dossier) :
  - correlate.py
  - semgrep_combined.json
  - zap_full_report_v2.json
  - promptfoo_results.json, promptfoo_results2.json
  - pentestgpt_confirmed.json

Sortie : unified_findings.json
"""

import json
from correlate import load_semgrep, load_zap

SEMGREP_FILE = "semgrep_combined.json"
ZAP_FILE = "zap_full_report_v2.json"
PROMPTFOO_FILES = ["promptfoo_results.json", "promptfoo_results2.json"]
PENTESTGPT_FILE = "pentestgpt_confirmed.json"
OUTPUT_FILE = "unified_findings.json"

# Mapping des plugins Promptfoo vers OWASP LLM Top 10 (2025).
# Jugement de mapping documenté ici pour transparence dans le rapport :
# certains plugins (bola/bfla/rbac) testent un contrôle d'accès classique
# mais appliqué au tool-calling du LLM — rattachés à LLM06 (Excessive
# Agency) car le vecteur d'attaque passe par l'usage abusif des outils
# du modèle, pas par une faille d'infrastructure classique.
PROMPTFOO_OWASP_LLM_MAP = {
    "prompt-extraction": "LLM07 - System Prompt Leakage",
    "excessive-agency":  "LLM06 - Excessive Agency",
    "pii:direct":        "LLM02 - Sensitive Information Disclosure",
    "bola":              "LLM06 - Excessive Agency",
    "bfla":               "LLM06 - Excessive Agency",
    "rbac":              "LLM06 - Excessive Agency",
    "sql-injection":     "LLM05 - Improper Output Handling",
}

_next_id = {"n": 0}


def _new_id(prefix: str) -> str:
    _next_id["n"] += 1
    return f"{prefix}-{_next_id['n']:03d}"


def normalize_semgrep(path: str):
    findings = load_semgrep(path)
    out = []
    for f in findings:
        out.append({
            "id": _new_id("sast"),
            "tool": "Semgrep",
            "source_type": "SAST",
            "title": f.get("rule_id") or f.get("id", "?"),
            "description": f.get("description", ""),
            "owasp_category": f.get("category", "?"),
            "severity": None,   # renseigné par la couche de triage IA
            "confirmed": False,  # statique uniquement, pas d'exploitation active
            "raw": f,
        })
    return out


def normalize_zap(path: str):
    findings = load_zap(path)
    out = []
    for f in findings:
        out.append({
            "id": _new_id("dast"),
            "tool": "OWASP ZAP",
            "source_type": "DAST",
            "title": f.get("name") or f.get("id", "?"),
            "description": f.get("description", ""),
            "owasp_category": f.get("category", "?"),
            "severity": None,
            "confirmed": False,
            "raw": f,
        })
    return out


def normalize_promptfoo(paths):
    out = []
    for path in paths:
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
        except FileNotFoundError:
            continue
        results = data.get("results", {}).get("results", [])
        for r in results:
            if r.get("success", True):
                continue  # ne garder que les échecs (comportement non désiré)
            plugin = r.get("testCase", {}).get("metadata", {}).get(
                "pluginId", "?"
            )
            out.append({
                "id": _new_id("llm"),
                "tool": "Promptfoo",
                "source_type": "LLM-redteam",
                "title": f"Redteam failure — plugin {plugin}",
                "description": r.get("prompt", {}).get("raw", ""),
                "owasp_category": PROMPTFOO_OWASP_LLM_MAP.get(
                    plugin, f"LLM (non mappé: {plugin})"
                ),
                "severity": r.get("testCase", {}).get(
                    "metadata", {}
                ).get("severity", "medium"),
                "confirmed": True,   # comportement observé réellement, pas statique
                "raw": {
                    "plugin": plugin,
                    "response": r.get("response", {}).get("output", ""),
                    "grading_reason": r.get("gradingResult", {}).get(
                        "reason", ""
                    ),
                },
            })
    return out


def normalize_pentestgpt(path: str):
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return []
    out = []
    for f in data.get("findings", []):
        out.append({
            "id": _new_id("pgpt"),
            "tool": "PentestGPT",
            "source_type": "Active-confirmation",
            "title": f.get("title", "?"),
            "description": (
                f"{f.get('endpoint', '')} (param: {f.get('parameter', '')})"
                f" — payload: {f.get('payload', '')}"
            ),
            "owasp_category": f.get("owasp_category", "?"),
            "severity": f.get("severity", "High"),
            "confirmed": f.get("confirmed", True),
            "raw": f,
        })
    return out


def main():
    unified = []
    unified += normalize_semgrep(SEMGREP_FILE)
    unified += normalize_zap(ZAP_FILE)
    unified += normalize_promptfoo(PROMPTFOO_FILES)
    unified += normalize_pentestgpt(PENTESTGPT_FILE)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(unified, fh, indent=2, ensure_ascii=False)

    by_source = {}
    for f in unified:
        by_source[f["source_type"]] = by_source.get(f["source_type"], 0) + 1

    print(f"{len(unified)} findings unifiés, sauvegardés dans {OUTPUT_FILE}")
    print("Répartition par type de source :")
    for src, count in sorted(by_source.items()):
        print(f"  {src:20s} {count}")


if __name__ == "__main__":
    main()
