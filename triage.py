"""
triage.py
Couche de triage assistée par IA : pour chaque finding de unified_findings.json,
demande au LLM local (llama3.2:3b via Ollama) de juger s'il s'agit d'un
vrai positif exploitable ou d'un faux positif / bruit, avec justification
et sévérité proposée. Généralise le jugement manuel déjà appliqué à
plaintext-http-link (voir correlate.py) en un processus reproductible.

Usage : python triage.py
Prérequis : unified_findings.json (généré par unified_findings.py),
            Ollama actif en local avec llama3.2:3b.
Sortie : unified_findings_triaged.json
"""

import json
import re
import requests

INPUT_FILE = "unified_findings.json"
OUTPUT_FILE = "unified_findings_triaged.json"
OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "llama3.2:3b"

TRIAGE_PROMPT = """Tu es un expert en cybersécurité applicative qui aide à trier des résultats de scan de sécurité.

Voici un finding détecté par l'outil {tool} (type: {source_type}) :
Titre : {title}
Catégorie OWASP : {owasp_category}
Description : {description}

Évalue ce finding et réponds UNIQUEMENT avec un objet JSON valide, rien d'autre, au format exact suivant :
{{"verdict": "true_positive" ou "false_positive" ou "needs_review", "severity": "Critical" ou "High" ou "Medium" ou "Low" ou "Info", "justification": "une phrase courte expliquant ton verdict"}}
"""


def get_triage(finding: dict, timeout: int = 120) -> dict:
    prompt = TRIAGE_PROMPT.format(
        tool=finding.get("tool", "?"),
        source_type=finding.get("source_type", "?"),
        title=finding.get("title", "?"),
        owasp_category=finding.get("owasp_category", "?"),
        description=(finding.get("description", "") or "")[:800],
    )
    resp = requests.post(
        OLLAMA_URL,
        json={"model": MODEL, "prompt": prompt, "stream": False},
        timeout=timeout,
    )
    resp.raise_for_status()
    text = resp.json().get("response", "").strip()

    # Le modèle local ajoute parfois du texte autour du JSON malgré la
    # consigne "UNIQUEMENT" — extraction défensive du premier bloc {...}.
    match = re.search(r"\{.*\}", text, re.DOTALL)
    if not match:
        return {
            "verdict": "needs_review",
            "severity": "Medium",
            "justification": f"Réponse LLM non parsable, revue manuelle requise. Brut: {text[:200]}",
        }
    try:
        parsed = json.loads(match.group(0))
        return {
            "verdict": parsed.get("verdict", "needs_review"),
            "severity": parsed.get("severity", "Medium"),
            "justification": parsed.get("justification", ""),
        }
    except json.JSONDecodeError:
        return {
            "verdict": "needs_review",
            "severity": "Medium",
            "justification": f"JSON invalide retourné par le LLM. Brut: {text[:200]}",
        }


def main():
    with open(INPUT_FILE, encoding="utf-8") as fh:
        findings = json.load(fh)

    print(f"Triage IA de {len(findings)} findings via {MODEL}...\n")

    # Appel de préchauffage : absorbe le délai de chargement à froid du
    # modèle (observé >60s sur CPU, cause des erreurs de connexion
    # précédentes) avant de démarrer la vraie boucle de triage, avec un
    # timeout généreux réservé à ce seul appel.
    print("Préchauffage du modèle (peut prendre 1-3 min au premier chargement)...")
    try:
        get_triage(
            {"tool": "warmup", "source_type": "warmup", "title": "warmup",
             "owasp_category": "?", "description": "test"},
            timeout=240,
        )
        print("Modèle chargé, démarrage du triage.\n")
    except requests.exceptions.RequestException as e:
        print(f"Échec du préchauffage ({e}) — vérifier qu'Ollama est actif.")
        return

    counts = {"true_positive": 0, "false_positive": 0, "needs_review": 0}

    for i, f in enumerate(findings, 1):
        # Les findings déjà confirmés activement (PentestGPT, Promptfoo
        # redteam observé) n'ont pas besoin d'un jugement LLM sur leur
        # réalité — seuls les findings purement statiques/passifs
        # (Semgrep, ZAP) bénéficient réellement du triage.
        if f.get("confirmed"):
            f["triage"] = {
                "verdict": "true_positive",
                "severity": f.get("severity") or "High",
                "justification": "Comportement confirmé activement (PentestGPT ou observation directe redteam), pas besoin de triage LLM.",
            }
            counts["true_positive"] += 1
            print(f"  [{i}/{len(findings)}] {f['id']:10s} — déjà confirmé, skip triage")
            continue

        triage = get_triage(f)
        f["triage"] = triage
        counts[triage["verdict"]] = counts.get(triage["verdict"], 0) + 1
        print(f"  [{i}/{len(findings)}] {f['id']:10s} — {triage['verdict']:15s} ({triage['severity']})")

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=2, ensure_ascii=False)

    print(f"\nRésultats sauvegardés dans {OUTPUT_FILE}")
    print("Répartition des verdicts :")
    for verdict, count in counts.items():
        print(f"  {verdict:15s} {count}")


if __name__ == "__main__":
    main()
