"""
generate_report.py
Génère le rapport final consolidé, audit-ready, à partir de :
  - unified_findings_triaged.json (ou unified_findings.json si le triage
    n'a pas encore été exécuté)
  - la corrélation SAST/DAST (recalculée via les fonctions de correlate.py)
  - embeddings_comparison.json (si présent, section local vs cloud)

Usage : python generate_report.py
Sortie : consolidated_report.md
"""

import json
import os
from datetime import datetime
from correlate import load_semgrep, load_zap, group_by_category, correlate_group

SEMGREP_FILE = "semgrep_combined.json"
ZAP_FILE = "zap_full_report_v2.json"
TRIAGED_FILE = "unified_findings_triaged.json"
FALLBACK_FILE = "unified_findings.json"
EMBEDDINGS_FILE = "embeddings_comparison.json"
OUTPUT_FILE = "consolidated_report.md"

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4, None: 5}


def load_findings():
    path = TRIAGED_FILE if os.path.exists(TRIAGED_FILE) else FALLBACK_FILE
    with open(path, encoding="utf-8") as fh:
        return json.load(fh), path


def get_severity(f):
    t = f.get("triage")
    if t and t.get("severity"):
        raw = t["severity"]
    else:
        raw = f.get("severity") or "Medium"
    # Normalise la casse (Promptfoo renvoie "medium"/"high" en minuscules,
    # les autres sources en Capitalized) pour que le tri et le comptage
    # Critical/High fonctionnent correctement quelle que soit la source.
    return str(raw).strip().capitalize()


def get_verdict(f):
    t = f.get("triage")
    if t:
        return t.get("verdict", "needs_review")
    return "true_positive" if f.get("confirmed") else "needs_review"


def truncate(text, length):
    """Tronque proprement à une limite de mots, avec '...' si coupé."""
    text = (text or "").replace("\n", " ").strip()
    if len(text) <= length:
        return text
    cut = text[:length].rsplit(" ", 1)[0]
    return cut + "..."


def recompute_correlations():
    """Recalcule les corrélations SAST/DAST via correlate.py pour les
    inclure dans le rapport, sans dupliquer sa logique."""
    try:
        sast = load_semgrep(SEMGREP_FILE)
        dast = load_zap(ZAP_FILE)
    except FileNotFoundError:
        return []
    groups = group_by_category(sast, dast)
    all_correlations = []
    for category, findings in groups.items():
        if category == "?":
            continue
        sast_list = findings.get("sast", [])
        dast_list = findings.get("dast", [])
        if not sast_list or not dast_list:
            continue
        all_correlations.extend(
            correlate_group(category, sast_list, dast_list)
        )
    return all_correlations


def load_embeddings_comparison():
    if not os.path.exists(EMBEDDINGS_FILE):
        return None
    with open(EMBEDDINGS_FILE, encoding="utf-8") as fh:
        return json.load(fh)


def build_report(findings, correlations, embeddings):
    lines = []
    now = datetime.now().strftime("%d/%m/%Y")

    # -- En-tête / Résumé exécutif --------------------------------------
    lines.append("# Rapport de sécurité consolidé — OWASP Juice Shop v20")
    lines.append(f"\n**Généré le :** {now}  ")
    lines.append("**Méthodologie :** SAST (Semgrep) + DAST (OWASP ZAP) + "
                  "tests LLM (Promptfoo) + confirmation active (PentestGPT), "
                  "corrélés et priorisés via une couche d'IA locale (Ollama).\n")

    true_pos = [f for f in findings if get_verdict(f) == "true_positive"]
    false_pos = [f for f in findings if get_verdict(f) == "false_positive"]
    needs_review = [f for f in findings if get_verdict(f) == "needs_review"]

    lines.append("## Résumé exécutif\n")
    lines.append(f"- **{len(findings)}** findings bruts analysés au total")
    lines.append(f"- **{len(true_pos)}** vrais positifs retenus")
    lines.append(f"- **{len(false_pos)}** faux positifs écartés par le triage IA")
    lines.append(f"- **{len(needs_review)}** findings nécessitant une revue manuelle")
    lines.append(f"- **{len(correlations)}** corrélations SAST/DAST confirmées")
    critical_high = [f for f in true_pos if get_severity(f) in ("Critical", "High")]
    lines.append(f"- **{len(critical_high)}** findings de sévérité Critical/High parmi les vrais positifs\n")

    # -- Findings vrais positifs, triés par sévérité ---------------------
    lines.append("## Findings retenus (vrais positifs), par sévérité\n")
    true_pos_sorted = sorted(true_pos, key=lambda f: SEVERITY_ORDER.get(get_severity(f), 5))
    lines.append("| Sévérité | Outil | Titre | Catégorie OWASP | Confirmé activement |")
    lines.append("|---|---|---|---|---|")
    for f in true_pos_sorted:
        confirmed = "✅ Oui" if f.get("confirmed") else "Statique"
        lines.append(
            f"| {get_severity(f)} | {f.get('tool','?')} | "
            f"{truncate(f.get('title','?'), 60)} | {f.get('owasp_category','?')} | {confirmed} |"
        )

    # -- Détail des findings confirmés activement (PentestGPT) ----------
    active = [f for f in true_pos if f.get("tool") == "PentestGPT"]
    if active:
        lines.append("\n## Vulnérabilités confirmées par exploitation active (PentestGPT)\n")
        for f in active:
            raw = f.get("raw", {})
            lines.append(f"### {f.get('title')}\n")
            lines.append(f"- **Endpoint :** `{raw.get('endpoint','?')}` (paramètre : `{raw.get('parameter','?')}`)")
            lines.append(f"- **Catégorie OWASP :** {f.get('owasp_category')}")
            lines.append(f"- **Sévérité :** {get_severity(f)}")
            lines.append(f"- **Payload :** `{raw.get('payload','?')}`")
            lines.append(f"- **Preuve :** {raw.get('evidence','?')}")
            if raw.get("corroborates_finding"):
                lines.append(f"- **Corrobore le finding SAST :** `{raw['corroborates_finding']}`")
            if raw.get("secondary_finding"):
                sf = raw["secondary_finding"]
                lines.append(f"- **Finding secondaire :** {sf.get('title')} ({sf.get('owasp_category')}) — {sf.get('detail')}")
            lines.append("")

    # -- Corrélations SAST/DAST ------------------------------------------
    if correlations:
        lines.append("## Corrélations SAST/DAST\n")
        lines.append("| SAST | DAST | Confiance | Marge | Catégorie |")
        lines.append("|---|---|---|---|---|")
        for c in correlations:
            lines.append(
                f"| {c['sast_rule']} | {c['dast_alert']} | "
                f"{c['score']:.3f} | {c['margin']:.3f} | {c['category']} |"
            )
        lines.append(
            "\n*Note méthodologique : une marge proche de 0 signale une "
            "corrélation potentiellement artefactuelle (un seul candidat "
            "DAST disponible dans la catégorie, pas de véritable choix "
            "discriminant). Voir Annexe C du rapport principal pour la "
            "discussion complète.*\n"
        )

    # -- Findings LLM (Promptfoo redteam) --------------------------------
    llm_findings = [f for f in findings if f.get("source_type") == "LLM-redteam"]
    if llm_findings:
        lines.append("## Résultats des tests LLM (Promptfoo redteam)\n")
        lines.append(f"**{len(llm_findings)}** comportements non désirés détectés sur le chatbot.\n")
        lines.append("| Catégorie OWASP LLM | Plugin | Prompt (extrait) |")
        lines.append("|---|---|---|")
        for f in llm_findings:
            plugin = f.get("raw", {}).get("plugin", "?")
            desc = truncate(f.get("description", ""), 80)
            lines.append(f"| {f.get('owasp_category')} | {plugin} | {desc} |")
        lines.append("")

    # -- Faux positifs écartés (transparence méthodologique) -------------
    if false_pos:
        lines.append("## Faux positifs écartés par le triage IA\n")
        lines.append("| Outil | Titre | Justification IA |")
        lines.append("|---|---|---|")
        for f in false_pos:
            just = truncate(f.get("triage", {}).get("justification", ""), 100)
            lines.append(f"| {f.get('tool')} | {truncate(f.get('title','?'), 50)} | {just} |")
        lines.append("")

    # -- Comparaison embeddings local vs cloud ---------------------------
    if embeddings:
        avg_local = sum(r["local_score"] for r in embeddings) / len(embeddings)
        avg_cloud = sum(r["cloud_score"] for r in embeddings) / len(embeddings)
        lines.append("## Comparaison embeddings local vs cloud\n")
        lines.append(f"- Paires comparées : {len(embeddings)}")
        lines.append(f"- Score moyen local (nomic-embed-text) : {avg_local:.4f}")
        lines.append(f"- Score moyen cloud (gemini-embedding-001) : {avg_cloud:.4f}")
        lines.append(f"- Écart moyen (cloud - local) : {avg_cloud - avg_local:+.4f}\n")

    # -- Findings à revoir manuellement -----------------------------------
    if needs_review:
        lines.append("## Findings nécessitant une revue manuelle\n")
        lines.append(f"**{len(needs_review)}** findings où le triage IA n'a pas pu trancher "
                      "avec confiance — à examiner manuellement avant intégration au rapport final.\n")

    return "\n".join(lines)


def main():
    findings, source = load_findings()
    print(f"Chargement de {len(findings)} findings depuis {source}")

    correlations = recompute_correlations()
    print(f"{len(correlations)} corrélations SAST/DAST recalculées")

    embeddings = load_embeddings_comparison()
    if embeddings:
        print(f"{len(embeddings)} comparaisons d'embeddings chargées")

    report = build_report(findings, correlations, embeddings)

    with open(OUTPUT_FILE, "w", encoding="utf-8") as fh:
        fh.write(report)

    print(f"\nRapport généré : {OUTPUT_FILE}")


if __name__ == "__main__":
    main()
