"""
compare_embeddings.py
Comparaison embeddings local (nomic-embed-text, via Ollama) vs cloud
(gemini-embedding-001, via l'API Gemini) sur les mêmes paires SAST/DAST.

Usage : python compare_embeddings.py
Prérequis :
  - semgrep_combined.json et zap_full_report_v2.json dans le même dossier
  - correlate.py dans le même dossier (réutilisation des mappings et loaders)
  - Ollama actif en local (http://localhost:11434)
  - Variable d'environnement GEMINI_API_KEY définie (clé Gemini, gratuite,
    voir https://aistudio.google.com)
"""

import os
import json
import requests

# Réutilise les mappings et loaders déjà validés dans correlate.py
from correlate import (
    load_semgrep,
    load_zap,
    group_by_category,
    cosine_similarity,
)

OLLAMA_EMBED_URL = "http://localhost:11434/api/embeddings"
LOCAL_MODEL = "nomic-embed-text"

GEMINI_EMBED_URL = (
    "https://generativelanguage.googleapis.com/v1beta/models/"
    "gemini-embedding-001:embedContent"
)
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY")

SEMGREP_FILE = "semgrep_combined.json"
ZAP_FILE = "zap_full_report_v2.json"
OUTPUT_FILE = "embeddings_comparison.json"


def get_local_embedding(text: str):
    """Embedding via Ollama / nomic-embed-text (local, gratuit)."""
    resp = requests.post(
        OLLAMA_EMBED_URL,
        json={"model": LOCAL_MODEL, "prompt": text},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["embedding"]


def get_cloud_embedding(text: str):
    """Embedding via l'API Gemini / gemini-embedding-001 (cloud, gratuit
    dans les limites du tier gratuit : 1500 req/jour, pas de carte requise).
    """
    if not GEMINI_API_KEY:
        raise RuntimeError(
            "GEMINI_API_KEY non définie. Voir instructions dans le "
            "docstring du script."
        )
    headers = {
        "Content-Type": "application/json",
        "x-goog-api-key": GEMINI_API_KEY,
    }
    payload = {
        "content": {"parts": [{"text": text}]},
        # 3072 = dimension par défaut recommandée par Google pour la
        # meilleure qualité ; réduite ici à 768 pour rester comparable
        # en ordre de grandeur à nomic-embed-text (768 dimensions) et
        # limiter la consommation de quota.
        "outputDimensionality": 768,
    }
    resp = requests.post(
        GEMINI_EMBED_URL, headers=headers, json=payload, timeout=30
    )
    resp.raise_for_status()
    return resp.json()["embedding"]["values"]


def compare_pair(sast_desc: str, dast_desc: str):
    """Calcule la similarité cosinus pour une paire SAST/DAST, en local
    et en cloud, et retourne les deux scores + l'écart entre eux."""
    local_sast = get_local_embedding(sast_desc)
    local_dast = get_local_embedding(dast_desc)
    local_score = cosine_similarity(local_sast, local_dast)

    cloud_sast = get_cloud_embedding(sast_desc)
    cloud_dast = get_cloud_embedding(dast_desc)
    cloud_score = cosine_similarity(cloud_sast, cloud_dast)

    return local_score, cloud_score


def main():
    if not GEMINI_API_KEY:
        print(
            "ERREUR : variable d'environnement GEMINI_API_KEY non définie.\n"
            "Définir avec :\n"
            '  [Environment]::SetEnvironmentVariable("GEMINI_API_KEY", '
            '"votre_cle", "User")\n'
            "puis ouvrir un nouveau terminal avant de relancer ce script."
        )
        return

    sast = load_semgrep(SEMGREP_FILE)
    dast = load_zap(ZAP_FILE)
    groups = group_by_category(sast, dast)

    results = []
    print("Comparaison embeddings local (nomic-embed-text) vs cloud "
          "(gemini-embedding-001)\n" + "=" * 70)

    for category, findings in sorted(groups.items()):
        if category == "?":
            continue
        # group_by_category retourne {'sast': [...], 'dast': [...]} par
        # catégorie (structure confirmée par introspection directe sur
        # le fichier réel, différente de l'hypothèse initiale du script)
        cat_sast = findings.get("sast", [])
        cat_dast = findings.get("dast", [])
        if not cat_sast or not cat_dast:
            continue

        print(f"\n=== Catégorie {category} ===")
        for s in cat_sast:
            s_id = s.get("rule_id", s.get("id", "?"))
            for d in cat_dast:
                d_id = d.get("name", d.get("id", "?"))
                local_score, cloud_score = compare_pair(
                    s["description"], d["description"]
                )
                diff = round(cloud_score - local_score, 4)
                print(
                    f"  {s_id:35s} <-> {d_id:35s} | "
                    f"local={local_score:.4f}  cloud={cloud_score:.4f}  "
                    f"écart={diff:+.4f}"
                )
                results.append({
                    "category": category,
                    "sast_id": s_id,
                    "dast_id": d_id,
                    "local_score": round(local_score, 4),
                    "cloud_score": round(cloud_score, 4),
                    "diff": diff,
                })

    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, ensure_ascii=False)

    if results:
        avg_local = sum(r["local_score"] for r in results) / len(results)
        avg_cloud = sum(r["cloud_score"] for r in results) / len(results)
        print("\n" + "=" * 70)
        print(f"Nombre de paires comparées : {len(results)}")
        print(f"Score moyen local (nomic-embed-text) : {avg_local:.4f}")
        print(f"Score moyen cloud (gemini-embedding-001) : {avg_cloud:.4f}")
        print(f"Écart moyen (cloud - local) : {avg_cloud - avg_local:+.4f}")
        print(f"\nRésultats détaillés sauvegardés dans {OUTPUT_FILE}")
    else:
        print("\nAucune paire SAST/DAST comparable trouvée (vérifier que "
              "les fichiers d'entrée sont bien peuplés dans les mêmes "
              "catégories des deux côtés).")


if __name__ == "__main__":
    main()
