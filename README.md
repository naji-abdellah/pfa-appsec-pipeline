# PFA AppSec Pipeline

**Évaluation de la Sécurité Applicative Assistée par IA**
À l'intersection de l'AppSec/Pentesting, du DevSecOps et de l'OWASP AI

Projet de Fin d'Année — ENSEM Casablanca, Génie Logiciel et Digitalisation
Stage effectué chez **CIH Bank**, encadré par M. Oussama Azzam

---

## Le problème

Les outils de test de sécurité fonctionnent en silos : SAST, DAST, tests LLM et confirmation active par pentest produisent chacun leur propre rapport, dans leur propre format, avec leur propre vocabulaire. Un analyste doit croiser ces rapports manuellement pour identifier les vulnérabilités réellement critiques — une tâche lente et source d'erreurs.

## La solution

Une couche de **corrélation et de priorisation assistée par IA**, orchestrant quatre outils existants sans les remplacer :

| Outil | Rôle |
|---|---|
| [Semgrep](https://semgrep.dev/) | SAST — analyse statique du code |
| [OWASP ZAP](https://www.zaproxy.org/) | DAST — analyse dynamique |
| [Promptfoo](https://www.promptfoo.dev/) | Red teaming des chatbots LLM |
| [PentestGPT](https://github.com/GreyDGL/PentestGPT) | Confirmation active des vulnérabilités |

La corrélation entre findings SAST/DAST est réalisée par **similarité cosinus sur des embeddings sémantiques** (nomic-embed-text via Ollama, en local), et non par un simple matching par mots-clés — voir la section Résultats pour la preuve empirique de cette nécessité.

## Architecture du pipeline

```
[Scan] → [Normalisation] → [Corrélation] → [Triage IA] → [Rapport & Dashboard]
```

1. **Scan** — les quatre outils s'exécutent sur la cible
2. **Normalisation** (`unified_findings.py`) — unifie les sorties dans un schéma JSON commun
3. **Corrélation** (`correlate.py`) — identifie les paires SAST/DAST liées via embeddings
4. **Triage IA** (`triage.py`) — classe chaque finding via `llama3.2:3b` (Ollama local) : `true_positive` / `false_positive` / `needs_review`
5. **Rapport** (`generate_report.py`) — produit un rapport consolidé, visualisé via un dashboard Streamlit

Le pipeline est intégré à un workflow **CI/CD sur GitHub Actions**, avec un job SAST rapide sur chaque push et un pipeline complet nocturne/manuel, protégé par un security gate qui bloque le build en cas de vulnérabilité Critical/High non résolue.

## Cibles testées

- **[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/)** (v20) — Node.js/Angular, cible principale, inclut un chatbot IA
- **[OWASP WebGoat](https://owasp.org/www-project-webgoat/)** — Java/Spring, cible de généralisation

*(Ces deux applications sont des projets OWASP volontairement vulnérables, utilisés à des fins d'entraînement et de recherche en sécurité — non inclus dans ce dépôt, disponibles via leurs dépôts officiels.)*

## Résultats clés

- **5 corrélations SAST/DAST** confirmées sur Juice Shop (scores 0.53 – 0.72)
- **2 corrélations record sur WebGoat** : 0.744 et 0.788 — portabilité démontrée sur une seconde stack technique
- **Bypass d'authentification administrateur complet**, via injection SQL (`' OR 1=1--`), avec exposition secondaire d'un hash MD5
- **16 comportements LLM non désirés** mappés à l'OWASP LLM Top 10
- **Embeddings vs mots-clés** : 100 % de rappel pour les embeddings sémantiques, contre seulement **28,6 %** pour un matching par mots-clés sur les mêmes 7 paires validées — preuve empirique que cette approche est une nécessité méthodologique, pas un choix de confort
- **Pipeline CI/CD opérationnel** (~26 min pour le pipeline complet, ~1min22 pour le SAST rapide), avec gate de sécurité validé dans les deux scénarios (blocage et passage)

## Stack technique

- **Langage** : Python 3.10+
- **IA locale** : Ollama (`llama3.2:3b` pour le triage, `nomic-embed-text` pour les embeddings)
- **Conteneurisation** : Docker
- **Dashboard** : Streamlit
- **CI/CD** : GitHub Actions
- **Environnement** : WSL2 (Ubuntu), Windows 11, 8 Go RAM — budget nul, 100 % open-source

## Limites connues

- Le modèle local (3B paramètres) assiste la revue humaine, il ne la remplace pas — 2 corrections manuelles nécessaires sur WebGoat
- Couverture DAST réduite sur les applications modernes en Single Page Application
- Échantillon de 7 corrélations validées — démonstration de faisabilité, pas encore une validation statistique à grande échelle

## Structure du dépôt

```
pfa-appsec-pipeline/
├── unified_findings.py          # Normalisation des résultats des 4 outils
├── correlate.py                 # Corrélation SAST/DAST par embeddings
├── triage.py                    # Triage IA (verdict par finding)
├── generate_report.py           # Génération du rapport consolidé
├── baseline_keyword_matching.py # Baseline de comparaison (embeddings vs mots-clés)
├── .github/workflows/           # Pipelines CI/CD (sast, full-pipeline)
└── README.md
```

## Auteur

**Naji Abdellah** — Génie Logiciel et Digitalisation, ENSEM Casablanca
[LinkedIn](#) · [GitHub](https://github.com/naji-abdellah)
