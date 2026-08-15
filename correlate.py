"""
correlate.py
SAST (Semgrep) + DAST (ZAP) correlation via OWASP category grouping
and semantic embedding similarity (nomic-embed-text via Ollama).

Updated to consume the widened scan coverage:
- semgrep_combined.json (p/owasp-top-ten + p/security-audit + p/r2c-security-audit + p/auto)
- zap_full_report_v2.json (AJAX spider + full active scan)
"""

import json
import math
import requests

OLLAMA_URL = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
SIMILARITY_THRESHOLD = 0.5

SEMGREP_FILE = "semgrep_combined.json"
ZAP_FILE = "zap_full_report_v2.json"

# ---------------------------------------------------------------------------
# OWASP Top 10:2025 mapping — Semgrep rule -> category
# ---------------------------------------------------------------------------
SEMGREP_OWASP_MAP = {
    # --- Original 10 rules (Week 3 baseline, p/owasp-top-ten) ---
    "github-actions-mutable-action-tag": "A03",  # Software Supply Chain Failures
    "express-sequelize-injection": "A05",         # Injection
    "run-shell-injection": "A03",                 # Software Supply Chain Failures (GitHub Actions)
    "express-check-directory-listing": "A02",     # Security Misconfiguration
    "express-res-sendfile": "A01",                # Broken Access Control
    "npm-missing-minimum-release-age": "A03",     # Software Supply Chain Failures
    "code-string-concat": "A05",                  # Injection
    "hardcoded-jwt-secret": "A04",                # Cryptographic Failures
    "gha-curl-pipe-shell": "A03",                 # Software Supply Chain Failures
    "express-open-redirect": "A01",               # Broken Access Control

    # --- New rules from widened scan (security-audit / r2c-security-audit) ---
    "unquoted-attribute-var": "A05",              # Injection (HTML attr injection / XSS-adjacent)
    "unknown-value-with-script-tag": "A05",       # Injection (XSS vector)
    "unknown-value-in-redirect": "A01",           # Broken Access Control (generic open-redirect pattern)

    # plaintext-http-link intentionally EXCLUDED — 84 occurrences of link-hygiene
    # noise (hardcoded http:// references), not a meaningful app-security signal.
    # See discussion: risks dominating/diluting A04 category numerically.
    # "plaintext-http-link": "A04",
}
# Official 2024 CWE Top 25 Most Dangerous Software Weaknesses (MITRE/CISA)
CWE_TOP_25 = {
    "CWE-79":  "Cross-Site Scripting (XSS)",
    "CWE-787": "Out-of-bounds Write",
    "CWE-89":  "SQL Injection",
    "CWE-352": "Cross-Site Request Forgery (CSRF)",
    "CWE-22":  "Path Traversal",
    "CWE-125": "Out-of-bounds Read",
    "CWE-78":  "OS Command Injection",
    "CWE-416": "Use After Free",
    "CWE-862": "Missing Authorization",
    "CWE-434": "Unrestricted File Upload",
    "CWE-94":  "Code Injection",
    "CWE-20":  "Improper Input Validation",
    "CWE-77":  "Command Injection",
    "CWE-287": "Improper Authentication",
    "CWE-269": "Improper Privilege Management",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-200": "Exposure of Sensitive Information",
    "CWE-863": "Incorrect Authorization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-119": "Improper Restriction of Memory Buffer Operations",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-306": "Missing Authentication for Critical Function",
}

# Full check_id strings as they appear in Semgrep's combined JSON output
# (Semgrep prefixes rule IDs with language/ruleset path). We match on the
# short name at the end of the check_id.
def short_rule_id(check_id: str) -> str:
    """Extract the short rule name from a full Semgrep check_id."""
    return check_id.split(".")[-1]


# ---------------------------------------------------------------------------
# OWASP Top 10:2025 mapping — ZAP alert name -> category
# ---------------------------------------------------------------------------
ZAP_OWASP_MAP = {
    # --- Original 8 categories (Week 3 baseline) ---
    "Backup File Disclosure": "A02",
    "Content Security Policy (CSP) Header Not Set": "A02",
    "Cross-Domain Misconfiguration": "A02",
    "Cross-Origin-Embedder-Policy Header Missing or Invalid": "A02",
    "Cross-Origin-Opener-Policy Header Missing or Invalid": "A02",
    "Dangerous JS Functions": "A02",
    "Deprecated Feature Policy Header Set": "A02",
    "Timestamp Disclosure - Unix": "A02",
    "Bypassing 403": "A01",  # may not appear in every run — kept for continuity

    # --- New alerts from widened scan (AJAX spider + full active scan) ---
    "SQL Injection": "A05",                        # Injection — the key new finding
    "Session ID in URL Rewrite": "A07",             # Authentication Failures
    "Missing Anti-clickjacking Header": "A02",       # Security Misconfiguration
    "Cookie Slack Detector": "A07",                  # Authentication Failures (session handling)
    "X-Content-Type-Options Header Missing": "A02",  # Security Misconfiguration
    "Private IP Disclosure": "A02",                  # Security Misconfiguration
    "Storable and Cacheable Content": "A02",         # Security Misconfiguration
    "Storable but Non-Cacheable Content": "A02",     # Security Misconfiguration

    # Informational / metadata alerts — excluded from correlation (not vulnerabilities)
    # "Modern Web Application": None,
    # "Session Management Response Identified": None,
    # "User Agent Fuzzer": None,
}

# Maps finding rule/alert names to CWE IDs, for findings you want retained
# via CWE Top 25 even if their OWASP category is weak/absent.
FINDING_CWE_MAP = {
    "express-sequelize-injection": "CWE-89",
    "SQL Injection": "CWE-89",
    "express-check-directory-listing": "CWE-200",
    "Backup File Disclosure": "CWE-200",
    "hardcoded-jwt-secret": "CWE-798",
    "express-open-redirect": None,  # not in CWE Top 25 — stays OWASP-only (A01)
    "unknown-value-in-redirect": None,
    "unquoted-attribute-var": "CWE-79",
    "unknown-value-with-script-tag": "CWE-79",
    # add more as you map new findings
}

# ---------------------------------------------------------------------------
# Robust JSON reading (handles Windows cp1252 fallback)
# ---------------------------------------------------------------------------
def read_json_robust(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except UnicodeDecodeError:
        with open(path, "r", encoding="cp1252") as f:
            return json.load(f)


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------
def load_semgrep(path: str):
    """
    Load Semgrep JSON, deduplicate by short rule name, keep only rules
    present in SEMGREP_OWASP_MAP OR mapped to a CWE Top 25 entry,
    attach category + a representative message.
    """
    data = read_json_robust(path)
    seen = {}
    for result in data.get("results", []):
        rule_id = short_rule_id(result.get("check_id", ""))

        if rule_id in SEMGREP_OWASP_MAP:
            category = SEMGREP_OWASP_MAP[rule_id]
        else:
            cwe_id = FINDING_CWE_MAP.get(rule_id)
            if cwe_id and cwe_id in CWE_TOP_25:
                category = cwe_id  # retained via CWE Top 25 fallback
            else:
                continue  # true hygiene noise — skip

        if rule_id in seen:
            continue  # dedupe — keep first occurrence only
        message = result.get("extra", {}).get("message", "")
        seen[rule_id] = {
            "rule_id": rule_id,
            "category": category,
            "description": f"{rule_id}. {message}",
        }
    return list(seen.values())

def load_zap(path: str):
    """
    Load ZAP JSON, keep only alerts present in ZAP_OWASP_MAP OR mapped
    to a CWE Top 25 entry, description = name + solution (Iteration 2b).
    """
    data = read_json_robust(path)
    alerts = data.get("site", [{}])[0].get("alerts", [])
    findings = []
    for alert in alerts:
        name = alert.get("alert", "")

        if name in ZAP_OWASP_MAP:
            category = ZAP_OWASP_MAP[name]
        else:
            cwe_id = FINDING_CWE_MAP.get(name)
            if cwe_id and cwe_id in CWE_TOP_25:
                category = cwe_id  # retained via CWE Top 25 fallback
            else:
                continue  # true hygiene noise — skip

        solution = alert.get("solution", "")
        findings.append({
            "name": name,
            "category": category,
            "description": f"{name}. {solution}",
        })
    return findings
# ---------------------------------------------------------------------------
# Grouping by OWASP category
# ---------------------------------------------------------------------------
def group_by_category(semgrep_findings, zap_findings):
    groups = {}
    for f in semgrep_findings:
        groups.setdefault(f["category"], {"sast": [], "dast": []})
        groups[f["category"]]["sast"].append(f)
    for f in zap_findings:
        groups.setdefault(f["category"], {"sast": [], "dast": []})
        groups[f["category"]]["dast"].append(f)
    return groups

# ---------------------------------------------------------------------------
# Embeddings + cosine similarity (Ollama / nomic-embed-text)
# ---------------------------------------------------------------------------
def get_embedding(text: str):
    resp = requests.post(
        f"{OLLAMA_URL}/api/embeddings",
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=30,
    )
    resp.raise_for_status()
    return resp.json()["embedding"]


def cosine_similarity(vec_a, vec_b):
    dot = sum(a * b for a, b in zip(vec_a, vec_b))
    norm_a = math.sqrt(sum(a * a for a in vec_a))
    norm_b = math.sqrt(sum(b * b for b in vec_b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# (Iteration 1 — kept for reference/documentation, NOT used in main pipeline)
# ---------------------------------------------------------------------------
def ask_ollama_similarity(text_a: str, text_b: str) -> float:
    """
    ECARTEE: LLM self-scoring approach. Returns near-uniform 0.60-0.65
    scores regardless of actual relatedness. Kept for historical reference.
    """
    prompt = (
        f"On a scale of 0 to 1, how related are these two security findings?\n"
        f"A: {text_a}\nB: {text_b}\nRespond with only a number."
    )
    resp = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": "phi3", "prompt": prompt, "stream": False},
        timeout=60,
    )
    resp.raise_for_status()
    try:
        return float(resp.json()["response"].strip())
    except ValueError:
        return 0.0


# ---------------------------------------------------------------------------
# Correlation — best DAST candidate per SAST finding, per category
# ---------------------------------------------------------------------------
def correlate_group(category: str, sast_findings, dast_findings):
    correlations = []
    for sast in sast_findings:
        sast_emb = get_embedding(sast["description"])
        scored = []
        for dast in dast_findings:
            dast_emb = get_embedding(dast["description"])
            score = cosine_similarity(sast_emb, dast_emb)
            scored.append((score, dast))
        scored.sort(key=lambda x: x[0], reverse=True)

        print(f"\nScores pour {sast['rule_id']} (catégorie {category}):")
        for score, dast in scored:
            print(f"  {score:.3f}  {dast['name']}")

        if not scored:
            continue
        best_score, best_dast = scored[0]
        margin = best_score - scored[1][0] if len(scored) > 1 else best_score

        if best_score >= SIMILARITY_THRESHOLD:
            correlations.append({
                "sast_rule": sast["rule_id"],
                "dast_alert": best_dast["name"],
                "score": best_score,
                "margin": margin,
                "category": category,
            })
    return correlations


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    semgrep_findings = load_semgrep(SEMGREP_FILE)
    zap_findings = load_zap(ZAP_FILE)

    print(f"Semgrep findings chargés (mappés): {len(semgrep_findings)}")
    print(f"ZAP findings chargés (mappés): {len(zap_findings)}")

    groups = group_by_category(semgrep_findings, zap_findings)

    all_correlations = []
    for category, findings in sorted(groups.items()):
        sast = findings["sast"]
        dast = findings["dast"]
        if not sast or not dast:
            continue  # need both sides to correlate
        print(f"\n=== Catégorie {category}: {len(sast)} SAST / {len(dast)} DAST ===")
        correlations = correlate_group(category, sast, dast)
        all_correlations.extend(correlations)

    print(f"\n{len(all_correlations)} corrélation(s) trouvée(s) au total :")
    for c in all_correlations:
        print(f"  [{c['category']}] [{c['score']:.3f}, marge={c['margin']:.3f}] "
              f"{c['sast_rule']} <-> {c['dast_alert']}")

    # --- Non-regression test: known reference pair (A02) ---
    reference_found = any(
        c["sast_rule"] == "express-check-directory-listing"
        and c["dast_alert"] == "Backup File Disclosure"
        for c in all_correlations
    )
    print(f"\nCas de référence (directory-listing / backup-file) détecté : {reference_found}")

    # --- New target pair to watch for (A05) ---
    sqli_found = any(
        c["sast_rule"] == "express-sequelize-injection"
        and c["dast_alert"] == "SQL Injection"
        for c in all_correlations
    )
    print(f"Nouveau cas (sequelize-injection / SQL Injection) détecté : {sqli_found}")


if __name__ == "__main__":
    main()