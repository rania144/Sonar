import requests
import datetime
import os
import re
from db import insert_vuln

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


# =========================
# 🧹 CLEAN TEXT
# =========================
def clean_description(text):
    text = re.sub(r"\s+", " ", text)
    return text.strip()


# =========================
# 🔎 FETCH CVES
# =========================
def fetch_cves():
    now = datetime.datetime.now(datetime.timezone.utc)
    last_week = now - datetime.timedelta(days=7)

    params = {
        "pubStartDate": last_week.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "resultsPerPage": 20
    }

    response = requests.get(NVD_API_URL, params=params, timeout=30)

    if response.status_code != 200:
        print("❌ NVD API error:", response.status_code)
        return []

    return response.json().get("vulnerabilities", [])


# =========================
# 📊 CVSS EXTRACTION
# =========================
def extract_cvss(cve_item):
    try:
        metrics = cve_item["cve"]["metrics"]

        if "cvssMetricV31" in metrics:
            return float(metrics["cvssMetricV31"][0]["cvssData"]["baseScore"])

        if "cvssMetricV30" in metrics:
            return float(metrics["cvssMetricV30"][0]["cvssData"]["baseScore"])

    except Exception:
        pass

    return 0.0


# =========================
# 🏷 CLASSIFICATION
# =========================
def classify(score):
    if score == 0:
        return "NO DATA"
    elif score < 4:
        return "LOW"
    elif score < 7:
        return "MEDIUM"
    elif score < 9:
        return "HIGH"
    else:
        return "CRITICAL"


# =========================
# 🚫 FILTER INVALID CVE
# =========================
def is_valid_cve(score, description):
    if score == 0:
        return False
    if "Rejected reason" in description:
        return False
    return True


# =========================
# 🧠 PROCESS CVES
# =========================
def process_cves(cves):
    results = []

    for item in cves:
        try:
            cve_id = item["cve"]["id"]

            description_raw = item["cve"]["descriptions"][0]["value"]
            description = clean_description(description_raw)

            score = extract_cvss(item)
            level = classify(score)

            if not is_valid_cve(score, description):
                continue

            results.append({
                "cve": cve_id,
                "description": description,
                "score": score,
                "level": level
            })

        except Exception:
            continue

    return results


# =========================
# 🚨 ANSIBLE TRIGGER
# =========================
def trigger_ansible():
    print("🚨 CRITICAL detected → launching Ansible remediation")
    os.system("ansible-playbook -i inventory.ini docker.yml")


# =========================
# 🚀 MAIN PIPELINE
# =========================
def run():
    print("🔎 Fetching CVEs from NVD...\n")

    cves = fetch_cves()
    results = process_cves(cves)

    print("📊 Vulnerabilities detected:\n")

    for r in results:
        print(f"{r['cve']} | CVSS: {r['score']} | {r['level']}")
        print(f"   ➜ {r['description'][:120]}")
        print("-" * 80)

        # 💾 INSERT DB
        insert_vuln(
            r["cve"],
            r["description"],
            r["score"],
            r["level"]
        )

        # ⚠️ AUTO REMEDIATION
        if r["level"] == "CRITICAL":
            trigger_ansible()


# =========================
# ▶ EXECUTION
# =========================
if __name__ == "__main__":
    run()
