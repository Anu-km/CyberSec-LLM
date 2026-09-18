import os, json, glob

RAW_DIR = r"E:\LLm\cyber10gb\raw\nvd_raw"
OUT_FILE = r"E:\LLm\cyber10gb\processed\nvd_text.txt"

os.makedirs(os.path.dirname(OUT_FILE), exist_ok=True)

def extract_cves_from_file(path):
    texts = []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        data = json.load(f)

    vulns = data.get("vulnerabilities", [])
    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "UNKNOWN-CVE")

        descs = cve.get("descriptions", [])
        desc_en = ""
        for d in descs:
            if d.get("lang") == "en":
                desc_en = d.get("value", "")
                break

        metrics = cve.get("metrics", {})
        score = ""
        if "cvssMetricV31" in metrics:
            score = str(metrics["cvssMetricV31"][0]["cvssData"].get("baseScore", ""))
        elif "cvssMetricV30" in metrics:
            score = str(metrics["cvssMetricV30"][0]["cvssData"].get("baseScore", ""))
        elif "cvssMetricV2" in metrics:
            score = str(metrics["cvssMetricV2"][0]["cvssData"].get("baseScore", ""))

        cwes = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                if d.get("lang") == "en":
                    cwes.append(d.get("value"))

        refs = []
        for r in cve.get("references", []):
            if "url" in r:
                refs.append(r["url"])

        text = f"CVE ID: {cve_id}. Description: {desc_en}. CVSS Score: {score}. Weaknesses: {', '.join(cwes)}."
        texts.append(text)

    return texts

all_text = []
json_files = glob.glob(os.path.join(RAW_DIR, "*.json"))
print(f"Found {len(json_files)} NVD JSON files")

for jf in json_files:
    print("Processing:", jf)
    try:
        all_text.extend(extract_cves_from_file(jf))
    except Exception as e:
        print("❌ Error:", jf, e)

with open(OUT_FILE, "w", encoding="utf-8") as out:
    for line in all_text:
        if line.strip():
            out.write(line.replace("\n", " ") + "\n")

print("✅ NVD JSON converted to text:", OUT_FILE)
print("Total CVE lines:", len(all_text))
