"""
Converts raw MITRE CVE JSON files into flat text records for embedding.

The raw MITRE files are one JSON per CVE, deeply nested, inconsistent across years,
and contain noise (HTML formatting, duplicate fields, ADP enrichment data). This module
is the translation layer between raw MITRE data and something the AI pipeline can use.
"""

import json
import logging
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

CVE_ROOT = Path(__file__).parent / "cvelistV5" / "cves"
OUTPUT_FILE = Path(__file__).parent / "cve_processed.jsonl"


def extract_cvss(metrics: list[dict]) -> tuple[float | None, str]:
    for m in metrics:
        for key in ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0"):
            if key in m:
                score = m[key].get("baseScore")
                severity = m[key].get("baseSeverity", "")
                return score, severity
    return None, ""


def cve_to_record(cve_json: dict) -> dict:
    meta = cve_json.get("cveMetadata", {})
    cve_id = meta.get("cveId", "")
    state = meta.get("state", "")
    date_published = meta.get("datePublished", "")
    year = cve_id.split("-")[1] if cve_id else ""

    cna = cve_json.get("containers", {}).get("cna", {})

    description = ""
    for d in cna.get("descriptions", []):
        if d.get("lang", "").startswith("en"):
            description = d.get("value", "").strip()
            break

    affected_parts = []
    for a in cna.get("affected", []):
        vendor = a.get("vendor", "")
        product = a.get("product", "")
        if vendor or product:
            affected_parts.append(f"{vendor} {product}".strip())
    affected = ", ".join(dict.fromkeys(affected_parts))  # deduplicate, preserve order

    cvss_score, severity = extract_cvss(cna.get("metrics", []))

    cwes = []
    for pt in cna.get("problemTypes", []):
        for d in pt.get("descriptions", []):
            cwe = d.get("cweId", "")
            if cwe:
                cwes.append(cwe)

    title = cna.get("title", "")

    parts = [f"CVE ID: {cve_id}"]
    if title:
        parts.append(f"Title: {title}")
    if affected:
        parts.append(f"Affected: {affected}")
    if severity and cvss_score is not None:
        parts.append(f"Severity: {severity} (CVSS {cvss_score})")
    if cwes:
        parts.append(f"CWE: {', '.join(cwes)}")
    if description:
        parts.append(f"Description: {description}")

    text = "\n".join(parts)

    return {
        "id": cve_id,
        "text": text,
        "metadata": {
            "year": year,
            "state": state,
            "date_published": date_published,
            "severity": severity,
            "cvss_score": cvss_score,
            "affected": affected,
            "cwes": cwes,
        },
    }


def main() -> None:
    files = sorted(CVE_ROOT.rglob("CVE-*.json"))
    total = len(files)
    logger.info("Found %d CVE files. Processing...", total)

    skipped = 0
    written = 0

    with OUTPUT_FILE.open("w") as out:
        for i, path in enumerate(files, 1):
            try:
                cve_json = json.loads(path.read_text())
                record = cve_to_record(cve_json)
                if not record["text"].strip():
                    skipped += 1
                    continue
                out.write(json.dumps(record) + "\n")
                written += 1
            except Exception as e:
                logger.warning("Error processing %s: %s", path.name, e)
                skipped += 1

            if i % 10000 == 0:
                logger.info(
                    "%d/%d processed (%d written, %d skipped)...",
                    i, total, written, skipped,
                )

    logger.info("Done. %d records written to %s", written, OUTPUT_FILE)
    logger.info("Skipped: %d", skipped)


if __name__ == "__main__":
    main()
