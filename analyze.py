"""
Analyzes Wazuh SIEM alerts by enriching them with CVE context via RAG.

Loads a daily alert export from Wazuh, groups alerts by rule, retrieves semantically
related CVEs from a local ChromaDB vector database, and generates a detailed security
report using a local LLM served by Ollama.

Usage:
    python3 analyze.py <path-to-alerts.json[.gz]>
"""

import gzip
import json
import logging
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import chromadb
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

CHROMA_PATH = Path(__file__).parent / "cve_db"
OLLAMA_URL = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
LLM_MODEL = "qwen2.5-coder:14b-instruct"
MIN_LEVEL = 7       # ignore alerts below this severity (1–15 scale)
TOP_K_CVES = 5      # related CVEs to retrieve per alert group


def embed(text: str) -> list[float]:
    r = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": EMBED_MODEL, "input": [text]},
        timeout=60,
    )
    r.raise_for_status()
    return r.json()["embeddings"][0]


def llm(prompt: str) -> str:
    r = requests.post(
        f"{OLLAMA_URL}/api/generate",
        json={"model": LLM_MODEL, "prompt": prompt, "stream": False},
        timeout=300,
    )
    r.raise_for_status()
    return r.json()["response"].strip()


def query_cves(
    collection: chromadb.Collection, query_text: str, top_k: int = TOP_K_CVES
) -> list[dict]:
    q_emb = embed(query_text)
    results = collection.query(
        query_embeddings=[q_emb],
        n_results=top_k,
        include=["documents", "metadatas"],
    )
    return [
        {"text": doc, "metadata": meta}
        for doc, meta in zip(results["documents"][0], results["metadatas"][0])
    ]


def load_alerts(path: Path) -> list[dict]:
    alerts = []
    opener = gzip.open if str(path).endswith(".gz") else open
    with opener(path, "rt") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                alerts.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return alerts


def group_alerts(alerts: list[dict], min_level: int) -> dict:
    groups: dict = defaultdict(
        lambda: {"rule": None, "agents": set(), "logs": [], "count": 0}
    )
    for alert in alerts:
        level = alert.get("rule", {}).get("level", 0)
        if level < min_level:
            continue
        rule_id = alert["rule"]["id"]
        g = groups[rule_id]
        g["rule"] = alert["rule"]
        g["count"] += 1
        agent = alert.get("agent", {})
        g["agents"].add(f"{agent.get('name', '?')} ({agent.get('ip', '?')})")
        if len(g["logs"]) < 3:  # keep up to 3 sample logs per rule
            g["logs"].append(alert.get("full_log", ""))
    return groups


def analyze_group(rule_id: str, group: dict, collection: chromadb.Collection) -> dict:
    rule = group["rule"]
    description = rule.get("description", "")
    groups_tags = ", ".join(rule.get("groups", []))
    level = rule.get("level", 0)
    agents = ", ".join(sorted(group["agents"]))
    count = group["count"]
    sample_logs = "\n".join(f"  - {l}" for l in group["logs"] if l)

    compliance = []
    for framework in ("pci_dss", "gdpr", "hipaa", "nist_800_53", "tsc"):
        tags = rule.get(framework, [])
        if tags:
            compliance.append(f"{framework.upper()}: {', '.join(tags)}")
    compliance_str = "\n".join(compliance) if compliance else "None flagged"

    cves = query_cves(collection, f"{description} {groups_tags}")
    cve_context = "\n\n".join(c["text"] for c in cves)

    prompt = f"""<|im_start|>system
You are a senior cybersecurity analyst writing a security report. When given an alert, you write a detailed, structured analysis. You always complete your full analysis and never repeat the instructions back.<|im_end|>
<|im_start|>user
Analyze this Wazuh SIEM alert and write a detailed security report.

ALERT DETAILS:
- Rule ID: {rule_id}
- Description: {description}
- Severity: {level}/15
- Categories: {groups_tags}
- Triggered: {count} time(s)
- Affected Agents: {agents}

SAMPLE LOGS:
{sample_logs}

COMPLIANCE FRAMEWORKS TRIGGERED:
{compliance_str}

RELATED CVEs FROM KNOWLEDGE BASE:
{cve_context}

Write your analysis covering: (1) what triggered this alert and what it means, (2) the security risk and potential impact, (3) which agents are most at risk, (4) how the related CVEs connect to this alert, (5) immediate actions to take, (6) long-term remediation.<|im_end|>
<|im_start|>assistant
"""

    response = llm(prompt)
    return {
        "rule_id": rule_id,
        "level": level,
        "description": description,
        "count": count,
        "agents": sorted(group["agents"]),
        "related_cves": [c["text"].split("\n")[0] for c in cves],
        "analysis": response,
    }


def write_report(results: list[dict], output_path: Path) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "# Wazuh Alert Analysis Report",
        f"Generated: {now}  ",
        f"Total alert groups analyzed: {len(results)}  ",
        "",
    ]

    for r in sorted(results, key=lambda x: -x["level"]):
        lines += [
            "---",
            f"## [{r['level']}/15] Rule {r['rule_id']}: {r['description']}",
            f"**Triggered:** {r['count']} time(s)  ",
            f"**Affected agents:** {', '.join(r['agents'])}  ",
            f"**Related CVEs:** {', '.join(r['related_cves'])}",
            "",
            r["analysis"],
            "",
        ]

    output_path.write_text("\n".join(lines))
    logger.info("Report written to %s", output_path)


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python3 analyze.py <path-to-alerts.json[.gz]>")
        sys.exit(1)

    alerts_path = Path(sys.argv[1])
    if not alerts_path.exists():
        logger.error("File not found: %s", alerts_path)
        sys.exit(1)

    logger.info("Loading alerts from %s...", alerts_path)
    alerts = load_alerts(alerts_path)
    logger.info("%d total alerts loaded", len(alerts))

    groups = group_alerts(alerts, MIN_LEVEL)
    logger.info("%d unique rule groups at level >= %d", len(groups), MIN_LEVEL)

    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_collection("cves")
    logger.info("ChromaDB ready (%d CVEs)", collection.count())

    results = []
    sorted_groups = sorted(groups.items(), key=lambda x: -x[1]["rule"]["level"])
    for i, (rule_id, group) in enumerate(sorted_groups, 1):
        desc = group["rule"]["description"]
        level = group["rule"]["level"]
        logger.info("[%d/%d] Level %d - %s...", i, len(groups), level, desc[:60])
        result = analyze_group(rule_id, group, collection)
        results.append(result)

    output_path = alerts_path.parent / f"report-{alerts_path.stem}.md"
    write_report(results, output_path)


if __name__ == "__main__":
    main()
