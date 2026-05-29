# CVE RAG — Wazuh Alert Analyzer

An automated security pipeline that enriches Wazuh SIEM alerts with CVE knowledge using Retrieval Augmented Generation (RAG). Every night it pulls the latest alerts from the Wazuh server, finds related vulnerabilities from a local CVE database, and generates a detailed security analysis report using a local LLM — no data leaves the network.

---

## What It Does

1. Pulls daily alert files from the Wazuh SIEM server over SSH
2. Filters alerts by severity (level 7+ on Wazuh's 1–15 scale)
3. Groups repeated alerts by rule to avoid redundant analysis
4. For each alert group, searches a local vector database of 353,000+ CVEs for semantically related vulnerabilities
5. Sends the alert details + matching CVEs to a local LLM for analysis
6. Writes a markdown report covering risks, affected machines, and remediation steps

---

## Architecture

```
Wazuh SIEM Server (<WAZUH_SERVER_IP>)
        |
        | rsync over SSH (daily at 00:05)
        |
        v
LLM Server (<LLM_SERVER_IP>)
        |
        |-- alerts/ossec-alerts-DD.json.gz
        |
        v
  analyze.py
        |
        |-- embed alert description
        |        |
        |        v
        |   nomic-embed-text (Ollama)
        |        |
        |        v
        |   ChromaDB vector search
        |        |
        |        v
        |   top-5 related CVEs
        |
        |-- build prompt (alert + CVEs)
        |        |
        |        v
        |   qwen2.5-coder:14b (Ollama)
        |        |
        |        v
        v
  reports/report-ossec-alerts-DD.md
```

---

## Technologies

| Component | Technology | Purpose |
|-----------|-----------|---------|
| SIEM | [Wazuh](https://wazuh.com) | Collects security events from agents across the network |
| CVE Data | [MITRE CVE List v5](https://github.com/CVEProject/cvelistV5) | 353,000+ vulnerability records in JSON format |
| Embeddings | [nomic-embed-text](https://ollama.com/library/nomic-embed-text) via Ollama | Converts text to vectors for semantic search |
| Vector Database | [ChromaDB](https://www.trychroma.com) | Stores and searches CVE embeddings |
| LLM | [qwen2.5-coder:14b](https://ollama.com/library/qwen2.5-coder) via Ollama | Generates the security analysis |
| Inference Server | [Ollama](https://ollama.com) (Docker) | Serves embedding and LLM models locally |
| Transfer | rsync over SSH | Securely pulls alert files from Wazuh server |
| Automation | cron | Runs the full pipeline nightly |

---

## Project Structure

```
cveRAG/
├── scrapper.py          # Converts raw MITRE CVE JSONs into flat text records
├── embed_store.py       # Embeds CVE records and stores them in ChromaDB
├── analyze.py           # Main analyzer: reads alerts, queries CVEs, generates report
├── sync_and_analyze.sh  # Cron script: rsync from Wazuh + run analyzer (LLM server)
├── export_alerts.sh     # Cron script: export today's alerts to ~/alerts/ (Wazuh server)
├── cvelistV5/           # Cloned MITRE CVE repository (353,000+ JSON files)
├── cve_processed.jsonl  # Processed CVE records (one per line)
├── cve_db/              # ChromaDB persistent storage
├── alerts/              # Incoming Wazuh alert files
└── reports/             # Generated analysis reports
```

---

## Setup

### Prerequisites
- Python 3.12+
- Docker with Ollama container running on port 11434
- SSH access between LLM server and Wazuh server

### 1. Clone CVE data and process it

```bash
git clone https://github.com/CVEProject/cvelistV5.git
python3 scrapper.py
```

### 2. Set up Python environment and embed CVEs

```bash
python3 -m venv venv
source venv/bin/activate
pip install chromadb requests

# Pull the embedding model
docker exec ollama ollama pull nomic-embed-text

python3 embed_store.py   # takes ~35 minutes for 353k CVEs
```

### 3. Pull the LLM

```bash
docker exec ollama ollama pull qwen2.5-coder:14b-instruct
```

### 4. Set up SSH key from LLM server to Wazuh server

```bash
ssh-keygen -t ed25519 -f ~/.ssh/wazuh_key -N ""
ssh-copy-id -i ~/.ssh/wazuh_key.pub <user>@<WAZUH_SERVER_IP>
```

### 5. Set up cron jobs

**On the Wazuh server** — export alerts daily at 00:05:
```bash
echo '5 0 * * * sudo /home/user/export_alerts.sh' | crontab -
```

**On the LLM server** — sync and analyze daily at 00:30:
```bash
echo '30 0 * * * /home/user/cveRAG/sync_and_analyze.sh' | crontab -
```

---

## Usage

**Run manually against an alert file:**
```bash
source venv/bin/activate
python3 analyze.py alerts/ossec-alerts-28.json
```

**View the report:**
```bash
cat reports/report-ossec-alerts-28.md
```

---

## How RAG Works in This Project

RAG (Retrieval Augmented Generation) is what connects the Wazuh alerts to the CVE knowledge base:

1. **Retrieval** — the alert description is embedded into a vector and used to search ChromaDB for the 5 most semantically similar CVEs
2. **Augmented** — those CVEs are injected into the LLM prompt as context
3. **Generation** — the LLM writes its analysis grounded in both the alert data and real CVE knowledge

This means the LLM does not rely solely on its training data. It gets up-to-date, specific vulnerability context at query time, which produces more accurate and actionable reports.

---

## Alert Severity Scale (Wazuh)

| Level | Meaning |
|-------|---------|
| 1–3 | Informational |
| 4–6 | Low — normal system activity |
| 7–9 | Medium — worth investigating |
| 10–12 | High — requires action |
| 13–15 | Critical — immediate response needed |

This pipeline filters to **level 7 and above** by default. Change `MIN_LEVEL` in `analyze.py` to adjust.
