#!/bin/bash
# Runs on the LLM server at 00:30 daily.
# Pulls yesterday's alert file from Wazuh, runs the analyzer, saves the report.

set -euo pipefail

readonly WAZUH_HOST="sysadmin@<WAZUH_SERVER_IP>"
readonly SSH_KEY="$HOME/.ssh/wazuh_key"
readonly REMOTE_ALERTS="/home/sysadmin/alerts/"
readonly LOCAL_ALERTS="$HOME/cveRAG/alerts/"
readonly REPORTS_DIR="$HOME/cveRAG/reports/"
readonly VENV="$HOME/cveRAG/venv/bin/python3"
readonly ANALYZER="$HOME/cveRAG/analyze.py"
readonly LOG="$HOME/cveRAG/sync.log"

DAY=$(date -d "yesterday" +%d)
readonly FILENAME="ossec-alerts-${DAY}.json.gz"
readonly ALERT_PATH="${LOCAL_ALERTS}${FILENAME}"
readonly REPORT="${LOCAL_ALERTS}report-ossec-alerts-${DAY}.md"

mkdir -p "$LOCAL_ALERTS" "$REPORTS_DIR"

echo "$(date): Starting sync" >> "$LOG"

if ! rsync -az -e "ssh -i $SSH_KEY" \
    "${WAZUH_HOST}:${REMOTE_ALERTS}${FILENAME}" \
    "$LOCAL_ALERTS"; then
    echo "$(date): rsync failed for $FILENAME" >> "$LOG"
    exit 1
fi

echo "$(date): Synced $FILENAME" >> "$LOG"

if "$VENV" "$ANALYZER" "$ALERT_PATH" >> "$LOG" 2>&1; then
    echo "$(date): Analysis complete" >> "$LOG"
else
    echo "$(date): Analysis failed" >> "$LOG"
fi

if [ -f "$REPORT" ]; then
    mv "$REPORT" "$REPORTS_DIR"
    echo "$(date): Report saved to $REPORTS_DIR" >> "$LOG"
fi

# Keep only the last 30 days of alerts and reports
find "$LOCAL_ALERTS" -name "ossec-alerts-*.json.gz" -mtime +30 -delete
find "$REPORTS_DIR" -name "report-*.md" -mtime +30 -delete
