#!/bin/bash
# Runs on the Wazuh server at 00:05 daily.
# Copies yesterday's completed gzipped alert file to ~/alerts/ for pickup by the LLM server.

set -euo pipefail

readonly DEST="/home/sysadmin/alerts/"
readonly LOG="${DEST}export.log"

YEAR=$(date -d "yesterday" +%Y)
MONTH=$(date -d "yesterday" +%b)
DAY=$(date -d "yesterday" +%d)
readonly SRC="/var/ossec/logs/alerts/${YEAR}/${MONTH}/ossec-alerts-${DAY}.json.gz"
readonly FILENAME="ossec-alerts-${DAY}.json.gz"

mkdir -p "$DEST"

if [ ! -f "$SRC" ]; then
    echo "$(date): Alert file not found: $SRC" >> "$LOG"
    exit 1
fi

cp "$SRC" "$DEST"
chown sysadmin:sysadmin "${DEST}${FILENAME}"
echo "$(date): Exported $SRC" >> "$LOG"

# Keep only the last 7 days of exported files
find "$DEST" -name "ossec-alerts-*.json.gz" -mtime +7 -delete
