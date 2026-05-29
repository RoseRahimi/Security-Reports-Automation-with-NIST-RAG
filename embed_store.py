"""
Embeds processed CVE records into a ChromaDB vector database.

Reads cve_processed.jsonl (produced by scrapper.py), generates text embeddings
via the nomic-embed-text model on Ollama, and upserts them into a persistent
ChromaDB collection. Skips CVEs already present, so it can resume safely if interrupted.
"""

import json
import logging
import time
from pathlib import Path

import chromadb
import requests

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

JSONL_FILE = Path(__file__).parent / "cve_processed.jsonl"
CHROMA_PATH = Path(__file__).parent / "cve_db"
OLLAMA_URL = "http://localhost:11434"
EMBED_MODEL = "nomic-embed-text"
BATCH_SIZE = 50


def embed_batch(texts: list[str]) -> list[list[float]]:
    r = requests.post(
        f"{OLLAMA_URL}/api/embed",
        json={"model": EMBED_MODEL, "input": texts},
        timeout=120,
    )
    r.raise_for_status()
    return r.json()["embeddings"]


def main() -> None:
    client = chromadb.PersistentClient(path=str(CHROMA_PATH))
    collection = client.get_or_create_collection(
        name="cves",
        metadata={"hnsw:space": "cosine"},
    )

    existing = set(collection.get(include=[])["ids"])
    logger.info("ChromaDB already has %d records. Skipping those.", len(existing))

    total_lines = sum(1 for _ in JSONL_FILE.open())
    written = 0
    skipped = len(existing)
    errors = 0
    batch_ids: list[str] = []
    batch_texts: list[str] = []
    batch_metas: list[dict] = []

    def flush() -> None:
        nonlocal written, errors
        if not batch_ids:
            return
        try:
            embeddings = embed_batch(batch_texts)
            collection.add(
                ids=batch_ids,
                embeddings=embeddings,
                documents=batch_texts,
                metadatas=batch_metas,
            )
            written += len(batch_ids)
        except Exception as e:
            logger.warning("Batch error: %s", e)
            errors += len(batch_ids)
        batch_ids.clear()
        batch_texts.clear()
        batch_metas.clear()

    start = time.time()
    with JSONL_FILE.open() as f:
        for i, line in enumerate(f, 1):
            record = json.loads(line)
            cve_id = record["id"]

            if cve_id in existing:
                continue

            batch_ids.append(cve_id)
            batch_texts.append(record["text"])
            batch_metas.append({
                k: (v if v is not None else "")
                for k, v in record["metadata"].items()
                if not isinstance(v, list)
            })

            if len(batch_ids) >= BATCH_SIZE:
                flush()

            if i % 1000 == 0:
                elapsed = time.time() - start
                rate = written / elapsed if elapsed > 0 else 0
                remaining = (total_lines - i) / rate if rate > 0 else 0
                logger.info(
                    "%d/%d | stored: %d | skipped: %d | errors: %d | rate: %.0f/s | ETA: %.1fm",
                    i, total_lines, written, skipped, errors, rate, remaining / 60,
                )

    flush()

    elapsed = time.time() - start
    logger.info("Done in %.1fm", elapsed / 60)
    logger.info("  Stored : %d", written)
    logger.info("  Skipped: %d", skipped)
    logger.info("  Errors : %d", errors)
    logger.info("  Total in DB: %d", collection.count())


if __name__ == "__main__":
    main()
