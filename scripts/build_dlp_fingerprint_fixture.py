#!/usr/bin/env python3
"""Generate synthetic local fixtures for DLP fingerprint acceptance tests.

Writes a key, fingerprint pack, and positive/negative inputs. Do not use this
script with production records or documents.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import secrets
from pathlib import Path

DOMAIN = b"eguard-dlp-classification-v1\0"
SHINGLE_WORDS = 5


def normalize(value: str) -> str:
    return " ".join(value.split()).lower()


def digest(key: bytes, value: str) -> str:
    payload = value.encode("utf-8")
    return hashlib.sha256(
        DOMAIN + len(key).to_bytes(8, "big") + key + payload + key
    ).hexdigest()


def structured_fingerprint(key: bytes, record: dict[str, str]) -> str:
    canonical = "\n".join(
        f"{normalize(name)}={normalize(value)}"
        for name, value in sorted(record.items(), key=lambda item: normalize(item[0]))
    )
    return digest(key, canonical)


def document_fingerprints(key: bytes, text: str) -> list[str]:
    words: list[str] = []
    current: list[str] = []
    for char in text:
        if char.isalnum():
            current.append(char)
        elif current:
            words.append(normalize("".join(current)))
            current = []
    if current:
        words.append(normalize("".join(current)))
    return sorted({
        digest(key, " ".join(words[index:index + SHINGLE_WORDS]))
        for index in range(len(words) - SHINGLE_WORDS + 1)
    })


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    key = secrets.token_bytes(32)
    record = {"customer_id": "TEST-ACME-001", "region": "Jakarta"}
    reference = (
        "synthetic confidential merger plan covers test acme revenue projection "
        "and customer pricing"
    )
    positive_document = (
        "This synthetic confidential merger plan covers TEST ACME revenue "
        "projection and customer pricing for acceptance testing."
    )
    negative_document = "The synthetic cafeteria menu is available for the town hall."

    pack = {
        "schema_version": "1",
        "key_id": "synthetic-acceptance-v1",
        "structured_fingerprints": [structured_fingerprint(key, record)],
        "document_fingerprints": [document_fingerprints(key, reference)],
        "minimum_shared_shingles": 3,
    }
    (output / "fingerprint.key").write_bytes(key)
    (output / "fingerprint-pack.json").write_text(
        json.dumps(pack, indent=2) + "\n", encoding="utf-8"
    )
    (output / "structured-positive.json").write_text(
        json.dumps(record, indent=2) + "\n", encoding="utf-8"
    )
    (output / "unstructured-positive.txt").write_text(positive_document + "\n", encoding="utf-8")
    (output / "negative.txt").write_text(negative_document + "\n", encoding="utf-8")
    print(f"synthetic fixture written to {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
