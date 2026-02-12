#!/usr/bin/env python3
"""Verify an Ed25519 signature via OpenSSL."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile


def load_public_key_pem(args: argparse.Namespace) -> str:
    if args.public_key_file:
        with open(args.public_key_file, "r", encoding="utf-8") as f:
            return f.read()

    env_name = args.public_key_env
    pem = os.environ.get(env_name, "")
    if pem.strip():
        return pem

    raise ValueError(
        f"missing public key PEM: provide --public-key-file or set {env_name}"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify Ed25519 signature (OpenSSL)")
    parser.add_argument("--input", required=True, help="Signed payload file")
    parser.add_argument("--signature", required=True, help="Detached signature file")
    parser.add_argument(
        "--public-key-env",
        default="THREAT_INTEL_ED25519_PUBLIC_KEY_PEM",
        help="Environment variable containing public key PEM",
    )
    parser.add_argument(
        "--public-key-file",
        default="",
        help="Path to public key PEM file",
    )
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    signature_path = os.path.abspath(args.signature)
    if not os.path.isfile(input_path):
        print(f"Input file does not exist: {input_path}", file=sys.stderr)
        return 1
    if not os.path.isfile(signature_path):
        print(f"Signature file does not exist: {signature_path}", file=sys.stderr)
        return 1

    try:
        public_key_pem = load_public_key_pem(args)
    except Exception as exc:
        print(f"Failed to load public key: {exc}", file=sys.stderr)
        return 1

    with tempfile.NamedTemporaryFile(
        prefix="eguard-ed25519-pub-", suffix=".pem", mode="w", encoding="utf-8", delete=True
    ) as pub_file:
        pub_file.write(public_key_pem)
        pub_file.flush()

        completed = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-rawin",
                "-pubin",
                "-inkey",
                pub_file.name,
                "-in",
                input_path,
                "-sigfile",
                signature_path,
            ],
            capture_output=True,
            text=True,
        )
        if completed.returncode != 0:
            stderr = completed.stderr.strip() or completed.stdout.strip()
            print(f"Verification failed: {stderr}", file=sys.stderr)
            return 1

    print(f"Signature verified: {signature_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
