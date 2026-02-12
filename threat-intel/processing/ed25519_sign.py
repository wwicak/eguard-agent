#!/usr/bin/env python3
"""Sign a file using an Ed25519 private key via OpenSSL."""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile


def load_private_key_pem(args: argparse.Namespace) -> str:
    if args.private_key_file:
        with open(args.private_key_file, "r", encoding="utf-8") as f:
            return f.read()

    env_name = args.private_key_env
    pem = os.environ.get(env_name, "")
    if pem.strip():
        return pem

    raise ValueError(
        f"missing private key PEM: provide --private-key-file or set {env_name}"
    )


def run_checked(cmd: list[str]) -> None:
    completed = subprocess.run(cmd, capture_output=True, text=True)
    if completed.returncode != 0:
        stderr = completed.stderr.strip() or completed.stdout.strip()
        raise RuntimeError(stderr or "unknown OpenSSL error")


def extract_public_key_hex(private_key_path: str) -> str:
    with tempfile.NamedTemporaryFile(prefix="eguard-ed25519-pub-", suffix=".der") as der_out:
        run_checked(
            [
                "openssl",
                "pkey",
                "-in",
                private_key_path,
                "-pubout",
                "-outform",
                "DER",
                "-out",
                der_out.name,
            ]
        )
        der_out.flush()
        with open(der_out.name, "rb") as f:
            der = f.read()

    if len(der) < 32:
        raise RuntimeError("public key DER output too short")

    # For Ed25519 SubjectPublicKeyInfo, the last 32 bytes are the raw public key.
    return der[-32:].hex()


def main() -> int:
    parser = argparse.ArgumentParser(description="Sign file with Ed25519 (OpenSSL)")
    parser.add_argument("--input", required=True, help="Input file path")
    parser.add_argument(
        "--output-sig",
        default="",
        help="Output signature path (default: <input>.sig)",
    )
    parser.add_argument(
        "--private-key-env",
        default="THREAT_INTEL_ED25519_PRIVATE_KEY_PEM",
        help="Environment variable containing private key PEM",
    )
    parser.add_argument(
        "--private-key-file",
        default="",
        help="Path to private key PEM file",
    )
    parser.add_argument(
        "--public-key-hex-out",
        default="",
        help="Optional path to write derived public key as hex",
    )
    args = parser.parse_args()

    input_path = os.path.abspath(args.input)
    output_sig = args.output_sig or f"{input_path}.sig"

    if not os.path.isfile(input_path):
        print(f"Input file does not exist: {input_path}", file=sys.stderr)
        return 1

    try:
        pem = load_private_key_pem(args)
    except Exception as exc:
        print(f"Failed to load private key: {exc}", file=sys.stderr)
        return 1

    os.makedirs(os.path.dirname(os.path.abspath(output_sig)), exist_ok=True)

    with tempfile.NamedTemporaryFile(
        prefix="eguard-ed25519-key-", suffix=".pem", mode="w", encoding="utf-8", delete=True
    ) as key_file:
        key_file.write(pem)
        key_file.flush()

        try:
            run_checked(
                [
                    "openssl",
                    "pkeyutl",
                    "-sign",
                    "-rawin",
                    "-inkey",
                    key_file.name,
                    "-in",
                    input_path,
                    "-out",
                    output_sig,
                ]
            )

            if args.public_key_hex_out:
                pub_hex = extract_public_key_hex(key_file.name)
                out_path = os.path.abspath(args.public_key_hex_out)
                os.makedirs(os.path.dirname(out_path), exist_ok=True)
                with open(out_path, "w", encoding="utf-8") as f:
                    f.write(pub_hex + "\n")
        except Exception as exc:
            print(f"OpenSSL signing failed: {exc}", file=sys.stderr)
            return 1

    print(f"Signed {input_path} -> {output_sig}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
