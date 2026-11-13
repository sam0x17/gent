#!/usr/bin/env python3
"""Reproduce file-object v1 fixtures using Python cryptography, independently of Rust.

Run with --check to compare the committed fixtures. All keys are public test data.
Requires the `cryptography` package; this is a development check, not a runtime dependency.
"""

import argparse
import hashlib
import json
from pathlib import Path
import struct

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305


def vectors():
    results = []
    for number, (plaintext, index) in enumerate(
        [(b"", 0), (b"Gent image bytes\x00\xff", 0), (bytes(range(251)) * 2090, 2)]
    ):
        manifest = {
            "id": f"00000000-0000-4000-8000-{number + 1:012d}",
            "name": "frame-猫.bin",
            "media_type": "application/octet-stream",
            "byte_length": len(plaintext),
            "sha256": hashlib.sha256(plaintext).hexdigest(),
        }
        key = bytes((number * 32 + i) % 256 for i in range(32))
        count = max(1, (len(plaintext) + 262143) // 262144)
        aad = b"gent/file-chunk/v1\0"
        for field in ["id", "name", "media_type", "sha256"]:
            encoded = manifest[field].encode("utf-8")
            aad += struct.pack(">H", len(encoded)) + encoded
        aad += struct.pack(">QII", len(plaintext), count, index)
        nonce = bytes(8) + struct.pack(">I", index)
        part = plaintext[index * 262144 : (index + 1) * 262144]
        ciphertext = ChaCha20Poly1305(key).encrypt(nonce, part, aad)
        results.append(
            {
                "grant": {"version": 1, "manifest": manifest, "key": list(key)},
                "index": index,
                "plaintext_hex": part.hex(),
                "ciphertext_hex": ciphertext.hex(),
            }
        )
    return results


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    output = json.dumps(vectors(), indent=2, ensure_ascii=False) + "\n"
    if args.check:
        path = Path(__file__).resolve().parents[1] / "crates/gent-crypto/tests/fixtures/file_objects_v1.json"
        if path.read_text() != output:
            raise SystemExit("file-object fixtures differ from Python cryptography output")
        print("Three file-object v1 fixtures match Python cryptography.")
    else:
        print(output, end="")


if __name__ == "__main__":
    main()
