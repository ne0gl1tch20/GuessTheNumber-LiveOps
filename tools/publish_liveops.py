#!/usr/bin/env python3
"""Build a SHA-256-checked, RSA-signed manifest for GuessTheNumber LiveOps."""

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "liveops-config.json"
MANIFEST_PATH = ROOT / "manifest.json"
SCRIPTS_DIR = ROOT / "scripts"


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    private_pem = os.environ.get("LIVEOPS_PRIVATE_KEY_PEM", "")
    if not private_pem.strip():
        fail("Missing Actions secret LIVEOPS_PRIVATE_KEY_PEM. Add the RSA private PEM as a repository Actions secret.")

    try:
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None
        )
    except Exception as exc:
        fail(f"Could not load LIVEOPS_PRIVATE_KEY_PEM ({type(exc).__name__}). Check that the secret contains the complete PEM including BEGIN/END lines.")

    if not isinstance(private_key, rsa.RSAPrivateKey):
        fail("The LiveOps signing key must be an RSA private key.")

    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception as exc:
        fail(f"Could not read liveops-config.json ({type(exc).__name__}).")

    script_entries = []
    for item in config.get("scripts", []):
        file_name = item.get("fileName", "")
        if not file_name or Path(file_name).name != file_name or not file_name.endswith(".lua"):
            fail(f"Invalid Lua fileName: {file_name!r}")
        script_path = SCRIPTS_DIR / file_name
        if not script_path.is_file():
            fail(f"Script file does not exist: scripts/{file_name}")
        script_bytes = script_path.read_bytes()
        entry = {
            "id": item["id"],
            "fileName": file_name,
            "title": item["title"],
            "description": item.get("description", ""),
            "sha256": hashlib.sha256(script_bytes).hexdigest(),
            "featured": bool(item.get("featured", False)),
            "hostApiVersion": int(item.get("hostApiVersion", config["hostApiVersion"])),
            "capabilities": item.get("capabilities", ["log"]),
        }
        script_entries.append(entry)

    payload = {
        "schemaVersion": int(config["schemaVersion"]),
        "hostApiVersion": int(config["hostApiVersion"]),
        "minAppVersionCode": int(config["minAppVersionCode"]),
        "maxAppVersionCode": int(config["maxAppVersionCode"]),
        "bundleVersion": int(config["bundleVersion"]),
        "scripts": script_entries,
    }
    payload_bytes = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    signature = private_key.sign(
        payload_bytes,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    envelope = {
        "payloadBase64": base64.b64encode(payload_bytes).decode("ascii"),
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
    }
    MANIFEST_PATH.write_text(
        json.dumps(envelope, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Signed manifest written: {MANIFEST_PATH.name}")
    print(f"Bundle version: {payload['bundleVersion']}")
    print(f"Lua scripts: {len(script_entries)}")
    print("Private key was not written to disk or printed by this script.")


if __name__ == "__main__":
    main()
