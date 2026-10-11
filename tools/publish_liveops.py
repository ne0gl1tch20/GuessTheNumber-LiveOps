#!/usr/bin/env python3
"""Validate and publish a SHA-256-checked, RSA-signed LiveOps manifest."""

import base64
import hashlib
import json
import os
import re
import sys
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = ROOT / "liveops-config.json"
MANIFEST_PATH = ROOT / "manifest.json"
SCRIPTS_DIR = ROOT / "scripts"
MAX_SCRIPTS = 50
MAX_SCRIPT_BYTES = 32_768
ID_PATTERN = re.compile(r"[a-z0-9_-]{1,64}")
FILE_PATTERN = re.compile(r"[a-zA-Z0-9_-]{1,80}\.lua")


def fail(message: str) -> "NoReturn":
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def build_payload(config: dict, scripts_dir: Path) -> dict:
    """Validate config and scripts before producing the signed payload."""
    required = ("schemaVersion", "hostApiVersion", "minAppVersionCode",
                "maxAppVersionCode", "bundleVersion")
    for key in required:
        if key not in config:
            raise ValueError(f"Missing required config field: {key}")
    for key in required:
        if not isinstance(config[key], int) or isinstance(config[key], bool):
            raise ValueError(f"{key} must be an integer")
    if config["schemaVersion"] != 1:
        raise ValueError("Unsupported LiveOps schemaVersion")
    if config["hostApiVersion"] < 1:
        raise ValueError("hostApiVersion must be positive")
    if config["bundleVersion"] < 1:
        raise ValueError("bundleVersion must be positive")
    if config["minAppVersionCode"] < 1 or config["maxAppVersionCode"] < config["minAppVersionCode"]:
        raise ValueError("Invalid app compatibility range")

    scripts = config.get("scripts")
    if not isinstance(scripts, list) or not 1 <= len(scripts) <= MAX_SCRIPTS:
        raise ValueError(f"scripts must contain 1 to {MAX_SCRIPTS} entries")

    ids = set()
    file_names = set()
    entries = []
    for item in scripts:
        if not isinstance(item, dict):
            raise ValueError("Each script entry must be an object")
        script_id = item.get("id", "")
        file_name = item.get("fileName", "")
        if not isinstance(script_id, str) or not ID_PATTERN.fullmatch(script_id):
            raise ValueError(f"Invalid script ID: {script_id!r}")
        if script_id in ids:
            raise ValueError(f"Duplicate script ID: {script_id}")
        ids.add(script_id)
        if not isinstance(file_name, str) or not FILE_PATTERN.fullmatch(file_name):
            raise ValueError(f"Invalid Lua fileName: {file_name!r}")
        if file_name in file_names:
            raise ValueError(f"Duplicate Lua fileName: {file_name}")
        file_names.add(file_name)

        title = item.get("title")
        description = item.get("description", "")
        if not isinstance(title, str) or not title.strip() or len(title) > 100:
            raise ValueError(f"Script {script_id} title must be 1 to 100 characters")
        if not isinstance(description, str) or not description.strip() or len(description) > 240:
            raise ValueError(f"Script {script_id} description must be 1 to 240 characters")
        host_api = item.get("hostApiVersion", config["hostApiVersion"])
        if not isinstance(host_api, int) or isinstance(host_api, bool) or host_api != config["hostApiVersion"]:
            raise ValueError(f"Script {script_id} has an unsupported hostApiVersion")
        capabilities = item.get("capabilities", ["log"])
        if not isinstance(capabilities, list) or any(capability != "log" for capability in capabilities):
            raise ValueError(f"Script {script_id} requests an unsupported capability")

        script_path = scripts_dir / file_name
        if not script_path.is_file():
            raise ValueError(f"Script file does not exist: scripts/{file_name}")
        script_bytes = script_path.read_bytes()
        if not script_bytes or len(script_bytes) > MAX_SCRIPT_BYTES:
            raise ValueError(f"Script {script_id} must be 1 to {MAX_SCRIPT_BYTES} bytes")
        try:
            script_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError(f"Script {script_id} is not valid UTF-8") from exc

        entries.append({
            "id": script_id,
            "fileName": file_name,
            "title": title,
            "description": description,
            "sha256": hashlib.sha256(script_bytes).hexdigest(),
            "featured": bool(item.get("featured", False)),
            "hostApiVersion": host_api,
            "capabilities": capabilities,
        })

    return {
        "schemaVersion": config["schemaVersion"],
        "hostApiVersion": config["hostApiVersion"],
        "minAppVersionCode": config["minAppVersionCode"],
        "maxAppVersionCode": config["maxAppVersionCode"],
        "bundleVersion": config["bundleVersion"],
        "scripts": entries,
    }


def validate_version_progression(payload_bytes: bytes, manifest_path: Path,
                                 private_key: rsa.RSAPrivateKey) -> None:
    """Reject changed content unless its version is strictly higher."""
    if not manifest_path.is_file():
        return
    try:
        envelope = json.loads(manifest_path.read_text(encoding="utf-8"))
        previous_bytes = base64.b64decode(envelope["payloadBase64"], validate=True)
        previous_signature = base64.b64decode(envelope["signatureBase64"], validate=True)
        private_key.public_key().verify(
            previous_signature, previous_bytes, padding.PKCS1v15(), hashes.SHA256()
        )
        previous = json.loads(previous_bytes.decode("utf-8"))
        current = json.loads(payload_bytes.decode("utf-8"))
    except Exception as exc:
        raise ValueError("Existing manifest cannot be verified with the current signing key; resolve key rotation or repair the manifest explicitly.") from exc

    if payload_bytes != previous_bytes and current["bundleVersion"] <= previous["bundleVersion"]:
        raise ValueError(
            f"Changed LiveOps content must increase bundleVersion above {previous['bundleVersion']}."
        )
    if current["bundleVersion"] < previous["bundleVersion"]:
        raise ValueError("bundleVersion cannot decrease.")


def main() -> None:
    private_pem = os.environ.get("LIVEOPS_PRIVATE_KEY_PEM", "")
    if not private_pem.strip():
        fail("Missing Actions secret LIVEOPS_PRIVATE_KEY_PEM.")

    try:
        private_key = serialization.load_pem_private_key(
            private_pem.encode("utf-8"), password=None
        )
    except Exception as exc:
        fail(f"Could not load LIVEOPS_PRIVATE_KEY_PEM ({type(exc).__name__}).")
    if not isinstance(private_key, rsa.RSAPrivateKey):
        fail("The LiveOps signing key must be an RSA private key.")

    try:
        config = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        payload = build_payload(config, SCRIPTS_DIR)
        payload_bytes = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        validate_version_progression(payload_bytes, MANIFEST_PATH, private_key)
    except Exception as exc:
        fail(str(exc))

    signature = private_key.sign(payload_bytes, padding.PKCS1v15(), hashes.SHA256())
    envelope = {
        "payloadBase64": base64.b64encode(payload_bytes).decode("ascii"),
        "signatureBase64": base64.b64encode(signature).decode("ascii"),
    }
    MANIFEST_PATH.write_text(json.dumps(envelope, indent=2) + "\n", encoding="utf-8")
    print(f"Signed manifest written: {MANIFEST_PATH.name}")
    print(f"Bundle version: {payload['bundleVersion']}")
    print(f"Lua scripts: {len(payload['scripts'])}")
    print("Private key was not written to disk or printed by this script.")


if __name__ == "__main__":
    main()
