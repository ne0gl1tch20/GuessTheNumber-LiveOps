import json
import tempfile
import unittest
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from tools.publish_liveops import build_payload, validate_version_progression


def config_for(scripts):
    return {
        "schemaVersion": 1,
        "hostApiVersion": 1,
        "minAppVersionCode": 19,
        "maxAppVersionCode": 999999,
        "bundleVersion": 2,
        "scripts": scripts,
    }


def entry(script_id, file_name):
    return {
        "id": script_id,
        "fileName": file_name,
        "title": script_id.title(),
        "description": f"{script_id} activity",
        "featured": False,
        "hostApiVersion": 1,
        "capabilities": ["log"],
    }


class PublishLiveOpsTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.scripts_dir = Path(self.temp.name) / "scripts"
        self.scripts_dir.mkdir()
        (self.scripts_dir / "welcome.lua").write_text('return { ok = true }', encoding="utf-8")
        (self.scripts_dir / "second.lua").write_text('return { ok = false }', encoding="utf-8")

    def test_build_payload_rejects_duplicate_filenames(self):
        config = config_for([entry("welcome", "welcome.lua"), entry("second", "welcome.lua")])
        with self.assertRaisesRegex(ValueError, "Duplicate Lua fileName"):
            build_payload(config, self.scripts_dir)

    def test_build_payload_rejects_duplicate_ids(self):
        config = config_for([entry("same", "welcome.lua"), entry("same", "second.lua")])
        with self.assertRaisesRegex(ValueError, "Duplicate script ID"):
            build_payload(config, self.scripts_dir)

    def test_build_payload_rejects_path_traversal(self):
        config = config_for([entry("welcome", "../welcome.lua")])
        with self.assertRaisesRegex(ValueError, "Invalid Lua fileName"):
            build_payload(config, self.scripts_dir)

    def test_build_payload_rejects_empty_script(self):
        (self.scripts_dir / "welcome.lua").write_bytes(b"")
        config = config_for([entry("welcome", "welcome.lua")])
        with self.assertRaisesRegex(ValueError, "must be 1 to"):
            build_payload(config, self.scripts_dir)

    def test_changed_payload_requires_higher_bundle_version(self):
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        old_payload = {
            "schemaVersion": 1, "hostApiVersion": 1, "minAppVersionCode": 19,
            "maxAppVersionCode": 999999, "bundleVersion": 2,
            "scripts": [{"id": "welcome", "fileName": "welcome.lua", "sha256": "old"}],
        }
        old_bytes = json.dumps(old_payload, separators=(",", ":")).encode()
        signature = key.sign(old_bytes, padding.PKCS1v15(), hashes.SHA256())
        import base64
        manifest_path = Path(self.temp.name) / "manifest.json"
        manifest_path.write_text(json.dumps({
            "payloadBase64": base64.b64encode(old_bytes).decode(),
            "signatureBase64": base64.b64encode(signature).decode(),
        }), encoding="utf-8")

        changed_same_version = dict(old_payload)
        changed_same_version["scripts"] = [{"id": "welcome", "fileName": "welcome.lua", "sha256": "new"}]
        changed_bytes = json.dumps(changed_same_version, separators=(",", ":")).encode()
        with self.assertRaisesRegex(ValueError, "must increase bundleVersion"):
            validate_version_progression(changed_bytes, manifest_path, key)

        changed_higher_version = dict(changed_same_version, bundleVersion=3)
        higher_bytes = json.dumps(changed_higher_version, separators=(",", ":")).encode()
        validate_version_progression(higher_bytes, manifest_path, key)


if __name__ == "__main__":
    unittest.main()
