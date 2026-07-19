from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

import resume_v2_segment as mod


class ResumeV2SegmentTests(unittest.TestCase):
    def test_validate_args_accepts_normalized_hash(self):
        self.assertEqual(mod.validate_args("A" * 64, 250_000_000, 50_000_000), "a" * 64)

    def test_validate_args_rejects_bad_hash(self):
        with self.assertRaisesRegex(ValueError, "64 lowercase hex"):
            mod.validate_args("xyz", 1, 1)

    def test_validate_args_rejects_nonpositive_segment(self):
        with self.assertRaisesRegex(ValueError, "positive"):
            mod.validate_args("a" * 64, 1, 0)

    def test_verified_source_identity_accepts_exact_v2_manifest(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)
            manifest = {
                "schema_version": "aion-clean-checkpoint/v2",
                "identity": {"files": {"x": {"sha256": "b" * 64}}},
            }
            raw = json.dumps(manifest).encode()
            (source / "checkpoint_manifest.json").write_bytes(raw)
            expected = hashlib.sha256(raw).hexdigest()
            loaded, identity = mod.verified_source_identity(source, expected)
            self.assertEqual(loaded, manifest)
            self.assertEqual(identity, manifest["identity"])

    def test_verified_source_identity_rejects_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)
            (source / "checkpoint_manifest.json").write_text("{}")
            with self.assertRaisesRegex(RuntimeError, "hash mismatch"):
                mod.verified_source_identity(source, "0" * 64)

    def test_verified_source_identity_rejects_non_v2(self):
        with tempfile.TemporaryDirectory() as td:
            source = Path(td)
            manifest = {"schema_version": "aion-clean-checkpoint/v1", "identity": {"x": 1}}
            raw = json.dumps(manifest).encode()
            (source / "checkpoint_manifest.json").write_bytes(raw)
            with self.assertRaisesRegex(RuntimeError, "not v2"):
                mod.verified_source_identity(source, hashlib.sha256(raw).hexdigest())


if __name__ == "__main__":
    unittest.main()
