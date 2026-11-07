#!/usr/bin/env python3
"""Tests for service_actor_e2e_redact: python3 -I scripts/test_service_actor_e2e_redact.py"""

import json
import os
import secrets
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import service_actor_e2e_redact as redaction  # noqa: E402

MASTER_KEY = secrets.token_hex(32)
redaction.register_secret(MASTER_KEY)
VAULT = f"file:///tmp/vault.json?master_key={MASTER_KEY}"


class RedactionTest(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.transcript = Path(self.directory.name) / "transcript.jsonl"

    def tearDown(self):
        self.directory.cleanup()

    def assertClean(self, text: str):
        self.assertNotIn(MASTER_KEY, text)
        self.assertNotIn(MASTER_KEY[:16], text)
        self.assertNotRegex(text, r"master_key=[0-9a-f]{8,}")

    def test_success_row_redacts_argv_and_output(self):
        result = redaction.run_logged([sys.executable, "-c", f"print('{VAULT}')", "--vault-url", VAULT],
                                      self.transcript, env=dict(os.environ))
        self.assertEqual(result.returncode, 0)
        self.assertClean(self.transcript.read_text())
        self.assertIn("master_key=<redacted>", self.transcript.read_text())

    def test_failure_message_and_row_are_redacted(self):
        with self.assertRaises(RuntimeError) as raised:
            redaction.run_logged([sys.executable, "-c", f"import sys; sys.stderr.write('{MASTER_KEY}'); sys.exit(3)"],
                                 self.transcript, env=dict(os.environ))
        self.assertClean(str(raised.exception))
        self.assertClean(self.transcript.read_text())

    def test_timeout_message_and_row_are_redacted(self):
        script = f"import sys, time; print('{MASTER_KEY}', flush=True); time.sleep(30)"
        with self.assertRaises(RuntimeError) as raised:
            redaction.run_logged([sys.executable, "-c", script, VAULT], self.transcript, env=dict(os.environ), timeout=1)
        self.assertIn("timed out", str(raised.exception))
        self.assertClean(str(raised.exception))
        self.assertClean(self.transcript.read_text())

    def test_secret_across_the_truncation_boundary(self):
        # The kept tail starts inside the secret; redaction happens before the cut.
        keep = 40
        script = f"print('x' * 100 + '{MASTER_KEY}' + 'y' * {keep - 10})"
        redaction.run_logged([sys.executable, "-c", script], self.transcript, env=dict(os.environ), keep=keep)
        row = json.loads(self.transcript.read_text())
        self.assertClean(row["stdout"])
        self.assertNotIn(MASTER_KEY[-8:], row["stdout"])

    def test_secret_fields_plain_and_escaped(self):
        plain = json.dumps({"seed_hex": "aa" * 32, "public_key": "bb" * 8, "mnemonic": "w1 w2", "secret": "cc"})
        escaped = json.dumps({"stdout": plain})
        for text in (plain, escaped):
            clean = redaction.redact(text)
            self.assertNotIn("aa" * 32, clean)
            self.assertNotIn("w1 w2", clean)
            self.assertNotIn('"cc"', clean.replace("\\", ""))
            self.assertIn("bb" * 8, clean)

    def test_redact_value_and_file(self):
        value = redaction.redact_value({"detail": [VAULT, {"k": MASTER_KEY}]})
        self.assertClean(json.dumps(value))
        path = Path(self.directory.name) / "old.jsonl"
        path.write_text(json.dumps({"argv": ["--vault-url", VAULT]}) + "\n" + json.dumps({"ok": 1}) + "\n")
        self.assertEqual(redaction.redact_file(path), 1)
        self.assertClean(path.read_text())


if __name__ == "__main__":
    unittest.main()
