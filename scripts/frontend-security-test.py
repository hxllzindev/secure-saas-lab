#!/usr/bin/env python3
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "src" / "SecureSaasLab.Api" / "wwwroot"


class FrontendSecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.html = (FRONTEND / "index.html").read_text(encoding="utf-8")
        cls.script = (FRONTEND / "app.js").read_text(encoding="utf-8")
        cls.all_text = "\n".join(path.read_text(encoding="utf-8") for path in FRONTEND.iterdir() if path.is_file())

    def test_no_credentials_are_embedded_or_prefilled(self):
        for value in ["Secure123!", "482911", "ana@", "caio@", "bruno@", "value=\"ana", "value=\"Secure"]:
            self.assertNotIn(value, self.all_text)

    def test_vulnerable_mode_and_bearer_tokens_are_not_shipped(self):
        for value in ["vulnerable-lab", "/api/vulnerable", "Authorization", "Bearer ", "state.token", "csrfToken", "X-CSRF-Token"]:
            self.assertNotIn(value, self.all_text)
        self.assertFalse((FRONTEND / "vulnerable-lab.js").exists())

    def test_no_raw_identity_business_or_note_fields_are_rendered(self):
        for value in ["invoice.customer", "invoice.tenantId", "event.actor", "event.email", "event.resourceId", "note.author", "note.content"]:
            self.assertNotIn(value, self.script)
        self.assertIsNone(re.search(r"invoice\.amount(?!Band)", self.script))

    def test_no_html_sinks_or_persistent_storage(self):
        for value in ["innerHTML", "outerHTML", "insertAdjacentHTML", "eval(", "localStorage", "sessionStorage"]:
            self.assertNotIn(value, self.script)

    def test_common_secret_patterns_are_absent(self):
        patterns = [r"AKIA[0-9A-Z]{16}", r"AIza[0-9A-Za-z_-]{30,}", r"sk-[A-Za-z0-9_-]{20,}", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"]
        for pattern in patterns:
            self.assertIsNone(re.search(pattern, self.all_text))


if __name__ == "__main__":
    unittest.main()
