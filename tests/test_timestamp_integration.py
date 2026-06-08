"""Test d'integration TSA RFC 3161 (reseau). Skip propre si la TSA est injoignable
-> la suite reste verte hors-ligne."""

import unittest
import urllib.error

from emeth_agent.timestamp import (request_rfc3161, sha256_hex, verify_chain,
                                       verify_token)

TSA_URL = "https://freetsa.org/tsr"


class TestRealTSA(unittest.TestCase):
    def setUp(self):
        self.digest = sha256_hex({"probe": "emeth-agent-integration"})
        try:
            self.ts = request_rfc3161(self.digest, TSA_URL, "2026-06-08T19:30:00Z", timeout=15)
        except (urllib.error.URLError, OSError) as exc:
            self.skipTest(f"TSA injoignable (hors-ligne) : {exc}")

    def test_sealed(self):
        self.assertEqual(self.ts["status"], "SEALED")

    def test_has_gentime_and_serial(self):
        self.assertTrue(self.ts["genTime"])
        self.assertTrue(self.ts["serialNumber"])

    def test_token_seals_our_hash(self):
        self.assertTrue(verify_token(self.ts["rfc3161TokenB64"], self.digest))

    def test_token_rejects_wrong_hash(self):
        self.assertFalse(verify_token(self.ts["rfc3161TokenB64"], "00" * 32))

    def test_chain_verifies_against_ca(self):
        ok, output = verify_chain(self.ts["rfc3161TokenB64"], self.digest)
        if ok is None:
            self.skipTest(f"openssl indisponible : {output}")
        self.assertTrue(ok, f"verif chaine echouee : {output}")

    def test_chain_rejects_wrong_digest(self):
        ok, _ = verify_chain(self.ts["rfc3161TokenB64"], "00" * 32)
        if ok is None:
            self.skipTest("openssl indisponible")
        self.assertFalse(ok)


if __name__ == "__main__":
    unittest.main(verbosity=2)
