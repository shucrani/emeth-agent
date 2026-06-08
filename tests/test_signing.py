"""Signature emetteur (proof). Tests hors-ligne : la signature couvre le contenu
ET le timestamp, et toute alteration la casse."""

import json
import unittest
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from emeth_agent.generate import generate
from emeth_agent.signing import sign_credential, verify_proof

FIXT = Path(__file__).resolve().parent.parent / "fixtures" / "acme_test.json"
ISSUED = "2026-06-08T19:30:00Z"


def _doc():
    with open(FIXT, encoding="utf-8") as fh:
        fx = json.load(fh)
    return generate(fx["subject"], fx["declared_inputs"], ISSUED)  # sans TSA -> hors-ligne


class TestIssuerSignature(unittest.TestCase):
    def test_generated_proof_verifies(self):
        self.assertTrue(verify_proof(_doc()))

    def test_proof_shape(self):
        proof = _doc()["proof"]
        self.assertEqual(proof["type"], "DataIntegrityProof")
        self.assertEqual(proof["cryptosuite"], "eddsa-jcs-2022")
        self.assertEqual(proof["proofPurpose"], "assertionMethod")
        self.assertTrue(proof["proofValue"].startswith("z"))  # multibase base58btc
        self.assertNotIn("status", proof)  # plus de PENDING_SIGNATURE

    def test_tamper_on_content_breaks_proof(self):
        c = _doc()
        c["credentialSubject"]["class"] = "IN_SCOPE:99 / UNDETERMINED:0"
        self.assertFalse(verify_proof(c))

    def test_tamper_on_timestamp_breaks_proof(self):
        c = _doc()
        c["timestamp"]["messageImprintHash"] = "00" * 32
        self.assertFalse(verify_proof(c))  # le proof couvre aussi le timestamp

    def test_wrong_key_fails(self):
        c = _doc()
        self.assertFalse(verify_proof(c, Ed25519PrivateKey.generate().public_key()))

    def test_ephemeral_roundtrip(self):
        priv = Ed25519PrivateKey.generate()
        signable = {"a": 1, "b": ["x", "y"], "n": "1e25"}
        doc = dict(signable)
        doc["proof"] = sign_credential(signable, priv, ISSUED)
        self.assertTrue(verify_proof(doc, priv.public_key()))


if __name__ == "__main__":
    unittest.main(verbosity=2)
