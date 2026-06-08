"""Criteres de succes de t0, executables. La barriere d'horizon est TESTEE,
pas seulement documentee."""

import json
import unittest
from pathlib import Path

from emeth_agent.generate import generate
from emeth_agent.timestamp import sha256_hex

FIXT = Path(__file__).resolve().parent.parent / "fixtures" / "acme_test.json"
ISSUED = "2026-06-08T19:30:00Z"

# Tout mot qui ferait basculer du bord (position) vers l'interieur (verdict).
FORBIDDEN = ["compliant", "non-compliant", "conforme", "high_risk", "high-risk",
             "highrisk", "exempt", "out_of_scope"]


def _load():
    with open(FIXT, encoding="utf-8") as fh:
        fx = json.load(fh)
    return generate(fx["subject"], fx["declared_inputs"], ISSUED)


class TestEnvelope(unittest.TestCase):
    def test_required_vc_fields_present(self):
        c = _load()
        self.assertEqual(c["@context"][0], "https://www.w3.org/ns/credentials/v2")
        self.assertIn("VerifiableCredential", c["type"])
        self.assertIn("BoundaryAttestationCredential", c["type"])
        for field in ("id", "issuer", "validFrom", "credentialSubject",
                      "termsOfUse", "proof", "timestamp", "corpusSnapshot"):
            self.assertIn(field, c, f"champ requis manquant : {field}")
        self.assertEqual(c["issuer"]["identifier"], "BE 1034.962.482")


class TestScope(unittest.TestCase):
    def setUp(self):
        self.c = _load()
        self.by_prov = {p["provision"]: p for p in self.c["credentialSubject"]["positions"]}

    def test_art50_1_in_scope(self):
        self.assertEqual(self.by_prov["Art. 50(1)"]["scopeStatus"], "IN_SCOPE")

    def test_art50_2_in_scope(self):
        self.assertEqual(self.by_prov["Art. 50(2)"]["scopeStatus"], "IN_SCOPE")

    def test_art51_omitted(self):
        # is_gpai_provider = no, present et non satisfait -> porte OMISE (pas OUT_OF_SCOPE)
        self.assertNotIn("Art. 51 + Art. 3(65)", self.by_prov)

    def test_annex_iii_undetermined(self):
        # annex_iii_use_case absent -> UNDETERMINED
        self.assertEqual(self.by_prov["Annexe III"]["scopeStatus"], "UNDETERMINED")

    def test_class_is_mechanical(self):
        self.assertEqual(self.c["credentialSubject"]["class"], "IN_SCOPE:2 / UNDETERMINED:1")


class TestHorizonRefusal(unittest.TestCase):
    def test_no_forbidden_verdict_tokens(self):
        c = _load()
        cls = c["credentialSubject"]["class"].lower()
        statuses = [p["scopeStatus"].lower()
                    for p in c["credentialSubject"]["positions"]]
        for bad in FORBIDDEN:
            self.assertNotIn(bad, cls, f"verdict interdit dans class : {bad}")
            self.assertNotIn(bad, statuses, f"statut interdit : {bad}")

    def test_scope_status_closed_enum(self):
        c = _load()
        for p in c["credentialSubject"]["positions"]:
            self.assertIn(p["scopeStatus"], ("IN_SCOPE", "UNDETERMINED"))

    def test_does_not_assert_includes_compliance(self):
        c = _load()
        joined = " ".join(c["termsOfUse"]["doesNotAssert"]).lower()
        self.assertIn("conformite", joined)
        self.assertIn("avis juridique", joined)

    def test_declared_inputs_are_unverified(self):
        c = _load()
        for di in c["credentialSubject"]["declaredInputs"]:
            self.assertFalse(di["verified"], "modele notaire viole : intrant marque verifie")


class TestDeterminism(unittest.TestCase):
    def test_same_inputs_same_hash(self):
        a, b = _load(), _load()
        self.assertEqual(a["timestamp"]["messageImprintHash"],
                         b["timestamp"]["messageImprintHash"])

    def test_hash_is_real_sha256(self):
        c = _load()
        self.assertEqual(len(c["timestamp"]["messageImprintHash"]), 64)


if __name__ == "__main__":
    unittest.main(verbosity=2)
