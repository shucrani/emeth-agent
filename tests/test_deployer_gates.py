"""Gates deployeur 50(3)/50(4) (ICP cible). Verifie que l'agent classe enfin un
deployeur HR-tech, et que la fixture provider n'y est pas a tort exposee."""

import json
import unittest
from pathlib import Path

from emeth_agent.generate import generate

FIX_DIR = Path(__file__).resolve().parent.parent / "fixtures"
ISSUED = "2026-06-08T19:30:00Z"


def _doc(name):
    with open(FIX_DIR / name, encoding="utf-8") as fh:
        fx = json.load(fh)
    return generate(fx["subject"], fx["declared_inputs"], ISSUED)


class TestDeployerHRtech(unittest.TestCase):
    def setUp(self):
        self.c = _doc("hrtech_deployer.json")
        self.by_prov = {p["provision"]: p for p in self.c["credentialSubject"]["positions"]}

    def test_50_3_in_scope(self):
        self.assertEqual(self.by_prov["Art. 50(3)"]["scopeStatus"], "IN_SCOPE")
        self.assertEqual(self.by_prov["Art. 50(3)"]["role"], "deployer")

    def test_50_4_omitted(self):
        self.assertNotIn("Art. 50(4)", self.by_prov)  # declare "no" -> omise

    def test_annex_iii_in_scope_carries_6_3_assessment(self):
        annex = self.by_prov["Annexe III"]
        self.assertEqual(annex["scopeStatus"], "IN_SCOPE")
        self.assertIn("6(3)", annex["assessment"])  # la nuance voyage avec la position

    def test_provider_gates_omitted_for_deployer(self):
        for prov in ("Art. 50(1)", "Art. 50(2)"):
            self.assertNotIn(prov, self.by_prov)

    def test_class_mechanical(self):
        self.assertEqual(self.c["credentialSubject"]["class"], "IN_SCOPE:2 / UNDETERMINED:0")


class TestProviderNotExposedToDeployerGates(unittest.TestCase):
    def test_acme_omits_deployer_gates(self):
        by_prov = {p["provision"]: p for p in _doc("acme_test.json")["credentialSubject"]["positions"]}
        self.assertNotIn("Art. 50(3)", by_prov)
        self.assertNotIn("Art. 50(4)", by_prov)


if __name__ == "__main__":
    unittest.main(verbosity=2)
