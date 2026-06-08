"""Classification deterministe et tracable a la regle. AUCUN LLM.

Decision 08/06 : scopeStatus = IN_SCOPE | UNDETERMINED uniquement.
Logique AND a trois valeurs (Kleene) sur les conditions requises de la porte :
- Au moins une condition presente et NON satisfaite ....... porte OMISE
  (negatif definitif : il domine les inconnues ; OUT_OF_SCOPE retire,
   l'absence de IN_SCOPE parle d'elle-meme)
- Sinon, au moins une condition dont l'intrant est manquant  UNDETERMINED
- Sinon (toutes presentes et satisfaites) ................. IN_SCOPE
"""


def _compare(declared_value, op, expected):
    if op == "eq":
        return declared_value == expected
    if op in ("gte", "gt"):
        try:
            dv, ev = float(declared_value), float(expected)
            return dv >= ev if op == "gte" else dv > ev
        except (TypeError, ValueError):
            return False
    if op == "in":
        return declared_value in expected
    raise ValueError(f"Operateur non supporte : {op}")


def evaluate_gate(gate, declared):
    """Retourne (scope_status, scope_basis). scope_status None => porte omise."""
    basis = []
    has_missing = False
    has_definitive_false = False

    for req in gate["scope_rule"]["requires"]:
        key, op, expected = req["key"], req.get("op", "eq"), req["value"]
        if key not in declared:
            has_missing = True
            basis.append({"key": key, "declared": None, "op": op,
                          "expected": expected, "satisfied": None, "input_missing": True})
            continue
        ok = _compare(declared[key], op, expected)
        if not ok:
            has_definitive_false = True
        basis.append({"key": key, "declared": declared[key], "op": op,
                      "expected": expected, "satisfied": ok, "input_missing": False})

    if has_definitive_false:          # negatif definitif domine -> porte omise
        return None, basis
    if has_missing:                   # aucun negatif, mais un intrant manque
        return "UNDETERMINED", basis
    return "IN_SCOPE", basis          # tout present et satisfait


def classify(corpus, declared_inputs):
    """Retourne (positions, class_label). Deterministe, sans verdict normatif."""
    snap = {"snapshotId": corpus["snapshot_id"], "snapshotDate": corpus["snapshot_date"]}
    positions = []
    n_in_scope = n_undetermined = 0

    for gate in corpus["gates"]:
        status, basis = evaluate_gate(gate, declared_inputs)
        if status is None:
            continue  # omise
        if status == "IN_SCOPE":
            n_in_scope += 1
        else:
            n_undetermined += 1
        position = {
            "filter": corpus["filter"],
            "provision": gate["provision"],
            "gate": gate["gate"],
            "gateEffectiveDate": gate["effective_date"],
            "gateProvisional": gate.get("provisional", False),
            "gateSource": gate["source"],
            "scopeStatus": status,
            "scopeBasis": basis,
            "corpusSnapshotRef": snap,
        }
        # metadonnees de gate qui doivent voyager avec la position (honnetete au point d'usage)
        for opt in ("role", "grace", "assessment", "original_date"):
            if gate.get(opt):
                position[opt] = gate[opt]
        positions.append(position)

    # class = reformulation MECANIQUE, jamais un label normatif (pas de HIGH_RISK / COMPLIANT)
    class_label = f"IN_SCOPE:{n_in_scope} / UNDETERMINED:{n_undetermined}"
    return positions, class_label
