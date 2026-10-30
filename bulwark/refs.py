"""Lookups against the real NIST 800-53, ATT&CK and FHIR data."""
import json
from functools import lru_cache
from pathlib import Path

RAW = Path(__file__).resolve().parents[1] / "data/raw"


@lru_cache
def nist():
    return json.loads((RAW / "nist80053.json").read_text())


@lru_cache
def attack():
    return json.loads((RAW / "attack_techniques.json").read_text())


@lru_cache
def fhir():
    return json.loads((RAW / "fhir_r4_elements.json").read_text())


def nist_ok(cid): return cid in nist()["controls"] and not nist()["controls"][cid]["withdrawn"]
def attack_ok(tid): return tid in attack()
