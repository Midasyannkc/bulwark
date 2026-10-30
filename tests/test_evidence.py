import copy, json
from datetime import date
from pathlib import Path
import pytest
from bulwark.evidence import package as P, collectors as C

ROOT = Path(__file__).resolve().parents[1]
SNAP = json.loads((ROOT / "data/snapshots/cloud_2026-10-30.json").read_text())
PKG = P.build(SNAP)
BY = {i["control"]: i for i in PKG["items"]}


def test_expected_exceptions_in_the_seeded_snapshot():
    assert BY["BW-IAM-01"]["exceptions"] == ["h.kim", "k.brown"]
    assert BY["BW-IAM-02"]["exceptions"] == ["j.diaz"]
    assert BY["BW-ENC-01"]["exceptions"] == ["cc-phi-exports"]
    assert BY["BW-ENC-02"]["exceptions"] == ["cc-app-assets"]
    assert BY["BW-NET-01"]["exceptions"] == ["sg-admin"]
    assert BY["BW-ACC-01"]["exceptions"] == ["EHR"]
    assert BY["BW-VULN-01"]["exceptions"] == ["V2", "V4"]
    assert BY["BW-END-01"]["exceptions"] == ["lap-07", "lap-12"]
    assert BY["BW-BCP-01"]["status"] == "pass" and BY["BW-LOG-01"]["status"] == "pass"


def test_every_control_has_a_working_collector_and_real_nist_ids():
    assert P.mapping_errors() == []
    assert {c["collector"] for c in P.library()} <= set(C.COLLECTORS)


def test_evidence_hashes_verify_and_detect_tampering():
    assert P.verify_hashes(PKG) == []
    t = copy.deepcopy(PKG); t["items"][0]["artifact"]["result"]["exceptions"] = []
    assert P.verify_hashes(t) == [t["items"][0]["control"]]


def test_package_is_deterministic():
    assert json.dumps(P.build(copy.deepcopy(SNAP)), sort_keys=True) == json.dumps(PKG, sort_keys=True)


def test_stale_evidence_is_flagged_by_frequency():
    assert P.stale(PKG, date(2026, 10, 31)) == []
    assert "BW-IAM-01" in P.stale(PKG, date(2026, 12, 15)) and "BW-BCP-01" not in P.stale(PKG, date(2026, 12, 15))


@pytest.mark.parametrize("mutate,control", [
    (lambda s: s["iam"]["users"][0].update(mfa=False), "BW-IAM-01"),
    (lambda s: s["s3"]["buckets"][0].update(encrypted=False), "BW-ENC-01"),
    (lambda s: s["cloudtrail"]["trails"][0].update(log_validation=False), "BW-LOG-01"),
    (lambda s: s["rds"]["instances"][0].update(backup_days=3), "BW-ENC-03"),
    (lambda s: s["kms"]["keys"][0].update(rotation=False), "BW-ENC-04"),
    (lambda s: s["backups"].update(last_restore_test="2026-01-01"), "BW-BCP-01"),
    (lambda s: s["training"].update(completed=30), "BW-TRN-01"),
    (lambda s: s["network"]["security_groups"][2]["ingress"].append({"port": 5432, "cidr": "0.0.0.0/0"}), "BW-NET-01"),
])
def test_each_collector_catches_a_new_failure(mutate, control):
    s = copy.deepcopy(SNAP); mutate(s)
    assert {i["control"]: i for i in P.build(s)["items"]}[control]["status"] == "exception"


def test_sampling_is_stable_and_bounded():
    ids = [f"u{i}" for i in range(40)]
    assert C.sample(ids) == C.sample(list(reversed(ids))) and len(C.sample(ids)) == 10
    assert C.sample(["a", "b"]) == ["a", "b"]


def test_baseline_coverage_is_computed_from_real_nist_data_and_is_honestly_partial():
    c = P.coverage()
    assert c["baseline_base_controls"] > 100 and 0 < c["percent"] < 40
