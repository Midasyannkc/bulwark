import json, os, subprocess, sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def run(seed):
    subprocess.run([sys.executable, "-m", "bulwark"], cwd=ROOT, env=dict(os.environ, PYTHONHASHSEED=str(seed)), check=True, capture_output=True)
    return (ROOT / "out/report.json").read_bytes(), (ROOT / "docs/REPORT.md").read_bytes()


def test_report_is_identical_across_hash_seeds():
    assert run(1) == run(2) == run(999)


def test_report_headline_facts():
    r = json.loads((ROOT / "out/report.json").read_text())
    assert r["threat_model"]["citations_unverified"] == 0
    assert r["evidence"]["hash_failures"] == 0 and r["evidence"]["nist_mapping_errors"] == 0
    assert r["fhir"]["spec_findings"] == 0 and r["fhir"]["deid_leaks"] == 0 and r["fhir"]["phi_in_audit_log"] is False
    assert r["fhir"]["api_probe_status"]["read own record (must work)"] == 200
    assert r["incident_response"]["strong_grade"] - r["incident_response"]["weak_grade"] >= 50
    assert r["incidents"] == 10
