from bulwark.fhir import integration as I

P = {p["id"]: p for p in I.load()}


def rules(pid): return {f.rule for f in I.assess(P[pid])}


def test_well_run_partner_is_clean():
    assert rules("lab-vendor") == set()


def test_ehr_partner_gaps():
    r = rules("ehr-partner")
    assert {"weak-tls", "long-token", "no-mtls", "broad-scope", "unknown-field", "unsigned-webhook", "slow-breach-notice"} <= r


def test_marketing_vendor_without_baa_is_high_risk():
    r = rules("marketing-analytics")
    assert {"no-baa", "static-credential", "minimum-necessary"} <= r


def test_ssn_is_flagged_because_it_is_not_a_real_patient_element():
    assert any("Patient.ssn" in f.title for f in I.assess(P["ehr-partner"]))
