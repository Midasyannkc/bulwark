import copy
from datetime import date
from pathlib import Path
import pytest
from bulwark.ir import runbook as R, breach as B

DOC = R.load(Path(__file__).resolve().parents[1] / "data/ir/runbooks.yml")


def test_shipped_runbooks_lint_clean():
    assert [(f.rule, f.location) for f in R.lint(DOC)] == []


def test_three_runbooks_cover_all_seven_phases():
    for rb in DOC["runbooks"]:
        assert {s["phase"] for s in rb["steps"]} == set(R.PHASES)


@pytest.mark.parametrize("phase", R.PHASES)
def test_removing_a_phase_is_flagged(phase):
    d = copy.deepcopy(DOC)
    rb = d["runbooks"][0]; rb["steps"] = [s for s in rb["steps"] if s["phase"] != phase]
    assert any(f.rule == "missing-phase" and phase in f.title for f in R.lint(d))


def test_unknown_owner_and_missing_evidence_flagged():
    d = copy.deepcopy(DOC)
    d["runbooks"][1]["steps"][2]["owner"] = "TBD"
    del d["runbooks"][1]["steps"][3]["evidence"]
    rules = {f.rule for f in R.lint(d)}
    assert {"unknown-owner", "no-evidence"} <= rules


def test_phi_runbook_without_breach_assessment_flagged():
    d = copy.deepcopy(DOC)
    for s in d["runbooks"][2]["steps"]: s.pop("decision", None)
    assert any(f.rule == "no-breach-assessment" for f in R.lint(d))


def test_fake_attack_id_flagged():
    d = copy.deepcopy(DOC); d["runbooks"][0]["attack"].append("T9999")
    assert any(f.rule == "bad-attack-id" for f in R.lint(d))


def test_breach_deadlines_large_breach():
    d = B.deadlines(date(2026, 3, 1), 1200, largest_state_count=900)
    assert d["individuals"] == date(2026, 4, 30) and d["hhs"] == d["individuals"] and d["media"] == d["individuals"]


def test_breach_deadlines_small_breach_goes_to_hhs_after_year_end():
    d = B.deadlines(date(2026, 3, 1), 120)
    assert d["individuals"] == date(2026, 4, 30)
    assert d["hhs"] == date(2027, 3, 1) and "media" not in d


def test_business_associate_notifies_covered_entity():
    assert B.deadlines(date(2026, 10, 1), 10, role="business_associate") == {"individuals": date(2026, 11, 30), "covered_entity": date(2026, 11, 30)}
