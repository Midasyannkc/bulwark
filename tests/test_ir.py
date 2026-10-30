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


from bulwark.ir import tabletop as T

SC = T.load(Path(__file__).resolve().parents[1] / "data/ir/scenarios.yml")["scenarios"][0]
RB = next(r for r in DOC["runbooks"] if r["id"] == SC["runbook"])


def test_strong_play_scores_far_above_weak():
    s, w = T.score(SC, RB, SC["plays"]["strong"]), T.score(SC, RB, SC["plays"]["weak"])
    assert s["grade"] >= 90 and w["grade"] <= 40 and s["grade"] - w["grade"] >= 50


def test_scenario_deadlines_use_discovery_date_and_revealed_counts():
    s = T.score(SC, RB, SC["plays"]["strong"])
    assert s["deadlines"] == {"hhs": "2027-01-08", "individuals": "2027-01-08", "media": "2027-01-08"}


def test_weak_play_findings_name_the_mistakes():
    w = T.score(SC, RB, SC["plays"]["weak"])
    text = " ".join(w["findings"])
    assert "D1" in text and "evidence" in text and w["skipped_steps"]


def test_every_runbook_has_an_explicit_evidence_preservation_step_in_containment():
    for rb in DOC["runbooks"]:
        assert any(s["phase"] == "containment" and s.get("preserves_evidence") for s in rb["steps"]), rb["id"]


def test_lint_flags_runbook_without_structured_preservation_step():
    d = copy.deepcopy(DOC)
    for s in d["runbooks"][2]["steps"]: s.pop("preserves_evidence", None); s["action"] = s["action"].replace("preserve", "keep")
    assert any(f.rule == "containment-without-preservation" for f in R.lint(d))


def test_isolation_step_that_merely_mentions_memory_is_not_preservation():
    d = copy.deepcopy(DOC)
    rb = d["runbooks"][2]
    for s in rb["steps"]: s.pop("preserves_evidence", None)
    assert any(f.rule == "containment-without-preservation" for f in R.lint(d))
