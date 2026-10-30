"""Deterministic tabletop simulator.  A play is a set of decision choices plus the minute each runbook step finished.
Scoring is rule based; there is no model in the loop."""
import yaml
from datetime import date, timedelta
from pathlib import Path
from bulwark.ir import breach


def load(path):
    return yaml.safe_load(Path(path).read_text())


def score(scenario, runbook, play):
    steps = {s["id"]: s for s in runbook["steps"]}
    due, t = {}, 0
    for sid in sorted(steps):
        t += steps[sid]["minutes"]
        due[sid] = t
    done = play["steps"]
    findings, pts, total = [], 0, 0
    for d in scenario["decisions"]:
        total += 2
        choice = play["decisions"].get(d["id"])
        opt = d["options"].get(choice)
        if opt and opt["correct"]:
            pts += 2
        else:
            findings.append(f"{d['id']}: chose {choice or 'nothing'}. {opt['why'] if opt else 'No decision made'}.")
    late, skipped = [], []
    for sid, s in sorted(steps.items()):
        total += 1
        if sid not in done:
            skipped.append(sid); findings.append(f"Step {sid} ({s['phase']}) was never completed."); continue
        if done[sid] <= due[sid]:
            pts += 1
        else:
            late.append(sid); findings.append(f"Step {sid} finished at minute {done[sid]}, target {due[sid]}.")
    # ordering: evidence must be preserved before eradication or recovery work
    pres = next((sid for sid, s in steps.items() if s["phase"] == "containment" and s.get("preserves_evidence")), None)
    for sid, s in steps.items():
        if s["phase"] in ("eradication", "recovery") and pres in done and sid in done and done[sid] < done[pres]:
            total += 1
            findings.append(f"Step {sid} ({s['phase']}) finished before evidence was preserved (step {pres}).")
    for sid, s in steps.items():
        if s["phase"] in ("eradication", "recovery") and pres not in done and sid in done:
            findings.append(f"Step {sid} ({s['phase']}) done without preserving evidence.")
    facts = {}
    for inj in scenario["injects"]:
        facts.update(inj.get("facts", {}))
    dl = breach.deadlines(scenario["discovered"], facts.get("affected", 0), facts.get("largest_state")) if facts else {}
    grade = round(100 * pts / total) if total else 0
    return {"scenario": scenario["id"], "grade": grade, "points": pts, "of": total, "late_steps": late, "skipped_steps": skipped,
            "deadlines": {k: v.isoformat() for k, v in sorted(dl.items())}, "findings": findings}
