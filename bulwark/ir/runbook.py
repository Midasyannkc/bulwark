import yaml
from pathlib import Path
from bulwark.model import Finding
from bulwark import refs

PHASES = ["detection", "containment", "eradication", "recovery", "assessment", "notification", "post-incident"]
EVIDENCE_PHASES = {"detection", "containment", "assessment", "notification"}


def load(path):
    return yaml.safe_load(Path(path).read_text())


def lint(doc):
    roles, out = set(doc["roles"]), []
    for rb in doc["runbooks"]:
        loc = rb["id"]
        steps = rb["steps"]
        ids = [s["id"] for s in steps]
        if len(ids) != len(set(ids)):
            out.append(Finding("runbook", "duplicate-step-id", "high", "Step ids repeat", loc))
        present = [s["phase"] for s in steps]
        for ph in PHASES:
            if ph not in present:
                out.append(Finding("runbook", "missing-phase", "high", f"No {ph} step", loc))
        order = [PHASES.index(p) for p in present if p in PHASES]
        if order != sorted(order):
            out.append(Finding("runbook", "phase-order", "medium", "Steps are out of phase order", loc))
        for s in steps:
            sl = f"{loc} step {s['id']}"
            if s.get("owner") not in roles:
                out.append(Finding("runbook", "unknown-owner", "high", f"Owner {s.get('owner')!r} is not a defined role", sl))
            if s["phase"] in EVIDENCE_PHASES and not s.get("evidence"):
                out.append(Finding("runbook", "no-evidence", "medium", "Step produces no evidence artifact", sl))
            if not s.get("minutes"):
                out.append(Finding("runbook", "no-target-time", "low", "Step has no target time", sl))
        if rb.get("touches_phi") and not any(s.get("decision") == "breach_assessment" for s in steps):
            out.append(Finding("runbook", "no-breach-assessment", "high", "PHI runbook has no HIPAA breach risk assessment decision", loc))
        if rb.get("touches_phi") and not any(s["phase"] == "notification" and s["owner"] in ("legal-counsel", "privacy-officer") for s in steps):
            out.append(Finding("runbook", "no-notification-owner", "high", "No legal or privacy owner for the notification decision", loc))
        for t in rb.get("attack", []):
            if not refs.attack_ok(t):
                out.append(Finding("runbook", "bad-attack-id", "medium", f"{t} is not a real ATT&CK technique", loc))
        contain = [s for s in steps if s["phase"] == "containment"]
        evid = [s for s in steps if "preserve" in s["action"].lower() or "log" in " ".join(s.get("evidence", [])).lower()]
        if contain and not any(s["phase"] == "containment" and "preserv" in s["action"].lower() for s in steps):
            out.append(Finding("runbook", "containment-without-preservation", "medium", "Containment never preserves evidence before changes", loc))
    return sorted(out, key=lambda f: (f.location, f.rule))
