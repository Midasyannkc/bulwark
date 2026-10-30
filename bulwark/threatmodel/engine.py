"""Threat modeling as code: a data-flow model in YAML goes in, STRIDE threats come out, each mapped to a
real ATT&CK technique and real NIST 800-53 controls.  Rules are deterministic; the output is sorted."""
import yaml
from pathlib import Path
from bulwark.model import Finding
from bulwark import refs

TRUST = {"untrusted": 0, "low": 1, "medium": 2, "high": 3}
SENSITIVE = {"PHI", "PII"}


def load(path):
    return yaml.safe_load(Path(path).read_text())


def _t(rule, stride, sev, title, loc, tech, ctl, fix, detail=""):
    return Finding("threatmodel", rule, sev, title, loc, detail or fix, {"stride": stride, "attack": tech, "nist": ctl, "mitigation": fix})


def analyze(m):
    el, zones = m["elements"], m["zones"]
    out = []
    for f in m["flows"]:
        s, d = el[f["src"]], el[f["dst"]]
        sens = SENSITIVE & set(f.get("data", []))
        loc = f"{f['id']} {f['src']}->{f['dst']}"
        if sens and not f.get("tls"):
            out.append(_t("flow-no-tls", "I", "high", "Sensitive data crosses a flow without TLS", loc, "T1040", ["sc-8", "sc-8.1"], "Require TLS 1.2+ on every flow carrying PHI or PII"))
        if "PHI" in sens and d.get("kind") == "external" and not f.get("minimized"):
            out.append(_t("phi-to-partner-unminimized", "I", "medium", "PHI sent to an external party without a minimum-necessary filter", loc, "T1567", ["ac-4", "si-12"], "Filter the payload to the fields the partner needs and log the disclosure"))
        if TRUST[zones[s["zone"]]["trust"]] < TRUST[zones[d["zone"]]["trust"]] and d.get("kind") == "process" and not d.get("authn"):
            out.append(_t("unauthenticated-inbound", "S", "high", "Lower-trust caller reaches a process that does not authenticate it", loc, "T1190", ["ia-2", "ac-3"], "Authenticate callers with OAuth 2, mTLS or workload identity"))
        gap = TRUST[zones[d["zone"]]["trust"]] - TRUST[zones[s["zone"]]["trust"]]
        if s["kind"] == "external" and d.get("kind") in ("store",) :
            out.append(_t("external-direct-to-store", "T", "high", "External party writes directly to a data store", loc, "T1190", ["sc-7", "ac-4"], "Put an authenticated service between the party and the store"))
        if s.get("zone") in ("internet", "dmz") and d.get("zone") == "data" and s["kind"] != "external":
            out.append(_t("boundary-skip", "E", "high", "Edge-zone component talks to the data zone directly", loc, "T1190", ["sc-7"], "Route through the application tier"))
        if d.get("kind") == "process" and d.get("authn") == "token" and sens and TRUST[zones[d["zone"]]["trust"]] >= 2:
            out.append(_t("bearer-only-internal-auth", "S", "low", "Internal service relies on a bearer token alone", loc, "T1528", ["ia-5", "sc-23"], "Prefer mTLS or short-lived signed workload identity"))
    for name, e in el.items():
        if e.get("kind") == "store":
            if SENSITIVE & set(e.get("data", [])) and not e.get("encrypted_at_rest"):
                out.append(_t("store-unencrypted", "I", "high", "Sensitive store is not encrypted at rest", name, "T1530", ["sc-28", "sc-28.1"], "Enable KMS-backed encryption and key rotation"))
            if name.startswith("audit") and not e.get("append_only"):
                out.append(_t("audit-mutable", "R", "high", "Audit log can be altered or deleted", name, "T1070", ["au-9", "au-9.2"], "Make the log append-only and ship a copy to a separate account"))
    out.sort(key=lambda f: (f.location, f.rule))
    return out


def validate_refs(findings):
    """Every technique and control a rule cites must exist in the real catalogs."""
    bad = []
    for f in findings:
        if not refs.attack_ok(f.refs["attack"]): bad.append(("attack", f.refs["attack"]))
        bad += [("nist", c) for c in f.refs["nist"] if not refs.nist_ok(c)]
    return bad
