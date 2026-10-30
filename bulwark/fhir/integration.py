"""Assess third-party integrations that receive patient data against a fixed checklist.
Requested fields are checked against the real FHIR R4 definitions; scope breadth against declared needs."""
from pathlib import Path
import yaml
from bulwark import refs
from bulwark.model import Finding

ROOT = Path(__file__).resolve().parents[2]


def load(path=None):
    return yaml.safe_load(Path(path or ROOT / "data/fhir/partners.yml").read_text())["partners"]


def assess(p):
    out, loc = [], p["id"]
    add = lambda rule, sev, title: out.append(Finding("integration", rule, sev, title, loc))
    if not p.get("baa"): add("no-baa", "high", "No business associate agreement while receiving PHI")
    if tuple(map(int, p["tls_min"].split("."))) < (1, 2): add("weak-tls", "high", f"Minimum TLS {p['tls_min']} is below 1.2")
    a = p["auth"]
    if a["type"] == "api_key": add("static-credential", "high", "Static API key instead of OAuth 2")
    if a["token_ttl_minutes"] > 60: add("long-token", "medium", f"Token lifetime {a['token_ttl_minutes']} minutes exceeds 60")
    if not a.get("mtls") and a["type"] != "api_key": add("no-mtls", "low", "Client authentication without mTLS or private key JWT")
    needs = set(p["needs"])
    for sc in p["scopes"]:
        t = sc.split("/")[1].split(".")[0]
        if t == "*" or sc.endswith(".*"): add("broad-scope", "high", f"{sc} grants more than the declared needs {sorted(needs)}")
        elif t not in needs: add("unneeded-scope", "medium", f"{sc} is outside the declared needs")
    for rtype, fields in p["fields_requested"].items():
        spec = refs.fhir().get(rtype, {})
        for f in fields:
            base = f.replace("[x]", "")
            real = any(k == f"{rtype}.{f}" or (f.endswith("[x]") and k == f"{rtype}.{f}") for k in spec)
            if not real: add("unknown-field", "medium", f"{rtype}.{f} is not an element in FHIR R4")
    pii = {"name", "telecom", "address", "ssn"}
    for rtype, fields in p["fields_requested"].items():
        direct = sorted(set(fields) & pii)
        if direct and p.get("purpose") not in ("treatment", "payment"):
            add("minimum-necessary", "medium", f"Direct identifiers requested for purpose {p.get('purpose')!r}: {direct}")
    w = p["webhook"]
    if not w["signed"]: add("unsigned-webhook", "medium", "Webhook payloads are not signed")
    if not w["ip_allowlist"]: add("no-ip-allowlist", "low", "No source IP allowlist")
    if not p["breach_notice_hours"] or p["breach_notice_hours"] > 72: add("slow-breach-notice", "medium", "Breach notice commitment missing or over 72 hours")
    return sorted(out, key=lambda f: (f.location, f.rule, f.title))
