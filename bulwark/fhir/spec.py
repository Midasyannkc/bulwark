"""Validate resources against the real FHIR R4 element definitions (data/raw/fhir_r4_elements.json)."""
import re
from bulwark import refs
from bulwark.model import Finding

PRIMITIVE_EXT = re.compile(r"^_(.+)$")


def _element_names(rtype):
    spec = refs.fhir()[rtype]
    names = {}
    for path, d in spec.items():
        parts = path.split(".")
        if len(parts) == 2:
            names[parts[1]] = d
    return names


def _match(key, names):
    if key in names: return names[key]
    for n, d in names.items():
        if n.endswith("[x]") and key.startswith(n[:-3]) and key[len(n) - 3:][:1].isupper():
            return d
    return None


def validate(res):
    out = []
    rtype = res.get("resourceType")
    if rtype not in refs.fhir():
        return [Finding("fhir-spec", "unknown-resource", "high", f"resourceType {rtype!r} is not in the loaded R4 definitions", str(rtype))]
    names = _element_names(rtype)
    loc = f"{rtype}/{res.get('id', '?')}"
    for k, v in res.items():
        if k == "resourceType": continue
        base = PRIMITIVE_EXT.match(k)
        d = _match(base.group(1) if base else k, names)
        if d is None:
            out.append(Finding("fhir-spec", "unknown-element", "medium", f"{k} is not an element of {rtype} in FHIR R4", loc)); continue
        if d["max"] == "*" and not isinstance(v, list):
            out.append(Finding("fhir-spec", "cardinality", "medium", f"{k} must be an array (max *)", loc))
        if d["max"] == "1" and isinstance(v, list):
            out.append(Finding("fhir-spec", "cardinality", "medium", f"{k} must not be an array (max 1)", loc))
    for n, d in names.items():
        if d["min"] >= 1 and _match_present(n, res) is False:
            out.append(Finding("fhir-spec", "missing-required", "high", f"required element {n} is missing", loc))
    return sorted(out, key=lambda f: (f.location, f.rule, f.title))


def _match_present(name, res):
    if name.endswith("[x]"):
        return any(k.startswith(name[:-3]) for k in res)
    return name in res
