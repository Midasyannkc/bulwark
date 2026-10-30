"""HIPAA Safe Harbor de-identification (45 CFR 164.514(b)(2)) for the synthetic FHIR resources.
Removes the 18 identifier classes this model can carry and scans free text for leaks.  Engineering aid, not an expert determination."""
import copy, hashlib, hmac, re
from bulwark.model import Finding

DROP_KEYS = {"name", "telecom", "photo", "identifier", "contact", "text", "extension", "modifierExtension", "contained", "meta", "link"}
SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
PHONE = re.compile(r"\b(?:\+?1[ -.])?\(?\d{3}\)?[ -.]\d{3}[ -.]\d{4}\b")
EMAIL = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.]+\b")
DATE = re.compile(r"\b\d{4}-\d{2}-\d{2}\b|\b\d{1,2}/\d{1,2}/\d{2,4}\b")
MRN = re.compile(r"\bMRN[- ]?\d+\b", re.I)
URL = re.compile(r"https?://\S+")
IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
LOW_POP_ZIP3 = {"036", "059", "102", "203", "205", "369", "556", "692", "821", "823", "878", "879", "884", "890", "893"}   # 17 prefixes with 20,000 or fewer people (2000 census list)
TEXT_PATTERNS = [("ssn", SSN), ("phone", PHONE), ("email", EMAIL), ("date", DATE), ("mrn", MRN), ("url", URL), ("ip", IP)]


def pseudonym(pid, key):
    return "x" + hmac.new(key, pid.encode(), hashlib.sha256).hexdigest()[:12]


def _scrub_text(s):
    for _, p in TEXT_PATTERNS:
        s = p.sub("[removed]", s)
    return s


def _year_only(d):
    return d[:4]


def deidentify(res, key: bytes, as_of_year=2026):
    r = copy.deepcopy(res)
    for k in list(r):
        if k in DROP_KEYS:
            del r[k]
    if "id" in r:
        r["id"] = pseudonym(r["id"], key)
    if r.get("resourceType") == "Patient":
        if "birthDate" in r:
            y = int(r["birthDate"][:4])
            r["birthDate"] = str(y) if as_of_year - y <= 89 else str(as_of_year - 90)
        if "address" in r:
            r["address"] = [{"state": a["state"]} | ({"postalCode": a["postalCode"][:3] + "00"} if a.get("postalCode", "")[:3] not in LOW_POP_ZIP3 and a.get("postalCode") else {}) for a in r["address"] if a.get("state")]
    _walk(r, key)
    return r


def _walk(o, key):
    if isinstance(o, dict):
        for k, v in list(o.items()):
            if k == "reference" and isinstance(v, str) and "/" in v:
                t, i = v.split("/", 1); o[k] = f"{t}/{pseudonym(i, key)}"
            elif k == "text" and isinstance(v, str):
                o[k] = _scrub_text(v)
            elif k.endswith(("DateTime", "Date")) or k in ("start", "end", "issued"):
                if isinstance(v, str) and DATE.search(v): o[k] = v[:4]
            else:
                _walk(v, key)
    elif isinstance(o, list):
        for x in o: _walk(x, key)


def leaks(res, raw_values=()):
    """Findings for identifiers still present in a supposedly de-identified resource."""
    import json
    s = json.dumps(res)
    out = []
    for name, p in TEXT_PATTERNS:
        if name == "date":
            continue
        if p.search(s): out.append(Finding("deid", f"leak-{name}", "high", f"{name} pattern remains", res.get("id", "?")))
    for v in raw_values:
        if v and v in s: out.append(Finding("deid", "leak-value", "high", "an original identifying value remains", res.get("id", "?"), v))
    for m in re.finditer(r'"(\w+)": "(\d{4}-\d{2}-\d{2}[^"]*)"', s):
        out.append(Finding("deid", "leak-full-date", "high", f"full date in {m.group(1)}", res.get("id", "?")))
    return out
