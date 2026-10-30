import hashlib, json
from datetime import date, timedelta
from pathlib import Path
import yaml
from bulwark import refs
from bulwark.evidence import collectors as C

ROOT = Path(__file__).resolve().parents[2]


def library(path=None):
    return yaml.safe_load(Path(path or ROOT / "data/controls.yml").read_text())["controls"]


def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":")).encode()


def build(snapshot, controls=None):
    controls = controls or library()
    as_of = date.fromisoformat(snapshot["as_of"])
    items = []
    for c in controls:
        res = C.COLLECTORS[c["collector"]](snapshot)
        art = {"control": c["id"], "as_of": snapshot["as_of"], "result": res}
        items.append({"control": c["id"], "title": c["title"], "status": "pass" if res["passed"] else "exception", "population": res["population"], "sample": res["sample"],
                      "exceptions": res["exceptions"], "collected": snapshot["as_of"], "expires": (as_of + timedelta(days=c["frequency_days"])).isoformat(),
                      "sha256": hashlib.sha256(canon(art)).hexdigest(), "soc2": c["soc2"], "hipaa": c["hipaa"], "nist": c["nist"], "hitrust": c["hitrust"], "artifact": art})
    return {"as_of": snapshot["as_of"], "items": items}


def stale(pkg, today: date):
    return sorted(i["control"] for i in pkg["items"] if date.fromisoformat(i["expires"]) < today)


def verify_hashes(pkg):
    return [i["control"] for i in pkg["items"] if hashlib.sha256(canon(i["artifact"])).hexdigest() != i["sha256"]]


def mapping_errors(controls=None):
    errs = []
    for c in controls or library():
        errs += [(c["id"], n) for n in c["nist"] if not refs.nist_ok(n)]
    return errs


def coverage():
    """Share of the real NIST 800-53 Moderate baseline touched by the control library (base controls only)."""
    base = {b for b in refs.nist()["moderate_baseline"] if "." not in b}
    mine = {n.split(".")[0] for c in library() for n in c["nist"]}
    hit = sorted(base & mine)
    fam = {}
    for b in base: fam.setdefault(b.split("-")[0], [0, 0])[1] += 1
    for b in hit: fam[b.split("-")[0]][0] += 1
    return {"baseline_base_controls": len(base), "covered": len(hit), "percent": round(100 * len(hit) / len(base), 1), "by_family": {k: f"{v[0]}/{v[1]}" for k, v in sorted(fam.items())}}


def index_md(pkg):
    L = [f"# Evidence index (as of {pkg['as_of']})", "", "| Control | Status | Population | Exceptions | SOC 2 | HIPAA | SHA-256 |", "| --- | --- | --- | --- | --- | --- | --- |"]
    for i in pkg["items"]:
        L.append(f"| {i['control']} | {i['status']} | {i['population']} | {', '.join(i['exceptions']) or 'none'} | {', '.join(i['soc2'])} | {', '.join(i['hipaa'])} | `{i['sha256'][:12]}` |")
    return "\n".join(L) + "\n"
