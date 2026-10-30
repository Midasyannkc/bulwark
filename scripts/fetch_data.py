"""Download real public sources and keep the trimmed fields Bulwark uses.
Sources (all reachable from the build sandbox via raw.githubusercontent.com):
  NIST OSCAL SP 800-53 rev5 catalog and Moderate baseline profile (usnistgov/oscal-content)
  MITRE ATT&CK enterprise (mitre/cti)
  HL7 FHIR R4 StructureDefinitions (hapifhir/hapi-fhir validation resources)
  CISA KEV catalog (cisa.gov, via raw mirror is not used; fetched directly if reachable)
Writes data/raw/*.json plus MANIFEST.json with source URL, sha256 of the download and trimmed size."""
import hashlib, json, re, sys, urllib.request
from pathlib import Path
import xml.etree.ElementTree as ET

RAW = Path(__file__).resolve().parents[1] / "data/raw"
RAW.mkdir(parents=True, exist_ok=True)
U = {
 "nist": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json",
 "nist_moderate": "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_MODERATE-baseline_profile.json",
 "attack": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
 "fhir": "https://raw.githubusercontent.com/hapifhir/hapi-fhir/master/hapi-fhir-validation-resources-r4/src/main/resources/org/hl7/fhir/r4/model/profile/profiles-resources.xml",
}
FHIR_RESOURCES = ["Patient", "Observation", "Encounter", "Condition", "MedicationRequest", "DocumentReference", "Practitioner", "Organization",
                  "AllergyIntolerance", "Bundle", "AuditEvent", "Consent", "Procedure", "Coverage", "Provenance"]
manifest = {}


def get(k):
    b = urllib.request.urlopen(U[k], timeout=120).read()
    manifest[k] = {"url": U[k], "sha256": hashlib.sha256(b).hexdigest(), "bytes": len(b)}
    return b


def controls(groups):
    out = {}
    def walk(c, family):
        out[c["id"]] = {"title": c["title"], "family": family, "withdrawn": any(p["name"] == "status" and p["value"] == "withdrawn" for p in c.get("props", []))}
        for s in c.get("controls", []):
            walk(s, family)
    for g in groups:
        for c in g.get("controls", []):
            walk(c, g["id"])
    return out


nist = json.loads(get("nist"))["catalog"]
cat = controls(nist["groups"])
mod = json.loads(get("nist_moderate"))["profile"]
ids = []
for imp in mod["imports"]:
    for inc in imp.get("include-controls", []):
        ids += inc.get("with-ids", [])
json.dump({"controls": cat, "moderate_baseline": sorted(set(ids))}, open(RAW / "nist80053.json", "w"), indent=0, sort_keys=True)

at = json.loads(get("attack"))
tech = {}
for o in at["objects"]:
    if o.get("type") == "attack-pattern" and not o.get("revoked") and not o.get("x_mitre_deprecated"):
        eid = next((r["external_id"] for r in o.get("external_references", []) if r.get("source_name") == "mitre-attack"), None)
        if eid:
            tech[eid] = {"name": o["name"], "tactics": sorted(p["phase_name"] for p in o.get("kill_chain_phases", [])), "platforms": sorted(o.get("x_mitre_platforms", []))}
json.dump(tech, open(RAW / "attack_techniques.json", "w"), indent=0, sort_keys=True)

root = ET.fromstring(get("fhir"))
ns = {"f": "http://hl7.org/fhir"}
res = {}
for sd in root.iter("{http://hl7.org/fhir}StructureDefinition"):
    name = sd.find("f:name", ns).get("value")
    if name in FHIR_RESOURCES and sd.find("f:kind", ns).get("value") == "resource":
        els = {}
        for e in sd.find("f:snapshot", ns).findall("f:element", ns):
            path = e.find("f:path", ns).get("value")
            mx = e.find("f:max", ns)
            types = [t.find("f:code", ns).get("value") for t in e.findall("f:type", ns)]
            els[path] = {"min": int(e.find("f:min", ns).get("value")), "max": mx.get("value") if mx is not None else "1", "types": types}
        res[name] = els
json.dump(res, open(RAW / "fhir_r4_elements.json", "w"), indent=0, sort_keys=True)
json.dump(manifest, open(RAW / "MANIFEST.json", "w"), indent=1, sort_keys=True)
print({k: (RAW / f).stat().st_size for k, f in (("nist", "nist80053.json"), ("attack", "attack_techniques.json"), ("fhir", "fhir_r4_elements.json"))}, len(cat), len(set(ids)), len(tech), {k: len(v) for k, v in res.items()})
