"""Evidence collectors.  Each reads a JSON snapshot shaped like AWS API output and returns
{population, sample, exceptions, passed, note}.  Pure functions of the snapshot and its as_of date."""
import hashlib, math
from datetime import date

KEY_MAX, REVIEW_MAX, RESTORE_MAX = 90, 90, 180
SLA = {"critical": 15, "high": 30}
ADMIN_PORTS = {22, 3389, 5432, 3306, 1433, 6379}


def sample(ids, size=None):
    """Internal sampling policy (not an audit standard): everything up to 5, otherwise the larger of 5 and 25 percent, chosen by hash order so it is stable."""
    ids = sorted(ids)
    n = len(ids)
    k = n if n <= 5 else max(5, math.ceil(0.25 * n))
    k = min(n, size or k)
    return sorted(sorted(ids, key=lambda i: hashlib.sha256(i.encode()).hexdigest())[:k])


def _r(pop, exc, note=""):
    return {"population": len(pop), "sample": sample(pop), "exceptions": sorted(exc), "passed": not exc, "note": note}


def _days(a, b): return (date.fromisoformat(a) - date.fromisoformat(b)).days


def mfa(s):
    users = [u for u in s["iam"]["users"] if u["console"]]
    return _r([u["name"] for u in users], [u["name"] for u in users if not u["mfa"]], "console users without MFA")


def offboarding(s):
    off = [u for u in s["iam"]["users"] if u["offboarded"]]
    return _r([u["name"] for u in off], [u["name"] for u in off if u["console"] or u["last_used_days"] < 30], "offboarded users still enabled or recently active")


def key_age(s):
    us = s["iam"]["users"]
    return _r([u["name"] for u in us], [u["name"] for u in us if u["key_age_days"] > KEY_MAX], f"access keys older than {KEY_MAX} days")


def privileged(s):
    adm = [u for u in s["iam"]["users"] if u["admin"]]
    exc = [u["name"] for u in adm if u["console"] and not u["mfa"]]
    if len(adm) > 4: exc.append("admin-count>4")
    return _r([u["name"] for u in adm], exc, "admins without MFA, or more than four admins")


def access_review(s):
    rv = s["access_reviews"]
    return _r([r["system"] for r in rv], [r["system"] for r in rv if _days(s["as_of"], r["last_review"]) > REVIEW_MAX], f"last review older than {REVIEW_MAX} days")


def phi_buckets(s):
    b = [x for x in s["s3"]["buckets"] if x["phi"]]
    return _r([x["name"] for x in b], [x["name"] for x in b if not (x["encrypted"] and x["versioning"] and x["public_access_block"])], "PHI bucket missing encryption, versioning or public access block")


def bucket_public(s):
    b = s["s3"]["buckets"]
    return _r([x["name"] for x in b], [x["name"] for x in b if not x["public_access_block"]], "bucket without public access block")


def databases(s):
    d = s["rds"]["instances"]
    return _r([x["id"] for x in d], [x["id"] for x in d if not x["encrypted"] or x["public"] or (x["phi"] and x["backup_days"] < 7)], "unencrypted, public, or PHI database with short backups")


def kms_rotation(s):
    k = s["kms"]["keys"]
    return _r([x["id"] for x in k], [x["id"] for x in k if not x["rotation"]], "key without rotation")


def cloudtrail(s):
    t = s["cloudtrail"]["trails"]
    return _r([x["name"] for x in t], [x["name"] for x in t if not (x["multi_region"] and x["log_validation"] and x["kms"])], "trail not multi-region, validated and encrypted") if t else {"population": 0, "sample": [], "exceptions": ["no trail"], "passed": False, "note": "no trail"}


def admin_ports(s):
    g = s["network"]["security_groups"]
    bad = [x["id"] for x in g for r in x["ingress"] if r["cidr"] == "0.0.0.0/0" and r["port"] in ADMIN_PORTS]
    return _r([x["id"] for x in g], bad, "administrative port open to 0.0.0.0/0")


def vuln_sla(s):
    v = s["vulnerabilities"]["open"]
    return _r([x["id"] for x in v], [x["id"] for x in v if x["sev"] in SLA and x["age_days"] > SLA[x["sev"]]], "open past remediation SLA")


def endpoints(s):
    e = s["endpoints"]
    return _r([x["host"] for x in e], [x["host"] for x in e if not (x["disk_encrypted"] and x["edr"])], "endpoint without disk encryption or EDR")


def restore_test(s):
    age = _days(s["as_of"], s["backups"]["last_restore_test"])
    return {"population": 1, "sample": ["restore-test"], "exceptions": [] if age <= RESTORE_MAX else [f"last test {age} days ago"], "passed": age <= RESTORE_MAX, "note": f"restore test within {RESTORE_MAX} days"}


def training(s):
    t = s["training"]
    pct = 100 * t["completed"] / t["employees"]
    return {"population": t["employees"], "sample": [], "exceptions": [] if pct >= 95 else [f"{pct:.1f} percent complete"], "passed": pct >= 95, "note": "completion at least 95 percent"}


COLLECTORS = {f.__name__ if f.__name__ != "mfa" else "mfa": f for f in (mfa, offboarding, key_age, privileged, access_review, phi_buckets, bucket_public, databases, kms_rotation, cloudtrail, admin_ports, vuln_sla, endpoints, restore_test, training)}
