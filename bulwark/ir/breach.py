"""HIPAA Breach Notification Rule deadlines (45 CFR 164.404 to 164.410) as I understand the rule.
This is an engineering aid, not legal advice; counsel decides.

- Individuals: without unreasonable delay and no later than 60 calendar days after discovery.
- HHS: 500 or more individuals, at the same time as individual notice; fewer than 500, within 60 days after the end of the calendar year of discovery.
- Media: more than 500 residents of one State or jurisdiction, within 60 days.
- Business associate to covered entity: without unreasonable delay and no later than 60 days after discovery.
Discovery is the first day the breach is known, or by reasonable diligence would have been known."""
from datetime import date, timedelta

LIMIT = 60


def deadlines(discovered: date, affected: int, largest_state_count: int | None = None, role: str = "covered_entity"):
    largest = affected if largest_state_count is None else largest_state_count
    d = {"individuals": discovered + timedelta(days=LIMIT)}
    if role == "business_associate":
        d["covered_entity"] = discovered + timedelta(days=LIMIT)
        return d
    if affected >= 500:
        d["hhs"] = d["individuals"]
    else:
        d["hhs"] = date(discovered.year + 1, 1, 1) + timedelta(days=LIMIT - 1)   # 60 days after 31 Dec
    if largest > 500:
        d["media"] = d["individuals"]
    return d
