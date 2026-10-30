from dataclasses import dataclass, field, asdict


@dataclass
class Finding:
    source: str
    rule: str
    severity: str
    title: str
    location: str
    detail: str = ""
    refs: dict = field(default_factory=dict)

    def to_dict(self): return asdict(self)
