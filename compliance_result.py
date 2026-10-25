from dataclasses import dataclass
from typing import Any

@dataclass
class ComplianceResult:
    device: str
    category: str
    target: str
    status: str
    message: str
    expected: Any = None
    actual: Any = None

    def to_dict(self):
        return {
            "device": self.device,
            "category": self.category,
            "target": self.target,
            "status": self.status,
            "message": self.message,
            "expected": self.expected,
            "actual": self.actual,
        }

