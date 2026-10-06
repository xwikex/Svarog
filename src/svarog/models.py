from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from types import MappingProxyType
from typing import Mapping


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ConclusionStatus(str, Enum):
    CONFIRMED = "confirmed"
    HIGHLY_LIKELY = "highly_likely"
    INSUFFICIENT_EVIDENCE = "insufficient_evidence"
    RULED_OUT = "ruled_out"


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    line_number: int
    timestamp: str
    source_ip: str
    method: str
    host: str
    path: str
    query: str = ""
    status: int | None = None
    user_agent: str = ""
    request_id: str | None = None
    body_excerpt: str = ""


@dataclass(frozen=True, slots=True)
class InputIssue:
    line_number: int
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class ParseResult:
    events: tuple[NormalizedEvent, ...]
    issues: tuple[InputIssue, ...] = ()
    total_issue_count: int | None = None

    def __post_init__(self) -> None:
        total = len(self.issues) if self.total_issue_count is None else self.total_issue_count
        if isinstance(total, bool) or not isinstance(total, int) or total < len(self.issues):
            raise ValueError("total_issue_count 必须是不小于已保留问题数的整数")
        object.__setattr__(self, "total_issue_count", total)


@dataclass(frozen=True, slots=True)
class Evidence:
    rule_id: str
    category: str
    severity: Severity
    description: str
    matched_field: str
    matched_excerpt: str
    references: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class EventAnalysis:
    event: NormalizedEvent
    local_severity: Severity
    conclusion: ConclusionStatus
    confidence: float
    evidence: tuple[Evidence, ...]
    attack_mappings: tuple[str, ...]
    recommendations: tuple[str, ...]
    actions_executed: bool = False


@dataclass(frozen=True, slots=True)
class AnalysisReport:
    schema_version: str
    generated_at: str
    analysis_status: str
    summary: Mapping[str, int]
    events: tuple[EventAnalysis, ...]
    input_issues: tuple[InputIssue, ...] = ()
    warnings: tuple[str, ...] = field(default_factory=tuple)
    actions_executed: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "summary", MappingProxyType(dict(self.summary)))
