"""PEP 440 version range evaluation."""

import re
from dataclasses import dataclass

from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import InvalidVersion, Version

from .models import MatchStatus


@dataclass(frozen=True, slots=True)
class RangeEvaluation:
    status: MatchStatus
    normalized_range: str | None
    reason_code: str | None = None


def evaluate_version_range(installed_version: str, affected_range: str) -> RangeEvaluation:
    try:
        version = Version(installed_version)
    except InvalidVersion:
        return RangeEvaluation(MatchStatus.INDETERMINATE, None, "invalid_installed_version")

    fragments = [fragment.strip() for fragment in affected_range.split(",")]
    normalized_range = ",".join(_normalize_fragment(fragment) for fragment in fragments)
    if any(not fragment for fragment in fragments):
        return RangeEvaluation(MatchStatus.INDETERMINATE, normalized_range, "unsupported_version_range")
    try:
        specifier = SpecifierSet(normalized_range)
    except (InvalidSpecifier, ValueError):
        return RangeEvaluation(MatchStatus.INDETERMINATE, normalized_range, "unsupported_version_range")

    matches = specifier.contains(version, prereleases=True)
    status = MatchStatus.AFFECTED if matches else MatchStatus.NOT_AFFECTED
    return RangeEvaluation(status, normalized_range)


def _normalize_fragment(fragment: str) -> str:
    match = re.fullmatch(r"=\s*(?![<>=!~])([^\s,]+)", fragment.strip())
    if not match:
        return fragment.strip()
    try:
        Version(match.group(1))
    except InvalidVersion:
        return fragment.strip()
    return f"=={match.group(1)}"
