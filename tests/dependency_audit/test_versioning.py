import pytest

from svarog.dependency_audit.models import MatchStatus
from svarog.dependency_audit.versioning import evaluate_version_range


@pytest.mark.parametrize(
    ("installed", "affected_range", "expected"),
    [
        ("1.5", ">=1,<2", MatchStatus.AFFECTED),
        ("2.0", ">=1,<2", MatchStatus.NOT_AFFECTED),
        ("1.2.3", "= 1.2.3", MatchStatus.AFFECTED),
        ("1.2.4", "= 1.2.3", MatchStatus.NOT_AFFECTED),
        ("2.0.0rc1", "<2.0.0", MatchStatus.NOT_AFFECTED),
    ],
)
def test_evaluates_supported_ranges(installed, affected_range, expected):
    result = evaluate_version_range(installed, affected_range)
    assert result.status is expected


def test_normalizes_standalone_single_equals_only():
    result = evaluate_version_range("1.2.3", "= 1.2.3")
    assert result.normalized_range == "==1.2.3"


@pytest.mark.parametrize(
    "affected_range",
    ["==1.0", "===1.0", ">=1.0", "<=1.0", "!=1.0", "~=1.0", "=>1.0", "= >1.0", "= =1.0"],
)
def test_does_not_rewrite_other_comparison_forms(affected_range):
    result = evaluate_version_range("1.0", affected_range)
    assert result.normalized_range == affected_range.strip()


def test_preserves_double_equals_range_and_matches():
    result = evaluate_version_range("1.0", "==1.0")
    assert result.status is MatchStatus.AFFECTED


@pytest.mark.parametrize(
    "affected_range",
    ["<0.8.3ubuntu7.5", ">=0.7.6,<0.7.11p3", "<4.6.0.stable11", "<0.9-stable"],
)
def test_rejects_unsupported_distribution_versions(affected_range):
    result = evaluate_version_range("1.0", affected_range)
    assert result.status is MatchStatus.INDETERMINATE
    assert result.reason_code == "unsupported_version_range"


def test_invalid_installed_version_is_indeterminate():
    result = evaluate_version_range("vendor-build", ">=1")
    assert result.status is MatchStatus.INDETERMINATE
    assert result.reason_code == "invalid_installed_version"


@pytest.mark.parametrize("affected_range", ["", "   ", ",", ">=1,", ",<2", ">=1,,<2"])
def test_rejects_empty_range_fragments(affected_range):
    result = evaluate_version_range("1.0", affected_range)
    assert result.status is MatchStatus.INDETERMINATE
    assert result.reason_code == "unsupported_version_range"


@pytest.mark.parametrize("affected_range", ["=1.*", "=1.0.*"])
def test_rejects_wildcard_single_equals_versions(affected_range):
    result = evaluate_version_range("1.0", affected_range)
    assert result.status is MatchStatus.INDETERMINATE
    assert result.reason_code == "unsupported_version_range"


@pytest.mark.parametrize(
    ("installed", "affected_range", "expected"),
    [("1.0", "<=1.0", MatchStatus.AFFECTED), ("1.1", "!=1.0", MatchStatus.AFFECTED),
     ("1.2", "~=1.0", MatchStatus.AFFECTED), ("1.0", "===1.0", MatchStatus.AFFECTED)],
)
def test_evaluates_comparison_operators(installed, affected_range, expected):
    result = evaluate_version_range(installed, affected_range)
    assert result.status is expected


@pytest.mark.parametrize("affected_range", ["=>1.0", "= >1.0", "= =1.0"])
def test_malformed_comparisons_are_indeterminate_and_unchanged(affected_range):
    result = evaluate_version_range("1.0", affected_range)
    assert result.status is MatchStatus.INDETERMINATE
    assert result.normalized_range == affected_range.strip()


def test_malformed_single_equals_is_not_rewritten():
    result = evaluate_version_range("1.0", "=>1.0")
    assert result.status is MatchStatus.INDETERMINATE
    assert result.normalized_range == "=>1.0"
