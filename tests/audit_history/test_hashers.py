from __future__ import annotations

from collections.abc import Mapping
from dataclasses import FrozenInstanceError
import math
import random
import sys

import pytest

import svarog.audit_history.hashers as hashers_module
from svarog.audit_history.hashers import (
    HASH_SCHEMA_VERSION,
    HashPackage,
    HashingError,
    canonical_json_bytes,
    composite_hash,
    environment_hash,
    evaluation_context_hash,
    knowledge_content_hash,
    knowledge_metadata_hash,
    policy_hash,
    semantic_lock_hash,
)
from svarog.dependency_audit.models import AuditIssue
from svarog.project_audit.models import LockIssue


PACKAGES = (
    HashPackage("Demo_Pkg", "1.0", True, "registry"),
    HashPackage("helper", "2.0", True, "git", source_identity="abc123"),
)

LOCK = {
    "path": "C:\\private\\alice\\poetry.lock",
    "lock_format": "poetry",
    "marker_policy": "ignored",
    "version_policy": "all_distinct_versions",
    "applicability": "unverified",
    "warnings": ["marker text\r\nis ignored"],
    "packages": [
        {
            "name": "Demo_Pkg",
            "normalized_name": "demo-pkg",
            "version": "1.0",
            "version_valid": True,
            "source_kind": "registry",
            "dependencies": [
                {
                    "name": "helper",
                    "normalized_name": "helper",
                    "version": "2.0",
                    "source_kind": "git",
                }
            ],
        },
        {
            "name": "helper",
            "normalized_name": "helper",
            "version": "2.0",
            "version_valid": True,
            "source_kind": "git",
            "source_identity": "abc123",
        },
    ],
    "issues": [
        {"code": "invalid_lock_version", "message": "localized message"},
        {"code": "missing_source", "subject": "helper"},
    ],
}

ADVISORIES = {
    "metadata": {
        "path": "C:\\private\\alice\\advisories.db",
        "size_bytes": 8192,
        "sources": ["osv", "ghsa"],
        "last_sync_at": "2026-09-23T12:00:00Z",
        "last_sync_status": "ok",
        "last_sync_message": "complete",
    },
    "advisories": [
        {
            "package_name": "Demo_Pkg",
            "normalized_package_name": "demo-pkg",
            "ghsa_id": "GHSA-2345-6789-cfgh",
            "cve_id": "CVE-2026-0001",
            "state": "published",
            "withdrawn_at": None,
            "version_range": ">=1,<2",
            "fixed_version": "2.0",
            "severity": "high",
            "cvss_score": 8.1,
            "summary": "first line\r\nsecond line",
            "source": "https://github.com/advisories/GHSA-2345-6789-cfgh",
            "updated_at": "2026-09-22T10:00:00Z",
        },
        {
            "package_name": "unrelated",
            "normalized_package_name": "unrelated",
            "ghsa_id": "GHSA-jmpq-rvwx-2345",
            "cve_id": None,
            "state": "published",
            "withdrawn_at": None,
            "version_range": "<9",
            "fixed_version": None,
            "severity": "low",
            "cvss_score": None,
            "summary": "not relevant",
            "source": "osv",
            "updated_at": "2026-09-22T11:00:00Z",
        },
    ],
}

METADATA = {
    "path": "C:\\private\\alice\\advisories.db",
    "size_bytes": 8192,
    "sources": ["osv", "ghsa", "osv"],
    "last_sync_at": "2026-09-23T12:00:00Z",
    "last_sync_status": "ok",
    "last_sync_message": "complete\r\nverified",
}

POLICY = {
    "marker_handling": "ignored",
    "version_handling": "all_distinct_versions",
    "withdrawn_handling": "exclude",
    "detail_limits": {"findings": 500, "issues": 1000},
    "freshness_threshold": {"days": 7},
}


def test_hash_schema_version_is_the_stable_public_identifier() -> None:
    assert HASH_SCHEMA_VERSION == "svarog-hash/1"


def test_canonical_json_has_fixed_utf8_sorted_compact_encoding() -> None:
    assert canonical_json_bytes(
        {"z": [True, None, 3, 1.5], "a": "雪\r\nline"}
    ) == '{"a":"雪\\r\\nline","z":[true,null,3,1.5]}'.encode("utf-8")


@pytest.mark.parametrize(
    "value",
    [
        {"value": math.nan},
        {"value": math.inf},
        {"value": -math.inf},
        {1: "non-string key"},
        {"value": b"bytes"},
        {"value": (1, 2)},
        {"value": {1, 2}},
        {"value": "\ud800"},
    ],
)
def test_canonical_json_rejects_non_json_and_nonfinite_values(value: object) -> None:
    with pytest.raises(HashingError, match="^invalid_canonical_value$") as raised:
        canonical_json_bytes(value)
    assert raised.value.code == "invalid_canonical_value"


def test_canonical_json_rejects_cycles_and_excessive_depth() -> None:
    cycle: list[object] = []
    cycle.append(cycle)
    with pytest.raises(HashingError, match="^invalid_canonical_value$"):
        canonical_json_bytes(cycle)

    nested: list[object] = []
    for _ in range(300):
        nested = [nested]
    with pytest.raises(HashingError, match="^invalid_canonical_value$"):
        canonical_json_bytes(nested)


def test_canonical_json_rejects_oversized_strings_and_total_bytes() -> None:
    with pytest.raises(HashingError, match="^invalid_canonical_value$"):
        canonical_json_bytes("x" * 1_000_001)

    with pytest.raises(HashingError, match="^invalid_canonical_value$"):
        canonical_json_bytes(["x" * 900_000 for _ in range(19)])


def test_hash_iterables_are_bounded_without_consuming_to_exhaustion() -> None:
    class TooLong:
        def __init__(self) -> None:
            self.next_calls = 0

        def __iter__(self) -> TooLong:
            return self

        def __next__(self) -> HashPackage:
            self.next_calls += 1
            if self.next_calls > 50_000:
                raise RuntimeError(r"C:\private\iterator")
            return HashPackage("demo", "1", True, "registry")

    packages = TooLong()
    with pytest.raises(HashingError, match="^invalid_packages$") as raised:
        environment_hash("cpython", (3, 11, 9), packages)
    assert packages.next_calls < 50_000
    assert raised.value.__cause__ is None


def test_iterator_and_property_errors_are_sanitized_without_raw_causes() -> None:
    class BrokenIterator:
        def __iter__(self) -> BrokenIterator:
            return self

        def __next__(self) -> object:
            raise OSError(r"C:\private\iterator")

    class BrokenPackage:
        @property
        def normalized_name(self) -> str:
            raise OSError(r"C:\private\property")

    for call in (
        lambda: environment_hash("cpython", (3, 11, 9), BrokenIterator()),
        lambda: environment_hash("cpython", (3, 11, 9), [BrokenPackage()]),
    ):
        with pytest.raises(HashingError) as raised:
            call()
        assert str(raised.value) in {"invalid_packages", "invalid_hash_input"}
        assert raised.value.__cause__ is None
        assert "private" not in str(raised.value)


def test_read_uses_one_mapping_lookup_or_attribute_access_per_alias() -> None:
    class OnceMapping(Mapping[str, object]):
        def __init__(self, values: dict[str, object]) -> None:
            self.values = values
            self.contains_calls = 0

        def __getitem__(self, key: str) -> object:
            return self.values[key]

        def __contains__(self, key: object) -> bool:
            self.contains_calls += 1
            raise OSError(r"C:\private\mapping")

        def __iter__(self):
            return iter(self.values)

        def __len__(self) -> int:
            return len(self.values)

    class OnceObject:
        version = "1"
        version_valid = True
        source_kind = "registry"

        def __init__(self) -> None:
            self.reads = 0

        @property
        def normalized_name(self) -> str:
            self.reads += 1
            if self.reads > 1:
                raise OSError(r"C:\private\attribute")
            return "demo"

    mapping = OnceMapping(
        {
            "normalized_name": "demo",
            "version": "1",
            "version_valid": True,
            "source_kind": "registry",
        }
    )
    modeled = OnceObject()
    expected = environment_hash(
        "cpython", (3, 11, 9), [HashPackage("demo", "1", True, "registry")]
    )
    assert environment_hash("cpython", (3, 11, 9), [mapping]) == expected
    assert environment_hash("cpython", (3, 11, 9), [modeled]) == expected
    assert mapping.contains_calls == 0
    assert modeled.reads == 1


def test_hash_package_is_frozen_slotted_and_normalizes_identity() -> None:
    package = HashPackage("Demo_Pkg", "1.0", True, " Registry ")
    assert package.normalized_name == "demo-pkg"
    assert package.source_kind == "registry"
    assert not hasattr(package, "__dict__")
    with pytest.raises(FrozenInstanceError):
        package.version = "2.0"  # type: ignore[misc]


def test_hash_package_rejects_absolute_path_as_a_name() -> None:
    with pytest.raises(HashingError, match="^forbidden_path$") as raised:
        HashPackage("C:\\Users\\alice\\demo", "1.0", True, "registry")
    assert str(raised.value) == "forbidden_path"


@pytest.mark.parametrize(
    "name",
    [
        "demo/pkg",
        r"demo\pkg",
        "demo:pkg",
        "../demo",
        "C:demo",
        ".",
        "---",
        "demo-",
        "-demo",
        "démø",
        "ß",
    ],
)
def test_package_names_require_ascii_pep508_distribution_syntax(name: str) -> None:
    with pytest.raises(HashingError, match="^(invalid_package_name|forbidden_path)$"):
        HashPackage(name, "1.0", True, "registry")


def test_environment_hash_fixed_vector() -> None:
    assert environment_hash(
        "CPython", (3, 11, 9), PACKAGES, issues=("missing_metadata",)
    ) == "26ef252ce976b8fd6adc1d64dee7dff7fee154bd171553b9feae95ba1f2c2fbc"


def test_environment_order_and_issue_multiset_order_are_stable() -> None:
    baseline = environment_hash(
        "cpython",
        (3, 11, 9),
        PACKAGES,
        issues=("z_issue", "a_issue", "a_issue"),
    )
    reordered = environment_hash(
        " CPython ",
        (3, 11, 9),
        (PACKAGES[1], PACKAGES[0], PACKAGES[0]),
        issues=(
            {"code": "a_issue", "message": "localized and ignored"},
            {"code": "z_issue", "subject": "private and ignored"},
            {"code": "a_issue", "message": "another ignored message"},
        ),
    )
    assert reordered == baseline


def test_environment_issue_multiplicity_changes_hash() -> None:
    once = environment_hash(
        "cpython", (3, 11, 9), PACKAGES, issues=("missing_metadata",)
    )
    twice = environment_hash(
        "cpython",
        (3, 11, 9),
        PACKAGES,
        issues=("missing_metadata", {"code": "missing_metadata"}),
    )
    assert twice != once


@pytest.mark.parametrize(
    "subject",
    [r"C:\Users\alice\private\METADATA", "/home/alice/private/METADATA"],
)
def test_issue_hashing_ignores_absolute_subject_and_message_details(
    subject: str,
) -> None:
    packages = [HashPackage("demo", "1.0", True, "registry")]
    detailed = AuditIssue(
        code="missing_metadata",
        message=f"ignored path detail: {subject}",
        subject=subject,
    )
    assert environment_hash(
        "cpython", (3, 11, 9), packages, issues=[detailed]
    ) == environment_hash(
        "cpython", (3, 11, 9), packages, issues=["missing_metadata"]
    )


def test_environment_keeps_distinct_versions_and_exact_python_patch() -> None:
    base = environment_hash("cpython", (3, 11, 8), PACKAGES)
    assert environment_hash("cpython", (3, 11, 9), PACKAGES) != base
    assert environment_hash(
        "cpython",
        (3, 11, 8),
        (*PACKAGES, HashPackage("demo-pkg", "1.1", True, "registry")),
    ) != base


def test_environment_unknown_target_is_explicit_and_never_runtime_fallback() -> None:
    unknown = environment_hash("cpython", None, PACKAGES)
    assert environment_hash("CPYTHON", "unknown", PACKAGES) == unknown
    assert environment_hash("cpython", (3, 11, 9), PACKAGES) != unknown


def test_environment_ambiguity_and_source_kind_are_semantic() -> None:
    baseline = environment_hash("cpython", (3, 11, 9), PACKAGES)
    ambiguous = (HashPackage("demo-pkg", "1.0", True, "registry", True), PACKAGES[1])
    changed_source = (
        HashPackage("demo-pkg", "1.0", True, "path"),
        PACKAGES[1],
    )
    assert environment_hash("cpython", (3, 11, 9), ambiguous) != baseline
    assert environment_hash("cpython", (3, 11, 9), changed_source) != baseline


@pytest.mark.parametrize("hash_kind", ["environment", "lock"])
@pytest.mark.parametrize("representation", ["hash_package", "attribute_object"])
@pytest.mark.parametrize(
    ("field", "unsafe_value"),
    [
        ("version", r"C:\Users\alice\private\VERSION"),
        ("version", "/home/alice/private/VERSION"),
        ("source_kind", r"C:\Users\alice\private\source"),
        ("source_kind", "/home/alice/private/source"),
    ],
)
def test_normalized_package_payloads_reject_absolute_paths_for_every_representation(
    hash_kind: str,
    representation: str,
    field: str,
    unsafe_value: str,
) -> None:
    values = {
        "normalized_name": "demo",
        "version": "1",
        "version_valid": True,
        "source_kind": "registry",
    }
    values[field] = unsafe_value

    if representation == "hash_package":
        package: object = HashPackage(
            values["normalized_name"],
            values["version"],
            values["version_valid"],
            values["source_kind"],
        )
    else:
        package = type("AttributePackage", (), values)()

    with pytest.raises(HashingError, match="^forbidden_path$"):
        if hash_kind == "environment":
            environment_hash("cpython", (3, 11, 9), [package])
        else:
            semantic_lock_hash(
                {"format": "uv", "packages": [package], "issues": []}
            )


def test_source_type_alias_matches_modeled_source_kind() -> None:
    package_by_type = {
        "normalized_name": "demo-pkg",
        "version": "1.0",
        "version_valid": True,
        "source_type": "registry",
    }
    package_by_kind = {**package_by_type, "source_kind": "registry"}
    del package_by_kind["source_type"]
    assert environment_hash(
        "cpython", (3, 11, 9), [package_by_type]
    ) == environment_hash("cpython", (3, 11, 9), [package_by_kind])

    lock_by_type = {
        "format": "uv",
        "packages": [package_by_type],
        "issues": [],
    }
    lock_by_kind = {
        "format": "uv",
        "packages": [package_by_kind],
        "issues": [],
    }
    assert semantic_lock_hash(lock_by_type) == semantic_lock_hash(lock_by_kind)


def test_semantic_lock_hash_fixed_vector() -> None:
    assert semantic_lock_hash(
        LOCK
    ) == "fdd3d54ee6ed3a7f024ab6652cdba885da35a8aa742aa0359765a1ed28194d72"


def test_lock_order_package_duplicates_line_endings_and_marker_text_are_ignored() -> None:
    changed = dict(LOCK)
    changed["path"] = "/home/bob/project/poetry.lock"
    changed["packages"] = [LOCK["packages"][1], LOCK["packages"][0], LOCK["packages"][0]]
    changed["issues"] = list(reversed(LOCK["issues"]))
    changed["warnings"] = ["different marker warning\nwith LF"]
    changed["applicability"] = "platform-specific marker expression"
    changed["marker_text"] = "python_version < '3.12'\r\n"
    assert semantic_lock_hash(changed) == semantic_lock_hash(LOCK)


def test_lock_issue_multiplicity_and_exposed_counts_are_semantic() -> None:
    duplicate_issue = {
        **LOCK,
        "issues": [*LOCK["issues"], LOCK["issues"][0]],
    }
    assert semantic_lock_hash(duplicate_issue) != semantic_lock_hash(LOCK)

    counted = {
        **LOCK,
        "total_issue_count": 5,
        "truncated_issue_count": 3,
    }
    changed_total = {**counted, "total_issue_count": 6, "truncated_issue_count": 4}
    assert semantic_lock_hash(counted) != semantic_lock_hash(LOCK)
    assert semantic_lock_hash(changed_total) != semantic_lock_hash(counted)


@pytest.mark.parametrize(
    "subject",
    [r"C:\Users\alice\private\poetry.lock", "/home/alice/private/poetry.lock"],
)
@pytest.mark.parametrize("issue_kind", ["mapping", "object"])
def test_lock_issue_hashing_ignores_absolute_message_and_subject_details(
    subject: str,
    issue_kind: str,
) -> None:
    if issue_kind == "mapping":
        detailed_issue: object = {
            "code": "missing_source",
            "message": f"ignored lock path: {subject}",
            "subject": subject,
        }
    else:
        detailed_issue = LockIssue(
            code="missing_source",
            message=f"ignored lock path: {subject}",
            subject=subject,
        )
    detailed = {**LOCK, "issues": [detailed_issue]}
    bare = {**LOCK, "issues": ["missing_source"]}
    assert semantic_lock_hash(detailed) == semantic_lock_hash(bare)


def test_lock_keeps_all_distinct_versions_and_unique_dependency_edges() -> None:
    changed = dict(LOCK)
    changed["packages"] = [
        *LOCK["packages"],
        {
            "name": "demo-pkg",
            "version": "1.1",
            "version_valid": True,
            "source_kind": "registry",
        },
    ]
    assert semantic_lock_hash(changed) != semantic_lock_hash(LOCK)

    duplicated_edge = dict(LOCK)
    parent = dict(LOCK["packages"][0])
    parent["dependencies"] = parent["dependencies"] * 2
    duplicated_edge["packages"] = [parent, LOCK["packages"][1]]
    assert semantic_lock_hash(duplicated_edge) == semantic_lock_hash(LOCK)


def test_lock_graph_uses_one_budget_for_packages_declarations_and_edges(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(hashers_module, "_MAX_LOCK_GRAPH_WORK", 5, raising=False)
    snapshot = {
        "format": "uv",
        "packages": [
            {
                "name": "parent",
                "version": "1",
                "version_valid": True,
                "source_kind": "registry",
                "dependencies": [
                    {"name": "child"},
                    {"name": "child"},
                ],
            },
            {
                "name": "child",
                "version": "1",
                "version_valid": True,
                "source_kind": "registry",
            },
        ],
        "issues": [],
    }

    with pytest.raises(HashingError) as raised:
        semantic_lock_hash(snapshot)

    assert raised.value.code == "lock_graph_budget_exceeded"
    assert str(raised.value) == "lock_graph_budget_exceeded"


def test_lock_dependency_budget_rejects_before_consuming_unneeded_items(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    consumed = 0

    def dependencies():
        nonlocal consumed
        for _ in range(20):
            consumed += 1
            yield {"name": "child"}

    monkeypatch.setattr(hashers_module, "_MAX_LOCK_GRAPH_WORK", 3, raising=False)
    snapshot = {
        "format": "uv",
        "packages": [
            {
                "name": "parent",
                "version": "1",
                "version_valid": True,
                "source_kind": "registry",
                "dependencies": dependencies(),
            },
            {
                "name": "child",
                "version": "1",
                "version_valid": True,
                "source_kind": "registry",
            },
        ],
        "issues": [],
    }

    with pytest.raises(HashingError, match="^lock_graph_budget_exceeded$"):
        semantic_lock_hash(snapshot)

    assert consumed == 1


def test_lock_dependency_resolution_uses_component_indexes() -> None:
    lock_edge_line_events = 0
    variant_count = 400
    dependencies = [
        {
            "name": "shared-child",
            "version": str(version),
            "source_kind": "registry",
        }
        for version in range(variant_count)
    ]
    packages = [
        {
            "name": "parent",
            "version": "1",
            "version_valid": True,
            "source_kind": "registry",
            "dependencies": dependencies,
        },
        *[
            {
                "name": "shared-child",
                "version": str(version),
                "version_valid": True,
                "source_kind": "registry",
            }
            for version in range(variant_count)
        ],
    ]

    def trace_lock_edges(frame: object, event: str, arg: object) -> object:
        del arg
        nonlocal lock_edge_line_events
        if (
            event == "line"
            and frame.f_code.co_name == "_lock_edges"  # type: ignore[attr-defined]
        ):
            lock_edge_line_events += 1
        return trace_lock_edges

    sys.settrace(trace_lock_edges)
    try:
        semantic_lock_hash({"format": "uv", "packages": packages, "issues": []})
    finally:
        sys.settrace(None)

    assert lock_edge_line_events < variant_count * 50


def test_lock_safe_source_identity_and_issue_codes_are_semantic() -> None:
    source_changed = dict(LOCK)
    helper = dict(LOCK["packages"][1])
    helper["source_identity"] = "def456"
    source_changed["packages"] = [LOCK["packages"][0], helper]
    assert semantic_lock_hash(source_changed) != semantic_lock_hash(LOCK)

    issue_changed = dict(LOCK)
    issue_changed["issues"] = [*LOCK["issues"], {"code": "new_issue"}]
    assert semantic_lock_hash(issue_changed) != semantic_lock_hash(LOCK)


def test_knowledge_content_hash_fixed_vector() -> None:
    assert knowledge_content_hash(
        ADVISORIES, {"Demo_Pkg"}
    ) == "5895a62a59f7ad83ccb2790e612d3b83ebe3ad62e454dc29c3a144d8ff4354d9"


def test_knowledge_filters_relevant_names_and_normalizes_content() -> None:
    baseline = knowledge_content_hash(ADVISORIES, ["demo-pkg"])
    changed_unrelated = {
        **ADVISORIES,
        "advisories": [
            ADVISORIES["advisories"][0],
            {**ADVISORIES["advisories"][1], "summary": "changed"},
        ],
    }
    lf_only = {
        **ADVISORIES,
        "advisories": [
            {**ADVISORIES["advisories"][0], "summary": "first line\nsecond line"},
            ADVISORIES["advisories"][1],
        ],
    }
    assert knowledge_content_hash(changed_unrelated, ["demo-pkg"]) == baseline
    assert knowledge_content_hash(lf_only, ["DEMO_pkg"]) == baseline
    assert knowledge_content_hash(changed_unrelated, ["unrelated"]) != baseline


def test_knowledge_skips_unrelated_private_invalid_advisories_before_validation() -> None:
    baseline = knowledge_content_hash(ADVISORIES, ["demo-pkg"])
    unrelated_private_invalid = {
        **ADVISORIES,
        "advisories": [
            ADVISORIES["advisories"][0],
            {
                "package_name": "unrelated",
                "source": r"C:\Users\alice\private-feed.json",
                "token": "private-token",
                "cvss_score": "not-a-number",
            },
        ],
    }

    assert knowledge_content_hash(
        unrelated_private_invalid, ["demo-pkg"]
    ) == baseline


def test_knowledge_content_changes_but_metadata_sync_does_not() -> None:
    baseline = knowledge_content_hash(ADVISORIES, ["demo-pkg"])
    metadata_changed = {
        **ADVISORIES,
        "metadata": {
            **ADVISORIES["metadata"],
            "last_sync_at": "2030-01-01T00:00:00Z",
            "last_sync_status": "failed",
            "last_sync_message": "different",
        },
    }
    content_changed = {
        **ADVISORIES,
        "advisories": [
            {**ADVISORIES["advisories"][0], "fixed_version": "2.1"},
            ADVISORIES["advisories"][1],
        ],
    }
    assert knowledge_content_hash(metadata_changed, ["demo-pkg"]) == baseline
    assert knowledge_content_hash(content_changed, ["demo-pkg"]) != baseline

    advisory_update_changed = {
        **ADVISORIES,
        "advisories": [
            {
                **ADVISORIES["advisories"][0],
                "updated_at": "2030-01-01T00:00:00Z",
            },
            ADVISORIES["advisories"][1],
        ],
    }
    assert knowledge_content_hash(advisory_update_changed, ["demo-pkg"]) == baseline


def test_knowledge_content_order_and_duplicates_are_stable() -> None:
    shuffled = {
        **ADVISORIES,
        "advisories": list(reversed(ADVISORIES["advisories"]))
        + [ADVISORIES["advisories"][0]],
    }
    assert knowledge_content_hash(
        shuffled, ["unrelated", "demo-pkg", "demo-pkg"]
    ) == knowledge_content_hash(ADVISORIES, ["demo-pkg", "unrelated"])


def test_knowledge_issue_multiset_hashes_only_safe_relevant_subjects() -> None:
    detailed = {
        **ADVISORIES,
        "issues": [
            AuditIssue(
                "invalid_cvss",
                "ignored C:\\private\\alice\\advisories.db",
                "Demo_Pkg",
            ),
            {"code": "invalid_cvss", "message": "ignored", "subject": "demo-pkg"},
            {
                "code": "invalid_severity",
                "message": "ignored",
                "subject": "unrelated",
            },
            {
                "code": "invalid_severity",
                "message": "ignored /home/alice/advisories.db",
                "subject": "/home/alice/advisories.db",
            },
        ],
    }
    reordered_and_redacted = {
        **ADVISORIES,
        "issues": [
            {"code": "invalid_severity", "subject": "/redacted/private.db"},
            {"code": "invalid_cvss", "subject": "demo-pkg"},
            {"code": "invalid_severity", "subject": "other-package"},
            {"code": "invalid_cvss", "subject": "DEMO.pkg"},
        ],
    }
    assert knowledge_content_hash(
        detailed, ["demo-pkg"]
    ) == knowledge_content_hash(reordered_and_redacted, ["demo-pkg"])

    one_issue = {**ADVISORIES, "issues": detailed["issues"][:1]}
    two_issues = {**ADVISORIES, "issues": detailed["issues"][:2]}
    assert knowledge_content_hash(one_issue, ["demo-pkg"]) != knowledge_content_hash(
        two_issues, ["demo-pkg"]
    )


def test_knowledge_issues_keep_global_and_related_but_skip_other_subjects() -> None:
    included = [
        {"code": "global_absent"},
        {"code": "global_none", "subject": None},
        {"code": "related", "subject": "Demo_Pkg"},
    ]
    snapshot = {
        **ADVISORIES,
        "issues": [
            *included,
            {"code": "not a valid code", "subject": "unrelated"},
            {
                "code": "not a valid code",
                "subject": "/home/alice/private/advisories.db",
            },
            {"code": "not a valid code", "subject": ""},
        ],
    }
    expected = {**ADVISORIES, "issues": included}

    assert knowledge_content_hash(snapshot, ["demo-pkg"]) == knowledge_content_hash(
        expected, ["demo-pkg"]
    )


def test_knowledge_content_hash_fixed_negative_issue_vector() -> None:
    snapshot = {
        **ADVISORIES,
        "issues": [
            AuditIssue("invalid_cvss", "ignored", "Demo_Pkg"),
            {"code": "global_issue"},
            {"code": "ignored_issue", "subject": "unrelated"},
            {
                "code": "ignored_issue",
                "subject": "/home/alice/private.db",
            },
        ],
    }
    assert knowledge_content_hash(
        snapshot, ["demo-pkg"]
    ) == "5354a86f994d385aca6c358e4788b93597f13d134fd5db76348cb7e6cf55fd1a"


def test_knowledge_metadata_hash_fixed_vector() -> None:
    updates = [
        {"advisory_id": "GHSA-2345-6789-cfgh", "updated_at": "2026-09-22T10:00:00Z"}
    ]
    assert knowledge_metadata_hash(
        METADATA, updates
    ) == "8b8ee711ed778e008e047121dc08de046084de1d75bb3875f2a06f4e97a1ba0d"


def test_metadata_sync_and_advisory_update_ordering() -> None:
    updates = [
        {"advisory_id": "OSV-b", "updated_at": "2026-09-22T11:00:00Z"},
        {"advisory_id": "OSV-a", "updated_at": "2026-09-22T10:00:00Z"},
    ]
    baseline = knowledge_metadata_hash(METADATA, updates)
    assert knowledge_metadata_hash(METADATA, [updates[1], updates[0], updates[0]]) == baseline
    assert knowledge_metadata_hash(
        {**METADATA, "last_sync_at": "2026-09-24T12:00:00Z"}, updates
    ) != baseline


def test_metadata_accepts_full_advisories_as_update_records() -> None:
    full_record = ADVISORIES["advisories"][0]
    lean_record = {
        "advisory_id": full_record["ghsa_id"],
        "updated_at": full_record["updated_at"],
    }
    assert knowledge_metadata_hash(METADATA, [full_record]) == knowledge_metadata_hash(
        METADATA, [lean_record]
    )


def test_evaluation_context_hash_fixed_vector_and_groups() -> None:
    assert evaluation_context_hash(
        "healthy"
    ) == "308676d255cad26017c51479ee18eb16568194f1837d32a4f1104838de4bf92c"
    assert evaluation_context_hash({"group": " HEALTHY "}) == evaluation_context_hash("healthy")
    assert evaluation_context_hash("stale") != evaluation_context_hash("healthy")
    assert evaluation_context_hash("future_skew") != evaluation_context_hash("stale")
    groups = [
        "healthy",
        "stale",
        "future_skew",
        "invalid_sync_time",
        "sync_failed",
        "sync_failed_stale",
        "sync_failed_future_skew",
        "sync_failed_invalid_sync_time",
    ]
    assert len({evaluation_context_hash(group) for group in groups}) == len(groups)


@pytest.mark.parametrize(
    "state",
    ["ok", "unknown", {"group": "healthy", "checked_at": "2026-09-24T00:00:00Z"}],
)
def test_evaluation_context_rejects_unstable_or_raw_state(state: object) -> None:
    with pytest.raises(HashingError, match="^(invalid_health_state|forbidden_timestamp)$"):
        evaluation_context_hash(state)


def test_policy_hash_fixed_vector_and_semantic_changes() -> None:
    assert policy_hash(
        POLICY
    ) == "ec27b58065644e9d1028747f0cd7eb128a736328adbbf0950fa1b5ffdd7ee4f7"
    changed = {**POLICY, "freshness_threshold": {"days": 8}}
    assert policy_hash(changed) != policy_hash(POLICY)
    reordered = {
        "freshness_threshold": {"days": 7},
        "detail_limits": {"issues": 1000, "findings": 500},
        "withdrawn_handling": "exclude",
        "version_handling": "all_distinct_versions",
        "marker_handling": "ignored",
    }
    assert policy_hash(reordered) == policy_hash(POLICY)


def test_composite_hash_fixed_vector_and_environment_lock_rule() -> None:
    hashes = _component_hashes()
    assert composite_hash(
        audit_kind="project",
        environment=hashes["environment"],
        lock=hashes["lock"],
        knowledge=hashes["knowledge"],
        context=hashes["context"],
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    ) == "640d7ab5bc70581d930526d9f0e2d840fae0faae597a688276ee2633eecdc77d"

    with pytest.raises(HashingError, match="^unexpected_lock_hash$"):
        composite_hash(
            audit_kind="environment",
            environment=hashes["environment"],
            lock=hashes["lock"],
            knowledge=hashes["knowledge"],
            context=hashes["context"],
            policy=hashes["policy"],
            contract="dependency-audit-v1",
        )


def test_composite_changes_with_components_and_excludes_knowledge_metadata() -> None:
    hashes = _component_hashes()
    baseline = composite_hash(
        audit_kind="environment",
        environment=hashes["environment"],
        lock=None,
        knowledge=hashes["knowledge"],
        context=hashes["context"],
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    )
    metadata_one = knowledge_metadata_hash(METADATA)
    metadata_two = knowledge_metadata_hash(
        {**METADATA, "last_sync_at": "2026-09-24T00:00:00Z"}
    )
    assert metadata_one != metadata_two
    assert baseline == composite_hash(
        audit_kind="environment",
        environment=hashes["environment"],
        lock=None,
        knowledge=hashes["knowledge"],
        context=hashes["context"],
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    )
    assert baseline != composite_hash(
        audit_kind="environment",
        environment=hashes["environment"],
        lock=None,
        knowledge=hashes["knowledge"],
        context=evaluation_context_hash("stale"),
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    )


def test_environment_composite_may_omit_optional_lock() -> None:
    hashes = _component_hashes()
    omitted = composite_hash(
        audit_kind="python_environment",
        environment=hashes["environment"],
        knowledge=hashes["knowledge"],
        context=hashes["context"],
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    )
    explicit = composite_hash(
        audit_kind="python_environment",
        environment=hashes["environment"],
        lock=None,
        knowledge=hashes["knowledge"],
        context=hashes["context"],
        policy=hashes["policy"],
        contract="dependency-audit-v1",
    )
    assert omitted == explicit


@pytest.mark.parametrize("audit_kind", ["project", "python_project"])
def test_project_composite_requires_valid_lock_digest(audit_kind: str) -> None:
    hashes = _component_hashes()
    for lock in (None, "not-a-digest"):
        with pytest.raises(
            HashingError,
            match="^(missing_lock_hash|invalid_component_hash)$",
        ):
            composite_hash(
                audit_kind=audit_kind,
                environment=hashes["environment"],
                lock=lock,
                knowledge=hashes["knowledge"],
                context=hashes["context"],
                policy=hashes["policy"],
                contract="dependency-audit-v1",
            )


@pytest.mark.parametrize("audit_kind", ["other", "projectish", ""])
def test_composite_rejects_unknown_audit_kinds(audit_kind: str) -> None:
    hashes = _component_hashes()
    with pytest.raises(HashingError, match="^invalid_audit_kind$"):
        composite_hash(
            audit_kind=audit_kind,
            environment=hashes["environment"],
            lock=hashes["lock"],
            knowledge=hashes["knowledge"],
            context=hashes["context"],
            policy=hashes["policy"],
            contract="dependency-audit-v1",
        )


@pytest.mark.parametrize(
    ("call", "expected_code"),
    [
        (lambda: policy_hash({**POLICY, "token": "top-secret-token"}), "forbidden_sensitive_field"),
        (lambda: policy_hash({**POLICY, "api_key": "private"}), "forbidden_sensitive_field"),
        (
            lambda: policy_hash({**POLICY, "authorization": "Bearer private"}),
            "forbidden_sensitive_field",
        ),
        (
            lambda: policy_hash(
                {**POLICY, "output_path": "C:\\Users\\alice\\report.json"}
            ),
            "forbidden_path",
        ),
        (lambda: policy_hash({**POLICY, "username": "alice"}), "forbidden_sensitive_field"),
        (
            lambda: policy_hash(
                {**POLICY, "evaluated_at": "2026-09-24T00:00:00Z"}
            ),
            "forbidden_timestamp",
        ),
        (
            lambda: semantic_lock_hash(
                {
                    **LOCK,
                    "packages": [
                        *LOCK["packages"],
                        {
                            "name": "local",
                            "version": "1",
                            "version_valid": True,
                            "source_kind": "path",
                            "source_identity": "C:\\Users\\alice\\private-package",
                        },
                    ],
                }
            ),
            "unsafe_source_identity",
        ),
        (
            lambda: environment_hash(
                "cpython",
                (3, 11, 9),
                [
                    {
                        "normalized_name": "demo",
                        "version": "1",
                        "version_valid": True,
                        "source_kind": "registry",
                        "metadata_path": "C:\\Users\\alice\\demo.dist-info",
                    }
                ],
            ),
            "forbidden_path_field",
        ),
    ],
)
def test_privacy_sensitive_fields_are_rejected_without_value_leakage(
    call: object, expected_code: str
) -> None:
    with pytest.raises(HashingError) as raised:
        call()  # type: ignore[operator]
    assert raised.value.code == expected_code
    message = str(raised.value)
    assert message == expected_code
    assert "alice" not in message
    assert "secret" not in message
    assert "2026" not in message


def test_legitimate_advisory_urls_and_package_names_are_not_overrejected() -> None:
    snapshot = {
        "advisories": [
            {
                **ADVISORIES["advisories"][0],
                "package_name": "user-token-helper",
                "normalized_package_name": "user-token-helper",
                "source": "https://example.test/users/security/advisory",
            }
        ]
    }
    digest = knowledge_content_hash(snapshot, ["user-token-helper"])
    assert len(digest) == 64
    assert digest == digest.lower()


@pytest.mark.parametrize(
    ("source", "expected_code"),
    [
        ("file:///C:/Users/alice/advisories.db", "invalid_public_url"),
        ("data:text/plain,secret", "invalid_public_url"),
        ("ftp://example.test/feed", "invalid_public_url"),
        ("https://example.test/feed?accessToken=x", "forbidden_sensitive_field"),
        ("https://example.test/feed?SIG=x", "forbidden_sensitive_field"),
        ("https://example.test/feed?id=public", "invalid_public_url"),
        ("https://example.test/feed#latest", "invalid_public_url"),
        ("https://alice:password@example.test/advisory", "forbidden_sensitive_field"),
    ],
)
def test_advisory_and_sync_sources_reject_unsafe_urls(
    source: str, expected_code: str
) -> None:
    unsafe_advisory = {
        "advisories": [
            {
                **ADVISORIES["advisories"][0],
                "source": source,
            }
        ]
    }
    with pytest.raises(HashingError, match=f"^{expected_code}$"):
        knowledge_content_hash(unsafe_advisory, ["demo-pkg"])

    with pytest.raises(HashingError, match=f"^{expected_code}$"):
        knowledge_metadata_hash(
            {**METADATA, "sources": [source]}
        )


@pytest.mark.parametrize(
    "source",
    [
        "git+https://github.com/example/demo.git",
        "git+ssh://github.com/example/demo.git",
        "ssh://github.com/example/demo.git",
    ],
)
def test_git_source_identity_allows_only_explicit_git_schemes(source: str) -> None:
    package = HashPackage("demo", "1", True, "git", source_identity=source)
    assert package.source_identity == source
    with pytest.raises(HashingError, match="^invalid_source_identity$"):
        HashPackage("demo", "1", True, "registry", source_identity=source)


def test_registry_source_url_from_uv_lock_can_be_hashed() -> None:
    snapshot = {
        "lock_format": "uv", "packages": [{
            "name": "demo", "version": "1.0", "version_valid": True,
            "source_kind": "registry", "source_identity": "https://pypi.org/simple",
        }], "issues": [],
    }
    assert len(semantic_lock_hash(snapshot)) == 64
    assert HashPackage("demo", "1.0", True, "registry",
                       source_identity="https://pypi.org/simple").source_identity == "https://pypi.org/simple"


@pytest.mark.parametrize(
    "source",
    [
        "artifact-1.2+build_3",
        "A_b.c-d",
        "sha256:" + "a" * 64,
    ],
)
def test_scheme_less_source_identity_allows_only_opaque_artifact_ids(
    source: str,
) -> None:
    package = HashPackage("demo", "1", True, "registry", source_identity=source)
    assert package.source_identity == source


@pytest.mark.parametrize(
    ("source", "expected_code"),
    [
        ("file:///home/alice/demo", "invalid_source_identity"),
        ("../private/demo", "unsafe_source_identity"),
        (r"C:private\demo", "unsafe_source_identity"),
        ("https://example.test/repo?sig=x", "forbidden_sensitive_field"),
        ("https://example.test/repo#main", "invalid_source_identity"),
        ("ssh://git@example.test/repo", "forbidden_sensitive_field"),
        ("git@example.test:repo", "invalid_source_identity"),
        ("user@example.test", "invalid_source_identity"),
        ("folder/name", "invalid_source_identity"),
        (r"folder\name", "invalid_source_identity"),
        ("unapproved:digest", "invalid_source_identity"),
        ("name=value", "invalid_source_identity"),
        ("two words", "invalid_source_identity"),
        ("token-secret", "invalid_source_identity"),
        ("username-alice", "invalid_source_identity"),
        ("a" * 257, "invalid_source_identity"),
    ],
)
def test_source_identity_rejects_local_or_credential_bearing_values(
    source: str, expected_code: str
) -> None:
    with pytest.raises(HashingError, match=f"^{expected_code}$"):
        HashPackage("demo", "1", True, "git", source_identity=source)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("ghsa_id", "GHSA-aaaa-bbbb-cccc"),
        ("ghsa_id", "GHSA-2345-6789"),
        ("ghsa_id", "GHSA-234-6789-cfgh"),
        ("ghsa_id", "GHSA-2345-67890-cfgh"),
        ("ghsa_id", "GHSA-2345-6789-cfg雪"),
        ("cve_id", "CVE-26-0001"),
        ("cve_id", "CVE-2026-001"),
        ("cve_id", "CVE-２０２６-0001"),
        ("advisory_id", "ß"),
        ("advisory_id", "bad id"),
    ],
)
def test_advisory_ids_require_conservative_ascii_syntax(
    field: str, value: str
) -> None:
    advisory = {**ADVISORIES["advisories"][0], field: value}
    with pytest.raises(HashingError, match="^invalid_advisory_id$"):
        knowledge_content_hash({"advisories": [advisory]}, ["demo-pkg"])


def test_generic_advisory_id_does_not_unicode_collide_after_uppercase() -> None:
    valid = {
        **ADVISORIES["advisories"][0],
        "advisory_id": "SS",
    }
    invalid = {**valid, "advisory_id": "ß"}
    valid_hash = knowledge_content_hash({"advisories": [valid]}, ["demo-pkg"])
    with pytest.raises(HashingError, match="^invalid_advisory_id$"):
        knowledge_content_hash({"advisories": [invalid]}, ["demo-pkg"])
    assert len(valid_hash) == 64


def test_randomized_permutations_are_stable() -> None:
    rng = random.Random(20260924)
    expected_environment = environment_hash(
        "cpython", (3, 11, 9), PACKAGES, ("b", "a")
    )
    expected_lock = semantic_lock_hash(LOCK)
    expected_knowledge = knowledge_content_hash(ADVISORIES, ["demo-pkg", "unrelated"])
    for _ in range(25):
        packages = list(PACKAGES)
        issues = ["a", "b"]
        lock_packages = list(LOCK["packages"])
        lock_issues = list(LOCK["issues"])
        advisories = list(ADVISORIES["advisories"])
        relevant = ["demo-pkg", "unrelated"]
        for values in (packages, issues, lock_packages, lock_issues, advisories, relevant):
            rng.shuffle(values)
        assert environment_hash("cpython", (3, 11, 9), packages, issues) == expected_environment
        assert semantic_lock_hash(
            {**LOCK, "packages": lock_packages, "issues": lock_issues}
        ) == expected_lock
        assert knowledge_content_hash(
            {**ADVISORIES, "advisories": advisories}, relevant
        ) == expected_knowledge


def _component_hashes() -> dict[str, str]:
    return {
        "environment": environment_hash("cpython", (3, 11, 9), PACKAGES),
        "lock": semantic_lock_hash(LOCK),
        "knowledge": knowledge_content_hash(ADVISORIES, ["demo-pkg"]),
        "context": evaluation_context_hash("healthy"),
        "policy": policy_hash(POLICY),
    }
