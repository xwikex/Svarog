"""Conservative graph resolution never invents an ambiguous edge."""

from svarog.project_audit.models import LockedDependency, LockedPackage
from svarog.sbom.dependency_graph import build_dependency_graph, component_ref


def pkg(name, version="1.0", *, source="registry", revision=None, dependencies=()):
    return LockedPackage(name, name, version, True, source, revision, dependencies)


def dep(name, version=None, source=None):
    return LockedDependency(name, name, version, source)


def test_exact_and_unique_constraint_resolve_but_ambiguous_missing_and_source_conflict_do_not():
    parent = pkg("parent", dependencies=(
        dep("exact", "2.0"), dep("unique"), dep("ambiguous"), dep("missing"),
        dep("git-child", source="registry"),
    ))
    children = (
        pkg("exact", "1.0"), pkg("exact", "2.0"), pkg("unique"),
        pkg("ambiguous", "1.0"), pkg("ambiguous", "2.0"),
        pkg("git-child", source="git", revision="a" * 40),
    )
    graph = build_dependency_graph((parent, *children))
    assert (component_ref(parent), component_ref(children[1])) in graph.edges
    assert (component_ref(parent), component_ref(children[2])) in graph.edges
    assert len(graph.edges) == 2
    assert {item.reason for item in graph.unresolved} == {
        "ambiguous_child", "missing_child", "source_conflict"
    }
    assert component_ref(children[0]) in graph.known_leaves
    assert graph.completeness == "incomplete"


def test_cycles_are_preserved_without_recursion_and_unknown_root_is_not_connected_to_every_package():
    a = pkg("a", dependencies=(dep("b"),))
    b = pkg("b", dependencies=(dep("a"),))
    graph = build_dependency_graph((a, b))
    assert set(graph.edges) == {(component_ref(a), component_ref(b)), (component_ref(b), component_ref(a))}
    assert graph.root_edges == ()
    assert graph.root_completeness == "unknown"


def test_safe_component_refs_are_reproducible_and_merge_undistinguishable_sources():
    assert component_ref(pkg("demo")) == "pkg:pypi/demo@1.0"
    left = pkg("private", source="path", revision="relative/one")
    right = pkg("private", source="path", revision="relative/two")
    assert component_ref(left) == component_ref(right)
    graph = build_dependency_graph((left, right))
    assert graph.component_count == 1
    assert "merged_undistinguishable_components" in graph.warnings


def test_pep440_constraint_resolves_only_unique_candidate():
    parent = pkg("parent", dependencies=(dep("child", ">=2,<3"),))
    old = pkg("child", "1.0")
    target = pkg("child", "2.1")
    graph = build_dependency_graph((parent, old, target))
    assert graph.edges == ((component_ref(parent), component_ref(target)),)
    assert graph.unresolved == ()


def test_unknown_constraint_does_not_invent_a_relationship():
    parent = pkg("parent", dependencies=(dep("child", "^2.0"),))
    child = pkg("child", "2.1")
    graph = build_dependency_graph((parent, child))
    assert graph.edges == ()
    assert graph.unresolved[0].reason == "unknown_constraint"


def test_merged_sources_with_different_declarations_do_not_gain_false_edges():
    first = pkg("private", source="path", revision="one", dependencies=(dep("child"),))
    second = pkg("private", source="path", revision="two")
    child = pkg("child")
    graph = build_dependency_graph((first, second, child))
    assert graph.edges == ()
    assert graph.unresolved[0].reason == "merged_source_conflict"
    assert component_ref(first) not in graph.known_leaves


def test_parser_gaps_do_not_masquerade_as_known_leaves():
    child = pkg("child")
    graph = build_dependency_graph((child,), unknown_relationships=True)
    assert graph.known_leaves == ()
    assert graph.unresolved[0].reason == "unknown_relationships"


def test_unknown_source_kind_has_safe_fallback_reference():
    unknown = pkg("source-less", source="unknown")
    assert component_ref(unknown).startswith("urn:svarog:component:sha256:")
