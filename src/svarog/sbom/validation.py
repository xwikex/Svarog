"""Offline CycloneDX validation and conservative privacy/reference checks."""

from __future__ import annotations

from functools import lru_cache
import hashlib
from importlib.resources import files
import json
import re
from urllib.parse import urlsplit

from jsonschema import Draft7Validator
from referencing import Registry, Resource


_SCHEMA_NAMES = (
    "bom-1.7.schema.json", "cryptography-defs.schema.json",
    "jsf-0.82.schema.json", "spdx.schema.json",
)
_BASE = "http://cyclonedx.org/schema/"
MAX_SBOM_BYTES = 16 * 1024 * 1024
MAX_COMPONENTS = 50_000
MAX_EDGES = 100_000
_DRIVE = re.compile(r"[A-Za-z]:[\\/]")


@lru_cache(maxsize=1)
def _validator() -> Draft7Validator:
    directory = files("svarog.sbom.schemas.cyclonedx").joinpath("1.7")
    manifest = directory.joinpath("SHA256SUMS").read_text(encoding="ascii").splitlines()
    expected = {}
    for line in manifest:
        digest, name = line.split("  ", 1)
        if name in expected or name not in _SCHEMA_NAMES:
            raise ValueError("invalid_sbom_schema_manifest")
        expected[name] = digest
    if set(expected) != set(_SCHEMA_NAMES):
        raise ValueError("invalid_sbom_schema_manifest")
    schemas = {}
    for name in _SCHEMA_NAMES:
        payload = directory.joinpath(name).read_bytes()
        if hashlib.sha256(payload).hexdigest() != expected[name]:
            raise ValueError("sbom_schema_checksum_mismatch")
        schemas[name] = json.loads(payload)
    registry = Registry().with_resources(
        (_BASE + name, Resource.from_contents(schema)) for name, schema in schemas.items()
    )
    return Draft7Validator(schemas["bom-1.7.schema.json"], registry=registry)


def _walk_strings(node: object):
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _walk_strings(value)
    elif isinstance(node, list):
        for item in node:
            yield from _walk_strings(item)
    elif isinstance(node, str):
        yield node


def validate_sbom(payload: bytes) -> None:
    """Validate schema, local references, size, and obvious sensitive strings."""

    if type(payload) is not bytes or len(payload) > MAX_SBOM_BYTES:
        raise ValueError("sbom_too_large")
    try:
        bom = json.loads(payload, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, ValueError, TypeError):
        raise ValueError("invalid_sbom_json") from None
    if not isinstance(bom, dict) or not _validator().is_valid(bom):
        raise ValueError("invalid_cyclonedx_schema")
    components = bom.get("components", [])
    dependencies = bom.get("dependencies", [])
    if len(components) > MAX_COMPONENTS or sum(len(item.get("dependsOn", [])) for item in dependencies) > MAX_EDGES:
        raise ValueError("sbom_too_large")
    root = bom.get("metadata", {}).get("component", {}).get("bom-ref")
    refs = [root, *(component.get("bom-ref") for component in components)]
    if any(not isinstance(ref, str) or not ref for ref in refs) or len(refs) != len(set(refs)):
        raise ValueError("invalid_sbom_reference")
    known = set(refs)
    dependency_refs = [item["ref"] for item in dependencies]
    if len(dependency_refs) != len(set(dependency_refs)):
        raise ValueError("duplicate_sbom_dependency")
    for item in dependencies:
        if item["ref"] not in known or any(ref not in known for ref in item.get("dependsOn", ())):
            raise ValueError("invalid_sbom_reference")
    for composition in bom.get("compositions", ()):
        if any(ref not in known for ref in composition.get("dependencies", ())):
            raise ValueError("invalid_sbom_reference")
    for value in _walk_strings(bom):
        if any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value):
            raise ValueError("unsafe_sbom_content")
        if value.startswith(("/", "\\")) or _DRIVE.match(value):
            raise ValueError("unsafe_sbom_content")
        if "://" in value:
            parts = urlsplit(value)
            if parts.username is not None or parts.password is not None:
                raise ValueError("unsafe_sbom_content")
