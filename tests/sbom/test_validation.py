"""Official schema bytes are pinned and usable with all network access disabled."""

from __future__ import annotations

import hashlib
from importlib.resources import files
import json
from pathlib import Path
import socket
from urllib.parse import urldefrag, urljoin
import urllib.request

from jsonschema import Draft7Validator
from referencing import Registry, Resource


NAMES = (
    "bom-1.7.schema.json",
    "cryptography-defs.schema.json",
    "jsf-0.82.schema.json",
    "spdx.schema.json",
)
BASE = "http://cyclonedx.org/schema/"
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures" / "cyclonedx" / "1.7"
RUNTIME = files("svarog.sbom.schemas.cyclonedx").joinpath("1.7")


def _manifest(data: bytes) -> dict[str, str]:
    lines = data.decode("ascii").splitlines()
    parsed = [line.split("  ", 1) for line in lines]
    assert [name for _, name in parsed] == sorted(NAMES)
    assert all(len(digest) == 64 for digest, _ in parsed)
    return {name: digest for digest, name in parsed}


def _references(node: object):
    if isinstance(node, dict):
        if "$ref" in node:
            yield node["$ref"]
        for child in node.values():
            yield from _references(child)
    elif isinstance(node, list):
        for child in node:
            yield from _references(child)


def test_manifest_independently_hashes_runtime_and_fixture_files():
    runtime_manifest = _manifest(RUNTIME.joinpath("SHA256SUMS").read_bytes())
    fixture_manifest = _manifest((FIXTURES / "SHA256SUMS").read_bytes())
    assert runtime_manifest == fixture_manifest
    for name in NAMES:
        runtime = RUNTIME.joinpath(name).read_bytes()
        fixture = (FIXTURES / name).read_bytes()
        assert runtime == fixture
        assert hashlib.sha256(runtime).hexdigest() == runtime_manifest[name]


def test_offline_schema_resolution_and_validation(monkeypatch):
    def no_network(*args, **kwargs):
        raise AssertionError("schema validation must not use the network")

    monkeypatch.setattr(socket.socket, "connect", no_network)
    monkeypatch.setattr(urllib.request, "urlopen", no_network)
    schemas = {name: json.loads(RUNTIME.joinpath(name).read_bytes()) for name in NAMES}
    registry = Registry().with_resources(
        (BASE + name, Resource.from_contents(schema)) for name, schema in schemas.items()
    )
    for name, schema in schemas.items():
        Draft7Validator.check_schema(schema)
        for ref in _references(schema):
            uri, _ = urldefrag(urljoin(BASE + name, ref))
            assert uri in {BASE + item for item in NAMES}

    validator = Draft7Validator(schemas["bom-1.7.schema.json"], registry=registry)
    assert validator.is_valid({"bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1})
    assert not validator.is_valid({"bomFormat": "not-CycloneDX", "specVersion": "1.7", "version": 1})
