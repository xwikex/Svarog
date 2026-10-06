"""Deterministic discovery of source-controlled Svarog feature packages."""

from __future__ import annotations

import importlib
import pkgutil
from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType

from .contracts import FeatureHandler, FeatureManifest


def _is_link_like(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", lambda: False)
    return path.is_symlink() or is_junction()


def _package_path_is_safe(package_paths: object, name: str) -> bool:
    for root_value in package_paths:
        root = Path(root_value)
        if not root.is_dir():
            continue
        candidate = root / name
        if not candidate.exists():
            continue
        try:
            if _is_link_like(root) or _is_link_like(candidate):
                return False
            canonical_root = root.resolve(strict=True)
            candidate.resolve(strict=True).relative_to(canonical_root)
            for child in candidate.rglob("*"):
                if _is_link_like(child):
                    return False
                child.resolve(strict=True).relative_to(canonical_root)
        except (OSError, RuntimeError, ValueError):
            return False
    return True


@dataclass(frozen=True, slots=True)
class RegisteredFeature:
    manifest: FeatureManifest
    handler: FeatureHandler

    @property
    def feature_id(self) -> str:
        return self.manifest.feature_id


class FeatureRegistry:
    def __init__(
        self,
        features: tuple[RegisteredFeature, ...],
        errors: tuple[dict[str, str], ...] = (),
    ) -> None:
        self._features = features
        self._errors = tuple(dict(item) for item in errors)
        self._by_id = {item.feature_id: item for item in features}

    @property
    def features(self) -> tuple[RegisteredFeature, ...]:
        return self._features

    @property
    def errors(self) -> tuple[dict[str, str], ...]:
        return tuple(dict(item) for item in self._errors)

    def get(self, feature_id: str) -> RegisteredFeature | None:
        return self._by_id.get(feature_id)

    @classmethod
    def from_entries(
        cls, entries: Iterable[tuple[FeatureManifest, FeatureHandler]]
    ) -> FeatureRegistry:
        loaded = [RegisteredFeature(manifest, handler) for manifest, handler in entries]
        if any(type(item.manifest) is not FeatureManifest or not callable(item.handler)
               for item in loaded):
            raise ValueError("功能条目无效")
        counts = Counter(item.feature_id for item in loaded)
        if any(value > 1 for value in counts.values()):
            raise ValueError("功能 ID 重复")
        loaded.sort(key=lambda item: (item.manifest.order, item.feature_id))
        return cls(tuple(loaded))

    @classmethod
    def discover(
        cls,
        *,
        package: ModuleType | None = None,
        importer: Callable[[str], object] = importlib.import_module,
        iterator: Callable[[object], Iterable[object]] = pkgutil.iter_modules,
    ) -> FeatureRegistry:
        if package is None:
            package = importlib.import_module("svarog.features")
        package_paths = getattr(package, "__path__", None)
        if package_paths is None:
            raise ValueError("功能根包不可枚举")
        package_name = package.__name__
        loaded: list[tuple[str, RegisteredFeature]] = []
        errors: list[dict[str, str]] = []
        for entry in sorted(iterator(package_paths), key=lambda item: item.name):
            if not entry.ispkg or not entry.name.isidentifier() or entry.name.startswith("_"):
                continue
            if not _package_path_is_safe(package_paths, entry.name):
                errors.append({"package": entry.name, "code": "feature_path_rejected"})
                continue
            module_name = f"{package_name}.{entry.name}"
            try:
                manifest_module = importer(f"{module_name}.manifest")
                handler_module = importer(f"{module_name}.handler")
                manifest = getattr(manifest_module, "FEATURE_MANIFEST")
                handler = getattr(handler_module, "run_feature")
                if type(manifest) is not FeatureManifest or not callable(handler):
                    raise ValueError("invalid exports")
                loaded.append((entry.name, RegisteredFeature(manifest, handler)))
            except Exception:
                errors.append({"package": entry.name, "code": "feature_load_failed"})

        counts = Counter(item.feature_id for _package, item in loaded)
        duplicate_ids = {name for name, count in counts.items() if count > 1}
        valid: list[RegisteredFeature] = []
        for package_name, item in loaded:
            if item.feature_id in duplicate_ids:
                errors.append({"package": package_name, "code": "duplicate_feature_id"})
            else:
                valid.append(item)
        valid.sort(key=lambda item: (item.manifest.order, item.feature_id))
        errors.sort(key=lambda item: item["package"])
        return cls(tuple(valid), tuple(errors))

    def catalog(self) -> dict[str, object]:
        return {
            "schema": "svarog.workbench.features.v1",
            "features": [
                {
                    "feature_id": item.feature_id,
                    "title": item.manifest.title,
                    "description": item.manifest.description,
                    "order": item.manifest.order,
                    "permissions": sorted(item.manifest.permissions),
                    "fields": [
                        {
                            "name": field.name,
                            "label": field.label,
                            "kind": field.kind,
                            "required": field.required,
                            "help_text": field.help_text,
                            "choices": list(field.choices),
                            "minimum": field.minimum,
                            "maximum": field.maximum,
                        }
                        for field in item.manifest.fields
                    ],
                }
                for item in self._features
            ],
            "disabled": [dict(item) for item in self._errors],
        }


__all__ = ["FeatureRegistry", "RegisteredFeature"]
