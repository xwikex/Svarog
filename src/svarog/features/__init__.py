"""Trusted, package-local feature extension contracts."""

from .contracts import FeatureContext, FeatureField, FeatureManifest
from .registry import FeatureRegistry

__all__ = ["FeatureContext", "FeatureField", "FeatureManifest", "FeatureRegistry"]
