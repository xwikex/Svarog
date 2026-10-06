from __future__ import annotations

from pathlib import Path
from types import MappingProxyType

import pytest

from svarog.features.contracts import FeatureField, FeatureManifest
from svarog.features.runtime import (
    FeatureInputError,
    FeatureResultError,
    present_feature_result,
    validate_feature_input,
)


def _manifest(fields: tuple[FeatureField, ...]) -> FeatureManifest:
    return FeatureManifest(
        feature_id="demo", title="演示功能", description="只读演示", order=1,
        fields=fields, permissions=frozenset({"workspace_read"}),
    )


def test_input_validation_converts_only_declared_values(tmp_path: Path) -> None:
    target = tmp_path / "input.txt"
    target.write_text("data", encoding="utf-8")
    manifest = _manifest((
        FeatureField("target", "文件", "workspace_file", True, "工作区文件"),
        FeatureField("limit", "上限", "integer", True, "1..20", minimum=1, maximum=20),
        FeatureField("enabled", "启用", "boolean", False, "是否启用"),
        FeatureField("mode", "模式", "choice", True, "选择模式", choices=("safe", "strict")),
    ))

    values = validate_feature_input(
        manifest,
        {"target": "input.txt", "limit": 5, "enabled": False, "mode": "safe"},
        tmp_path,
    )

    assert values == {"target": target.resolve(), "limit": 5, "enabled": False, "mode": "safe"}


@pytest.mark.parametrize("payload,field", [
    ({"name": "ok", "extra": "no"}, "extra"),
    ({"name": ""}, "name"),
    ({"name": "ok", "count": True}, "count"),
    ({"name": "ok", "count": 11}, "count"),
])
def test_input_validation_rejects_unknown_missing_and_wrong_types(
    tmp_path: Path, payload: dict, field: str,
) -> None:
    manifest = _manifest((
        FeatureField("name", "名称", "text", True, "名称"),
        FeatureField("count", "数量", "integer", False, "0..10", minimum=0, maximum=10),
    ))
    with pytest.raises(FeatureInputError) as error:
        validate_feature_input(manifest, payload, tmp_path)
    assert field in error.value.fields


def test_workspace_input_cannot_escape(tmp_path: Path) -> None:
    manifest = _manifest((FeatureField(
        "target", "文件", "workspace_file", True, "工作区文件"
    ),))
    with pytest.raises(FeatureInputError) as error:
        validate_feature_input(manifest, {"target": "../outside.txt"}, tmp_path)
    assert error.value.fields == {"target": "请选择工作区内已存在的文件。"}


def test_result_is_converted_to_fixed_read_only_presentation() -> None:
    result = {
        "status": "completed",
        "summary": [{"key": "items", "label": "项目", "value": 1}],
        "warnings": ["需要人工确认"],
        "tables": [{
            "id": "results", "title": "结果",
            "columns": [{"key": "name", "label": "名称", "type": "text"}],
            "rows": [{"name": "demo"}],
        }],
        "actions_executed": False,
    }

    presented = present_feature_result(_manifest(()), result)

    assert presented == {
        "schema": "svarog.workbench.feature-result.v1",
        "kind": "trusted_feature", "feature_id": "demo", "title": "演示功能",
        "status": "completed", "summary_cards": result["summary"],
        "warnings": result["warnings"], "tables": result["tables"],
        "actions_executed": False,
    }


def test_result_accepts_the_declared_mapping_contract() -> None:
    result = MappingProxyType({
        "status": "completed", "summary": [], "warnings": [], "tables": [],
        "actions_executed": False,
    })
    assert present_feature_result(_manifest(()), result)["status"] == "completed"


@pytest.mark.parametrize("mutation", [
    {"actions_executed": True},
    {"status": "approved"},
    {"summary": [{"key": "x", "label": "X", "value": 1},
                 {"key": "x", "label": "Y", "value": 2}]},
    {"tables": [{"id": "x", "title": "X", "columns": [
        {"key": "url", "label": "URL", "type": "attack_link"}], "rows": [{"url": "x"}]}]},
])
def test_result_rejects_actions_unknown_status_duplicates_and_active_columns(mutation: dict) -> None:
    result = {
        "status": "completed", "summary": [], "warnings": [], "tables": [],
        "actions_executed": False,
    }
    result.update(mutation)
    with pytest.raises(FeatureResultError):
        present_feature_result(_manifest(()), result)


def test_result_rejects_oversized_payload() -> None:
    result = {
        "status": "completed", "summary": [], "warnings": [],
        "tables": [{"id": "large", "title": "Large", "columns": [
            {"key": "value", "label": "Value", "type": "text"}],
            "rows": [{"value": "x" * 9000} for _ in range(300)]}],
        "actions_executed": False,
    }
    with pytest.raises(FeatureResultError, match="过大"):
        present_feature_result(_manifest(()), result)
