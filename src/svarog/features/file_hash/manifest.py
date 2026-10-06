"""Declarative workbench metadata for the file hash feature."""

from svarog.features.contracts import FeatureField, FeatureManifest


FEATURE_MANIFEST = FeatureManifest(
    feature_id="file-hash",
    title="文件哈希检查",
    description="只读计算工作区内单个文件的 SHA-256，用于证据核对。",
    order=100,
    fields=(FeatureField(
        name="target",
        label="目标文件",
        kind="workspace_file",
        required=True,
        help_text="请输入工作区内的相对文件路径；不会修改文件。",
    ),),
    permissions=frozenset({"workspace_read"}),
)


__all__ = ["FEATURE_MANIFEST"]
