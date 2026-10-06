"use strict";

window.SvarogPages = window.SvarogPages || Object.create(null);
window.SvarogPages["audit-diff"] = (context) => {
  const ui = window.SvarogUI;
  const form = document.querySelector("#diff-form");
  const output = document.querySelector("#diff-result");
  const body = document.querySelector("#diff-result-content");
  const choices = document.querySelector("#diff-snapshots");
  const names = {
    initial_snapshot: "首次审计", no_change: "无变化", project_changed: "项目变化",
    knowledge_changed: "知识库变化", project_and_knowledge_changed: "项目与知识库均变化",
  };

  async function load() {
    try {
      const result = await context.api("/api/audit-history?limit=100&offset=0");
      const successful = (result.items || []).filter((row) => row.snapshot_id &&
        (row.status === "completed_computed" || row.status === "completed_reused"));
      choices.replaceChildren();
      const seen = new Set();
      successful.forEach((row) => {
        if (seen.has(row.snapshot_id)) return;
        seen.add(row.snapshot_id);
        const option = document.createElement("option");
        option.value = String(row.snapshot_id);
        option.label = `${row.audit_kind === "python_project" ? "项目" : "环境"} · ${row.completed_at}`;
        choices.append(option);
      });
      if (!form.elements.target_snapshot_id.value && successful.length) {
        const target = successful[0];
        form.elements.target_snapshot_id.value = target.snapshot_id;
        const previous = successful.find((row) => row.audit_kind === target.audit_kind &&
          row.run_id !== target.run_id);
        if (previous) form.elements.baseline_snapshot_id.value = previous.snapshot_id;
      }
    } catch (error) {
      context.announce(error.message || "无法读取快照。", true);
    }
  }

  function render(result) {
    output.hidden = false;
    body.replaceChildren(ui.text("p", names[result.classification] || result.classification,
      "diff-classification"));
    if (result.baseline_snapshot_id === result.target_snapshot_id) {
      body.append(ui.text("p", "两次运行使用同一快照；审计内容无变化。"));
    }
    const summary = result.summary || {};
    body.append(ui.metrics([
      ["新增包", summary.package_added_count || 0], ["移除包", summary.package_removed_count || 0],
      ["变更包", summary.package_changed_count || 0],
      ["新增漏洞", summary.finding_introduced_count || 0],
      ["已解决漏洞", summary.finding_resolved_count || 0],
    ]));
    const causes = result.causes || [];
    if (causes.length) body.append(ui.text("p", `变化原因：${causes.join("、")}`));
    const packages = result.package_changes || [];
    body.append(ui.text("h3", `依赖变化 · ${packages.length}`));
    body.append(ui.table([
      {label: "范围", value: (item) => item.scope},
      {label: "依赖包", value: (item) => item.normalized_name},
      {label: "类型", value: (item) => (item.change_types || []).join("、")},
      {label: "之前", value: (item) => (item.before || []).map((row) => row.version).join("、") || "—"},
      {label: "之后", value: (item) => (item.after || []).map((row) => row.version).join("、") || "—"},
    ], packages.slice(0, 200)));
    if (packages.length > 200) body.append(ui.text("p", `仅显示前 200 项，共 ${packages.length} 项。`));
    const findings = result.finding_changes || [];
    body.append(ui.text("h3", `漏洞变化 · ${findings.length}`));
    body.append(ui.table([
      {label: "依赖包", value: (item) => item.normalized_name},
      {label: "版本", value: (item) => item.audited_version},
      {label: "漏洞编号", value: (item) => item.advisory_id},
      {label: "变化", value: (item) => item.change_type},
    ], findings.slice(0, 200)));
    if (findings.length > 200) body.append(ui.text("p", `仅显示前 200 项，共 ${findings.length} 项。`));
    const technical = document.createElement("div");
    technical.append(ui.text("p", `依赖边变化 ${(result.dependency_changes || []).length} · 输入问题变化 ${(result.issue_changes || []).length}`));
    technical.append(ui.text("p", `基线 ${result.baseline_snapshot_id || "无"} → 目标 ${result.target_snapshot_id}`));
    body.append(ui.detail("技术信息", technical));
    const full = ui.text("button", "下载完整差异 JSON");
    full.type = "button";
    full.className = "secondary";
    full.addEventListener("click", () => {
      const file = new Blob([JSON.stringify(result, null, 2) + "\n"], {type: "application/json"});
      const url = URL.createObjectURL(file);
      const link = document.createElement("a");
      link.href = url;
      link.download = "svarog-diff.json";
      link.click();
      window.setTimeout(() => URL.revokeObjectURL(url), 1000);
    });
    body.append(full);
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const baseline = form.elements.baseline_snapshot_id.value.trim();
    const target = form.elements.target_snapshot_id.value.trim();
    const valid = (value) => /^[1-9][0-9]*$/.test(value) && Number.isSafeInteger(Number(value));
    if (!valid(target) || (baseline && !valid(baseline))) {
      const field = !valid(target) ? "target_snapshot_id" : "baseline_snapshot_id";
      context.fieldErrors(form, {[field]: "请输入有效快照编号。"});
      return;
    }
    try {
      const result = await context.busy(form, () => context.api("/api/audit-history/compare",
        context.json({baseline_snapshot_id: baseline ? Number(baseline) : null,
          target_snapshot_id: Number(target)})));
      if (result) render(result);
    } catch (_error) { /* error shown next to the form */ }
  });
  return {load};
};
