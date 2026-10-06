"use strict";

window.SvarogPages = window.SvarogPages || Object.create(null);
window.SvarogPages.sbom = (context) => {
  const ui = window.SvarogUI;
  const form = document.querySelector("#sbom-form");
  const output = document.querySelector("#sbom-result");
  const body = document.querySelector("#sbom-result-content");
  const download = document.querySelector("#sbom-download");

  async function load() {
    try {
      const result = await context.api("/api/audit-history?audit_kind=python_project&limit=100&offset=0");
      const choices = document.querySelector("#sbom-snapshots");
      choices.replaceChildren();
      const seen = new Set();
      (result.items || []).forEach((row) => {
        if (!row.snapshot_id || seen.has(row.snapshot_id)) return;
        seen.add(row.snapshot_id);
        const option = document.createElement("option");
        option.value = String(row.snapshot_id);
        option.label = row.completed_at || "项目审计";
        choices.append(option);
        if (!form.elements.snapshot_id.value) form.elements.snapshot_id.value = row.snapshot_id;
      });
    } catch (error) {
      context.announce(error.message || "无法读取快照。", true);
    }
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const rawId = form.elements.snapshot_id.value.trim();
    if (!/^[1-9][0-9]*$/.test(rawId) || !Number.isSafeInteger(Number(rawId))) {
      context.fieldErrors(form, {snapshot_id: "请输入有效快照编号。"});
      return;
    }
    const id = Number(rawId);
    download.hidden = true;
    try {
      const result = await context.busy(form, async () => {
        const url = `/api/audit-history/snapshots/${id}/sbom`;
        const response = await fetch(url, {headers: {Accept: "application/vnd.cyclonedx+json"}});
        if (!response.ok) {
          const error = await response.json();
          throw new Error(error.error?.message || "SBOM 生成失败。");
        }
        return {bom: await response.json(), digest: response.headers.get("X-Content-SHA256"), url};
      });
      if (!result) return;
      const {bom, digest, url} = result;
      const edges = (bom.dependencies || []).reduce((count, item) => count + (item.dependsOn || []).length, 0);
      const incomplete = (bom.compositions || []).find((item) => item.aggregate === "incomplete");
      const unresolved = incomplete ? (incomplete.dependencies || []) : [];
      output.hidden = false;
      body.replaceChildren(ui.metrics([
        ["组件", (bom.components || []).length], ["依赖边", edges],
        ["未解析关系", unresolved.length],
        ["完整性", unresolved.length ? "部分" : "可解析关系已列出"],
        ["Schema", bom.specVersion === "1.7" ? "已校验 · 1.7" : "未知"],
      ]));
      body.append(ui.text("p", `SHA-256 · ${digest || "未返回"}`, "digest-value"));
      if (unresolved.length) {
        body.append(ui.text("h3", "未解析关系"));
        body.append(ui.table([{label: "依赖包", value: (reference) => reference}], unresolved));
      }
      download.href = url;
      download.hidden = false;
    } catch (error) {
      context.announce(error.message || "SBOM 生成失败。", true);
    }
  });
  return {load};
};
