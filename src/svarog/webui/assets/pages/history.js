"use strict";

window.SvarogPages = window.SvarogPages || Object.create(null);
window.SvarogPages["audit-history"] = (context) => {
  const ui = window.SvarogUI;
  const form = document.querySelector("#history-filter");
  const list = document.querySelector("#history-list");
  const pageLabel = document.querySelector("#history-page");
  const prev = document.querySelector("#history-prev");
  const next = document.querySelector("#history-next");
  const detail = document.querySelector("#history-detail");
  const detailBody = document.querySelector("#history-detail-content");
  let offset = 0;
  let detailOffset = 0;
  let requestNumber = 0;
  const limit = 20;
  const statusNames = {
    started: "运行中", completed_computed: "已完成", completed_reused: "已复用",
    failed: "失败", interrupted: "中断",
  };
  const changeNames = {
    initial_snapshot: "首次审计", no_change: "无变化", project_changed: "项目变化",
    knowledge_changed: "知识库变化", project_and_knowledge_changed: "项目与知识库均变化",
  };

  function parameters() {
    const fields = new URLSearchParams({limit: String(limit), offset: String(offset)});
    for (const name of ["audit_kind", "run_status", "reused"]) {
      const value = form.elements[name].value;
      if (value) fields.set(name, value);
    }
    if (form.elements.completed_from.value) fields.set("completed_from", `${form.elements.completed_from.value}T00:00:00Z`);
    if (form.elements.completed_to.value) fields.set("completed_to", `${form.elements.completed_to.value}T23:59:59Z`);
    return fields;
  }

  async function load() {
    const current = ++requestNumber;
    const status = form.querySelector(".form-status");
    status.textContent = "正在读取…";
    try {
      const result = await context.api(`/api/audit-history?${parameters()}`);
      if (current !== requestNumber) return;
      const rows = result.items || [];
      const columns = [
        {label: "时间", value: (row) => row.completed_at || row.started_at},
        {label: "类型", value: (row) => row.audit_kind === "python_project" ? "项目依赖" : "Python 环境"},
        {label: "状态", value: (row) => statusNames[row.status] || row.status},
        {label: "包", value: (row) => row.summary ? row.summary.environment_package_count + row.summary.lock_package_count : "—"},
        {label: "漏洞", value: (row) => row.summary ? row.summary.affected_finding_count : "—"},
        {label: "变化", value: (row) => changeNames[row.classification] || "—"},
        {label: "复用", value: (row) => row.reused ? "是" : "否"},
      ];
      list.replaceChildren(ui.table(columns, rows, (cell, row) => {
        if (!row.snapshot_id) return;
        const button = ui.text("button", "详情");
        button.type = "button";
        button.className = "secondary";
        button.addEventListener("click", () => { detailOffset = 0; openSnapshot(row.snapshot_id); });
        cell.append(button);
      }));
      pageLabel.textContent = `第 ${Math.floor(offset / limit) + 1} 页 · 共 ${result.total_count} 项`;
      prev.disabled = offset === 0;
      next.disabled = offset + limit >= result.total_count;
      status.textContent = "";
    } catch (error) {
      if (current !== requestNumber) return;
      status.textContent = error.message || "无法读取历史。";
      context.announce(status.textContent, true);
    }
  }

  async function openSnapshot(id) {
    detail.hidden = false;
    detailBody.replaceChildren(ui.text("p", "正在读取…"));
    try {
      const data = await context.api(`/api/audit-history/snapshots/${id}?limit=100&offset=${detailOffset}`);
      const summary = data.summary;
      detailBody.replaceChildren(ui.metrics([
        ["环境包", summary.environment_package_count], ["锁定包", summary.lock_package_count],
        ["受影响漏洞", summary.affected_finding_count], ["无法判断", summary.indeterminate_finding_count],
      ]));
      const packageRows = data.packages.items || [];
      detailBody.append(ui.text("h3", `依赖包 · ${data.packages.total_count}`));
      detailBody.append(ui.table([
        {label: "范围", value: (row) => row.scope === "lock" ? "锁文件" : "环境"},
        {label: "名称", value: (row) => row.raw_name},
        {label: "版本", value: (row) => row.version},
        {label: "来源", value: (row) => row.source_kind},
      ], packageRows));
      detailBody.append(ui.text("h3", `漏洞 · ${data.findings.total_count}`));
      detailBody.append(ui.table([
        {label: "依赖包", value: (row) => row.normalized_name},
        {label: "版本", value: (row) => row.audited_version},
        {label: "编号", value: (row) => row.advisory_id},
        {label: "结果", value: (row) => row.finding_status},
      ], data.findings.items || []));
      const maxCount = Math.max(data.packages.total_count, data.findings.total_count);
      if (maxCount > 100) {
        const pager = document.createElement("div");
        pager.className = "pagination";
        const previous = ui.text("button", "上一页");
        previous.type = "button";
        previous.className = "secondary";
        previous.disabled = detailOffset === 0;
        previous.addEventListener("click", () => { detailOffset = Math.max(0, detailOffset - 100); openSnapshot(id); });
        const following = ui.text("button", "下一页");
        following.type = "button";
        following.id = "detail-next";
        following.className = "secondary";
        following.disabled = detailOffset + 100 >= maxCount;
        following.addEventListener("click", () => { detailOffset += 100; openSnapshot(id); });
        pager.append(previous, ui.text("span", `第 ${Math.floor(detailOffset / 100) + 1} 页`), following);
        detailBody.append(pager);
      }
      const technical = document.createElement("div");
      technical.append(ui.text("p", `快照 ${id} · Python ${summary.python_version}`));
      technical.append(ui.text("p", `依赖关系 ${data.dependencies.total_count} · 输入问题 ${data.issues.total_count}`));
      detailBody.append(ui.detail("技术信息", technical));
      detail.focus();
      detail.scrollIntoView({block: "start"});
    } catch (error) {
      detailBody.replaceChildren(ui.text("p", error.message || "快照不可用。"));
    }
  }

  form.addEventListener("submit", (event) => { event.preventDefault(); offset = 0; load(); });
  prev.addEventListener("click", () => { offset = Math.max(0, offset - limit); load(); });
  next.addEventListener("click", () => { offset += limit; load(); });
  document.querySelector("#history-close-detail").addEventListener("click", () => {
    detail.hidden = true;
    form.elements.audit_kind.focus();
  });
  return {load};
};
