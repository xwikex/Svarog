"use strict";

window.SvarogPages = window.SvarogPages || Object.create(null);
window.SvarogPages.settings = (context) => {
  const projectForm = document.querySelector("#project-settings-form");
  const retentionForm = document.querySelector("#retention-settings-form");
  const directory = document.querySelector("#settings-data-directory");
  const projectId = document.querySelector("#settings-project-id");

  async function load() {
    try {
      const [project, settings] = await Promise.all([
        context.api("/api/project"), context.api("/api/settings"),
      ]);
      projectForm.elements.display_name.value = project.display_name || "";
      retentionForm.elements.audit_retention_days.value = settings.audit_retention_days;
      directory.textContent = settings.data_directory;
      projectId.textContent = project.exists ? `项目标识：${project.project_id}` : "项目尚未初始化";
    } catch (error) {
      context.announce(error.message || "设置暂时不可用。", true);
    }
  }

  projectForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const name = projectForm.elements.display_name.value.trim();
    if (!name) {
      context.fieldErrors(projectForm, {display_name: "请输入项目名称。"});
      return;
    }
    try {
      const project = await context.busy(projectForm, () => context.api("/api/project",
        context.json({display_name: name})));
      if (project) projectId.textContent = `项目标识：${project.project_id}`;
    } catch (_error) { /* inline error is already visible */ }
  });

  retentionForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    const days = Number(retentionForm.elements.audit_retention_days.value);
    if (!Number.isInteger(days) || days < 3 || days > 365) {
      context.fieldErrors(retentionForm, {audit_retention_days: "请输入 3 至 365 天。"});
      return;
    }
    try {
      const settings = await context.busy(retentionForm, () => context.api("/api/settings",
        context.json({audit_retention_days: days})));
      if (settings) {
        directory.textContent = settings.data_directory;
        retentionForm.querySelector(".form-status").textContent = "已保存，将在下次成功审计后清理过期记录。";
      }
    } catch (_error) { /* inline error is already visible */ }
  });
  return {load};
};
