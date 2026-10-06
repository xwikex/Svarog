"use strict";

const csrfToken = document.querySelector('meta[name="svarog-csrf"]').content;
const ALERT_MAX_BYTES = 64 * 1024;
const LOG_MAX_BYTES = 10 * 1024 * 1024;
const PREF_KEY = "svarog_ui_prefs_v1";
let selectedCaseId = null;
let caseOffset = 0;
const pageInstances = Object.create(null);
const pendingSubmissions = new WeakMap();

class ApiError extends Error {
  constructor(error) {
    super((error && error.message) || "请求失败");
    this.detail = error || {};
  }
}

async function api(path, options = {}) {
  const headers = Object.assign({"Accept": "application/json"}, options.headers || {});
  if (options.method && options.method !== "GET") headers["X-Svarog-CSRF"] = csrfToken;
  const requestOptions = Object.assign({}, options, {headers});
  const response = await fetch(path, requestOptions);
  const payload = await response.json();
  if (!response.ok || !payload.ok) throw new ApiError(payload.error);
  return payload.data;
}

function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined && text !== null) node.textContent = String(text);
  if (className) node.setAttribute("class", className);
  return node;
}

function announce(message, assertive = false) {
  const target = document.querySelector(assertive ? "#global-status" : "#global-notice");
  if (target) target.textContent = message;
}

const navigation = document.querySelector("#primary-navigation");
const mobileNavigation = window.matchMedia("(max-width: 899px)");

function setNavigationOpen(open) {
  const isOpen = Boolean(open) && mobileNavigation.matches;
  document.body.classList.toggle("nav-open", isOpen);
  document.querySelector("#nav-toggle").setAttribute("aria-expanded", String(isOpen));
  if (mobileNavigation.matches) navigation.setAttribute("aria-hidden", String(!isOpen));
  else navigation.removeAttribute("aria-hidden");
  navigation.inert = mobileNavigation.matches && !isOpen;
}

function showView(name) {
  document.querySelectorAll("[data-view]").forEach((view) => { view.hidden = view.dataset.view !== name; });
  document.querySelectorAll("[data-nav-view]").forEach((link) => {
    if (link.dataset.navView === name) link.setAttribute("aria-current", "page");
    else link.removeAttribute("aria-current");
  });
  setNavigationOpen(false);
  document.querySelector("#main-content").focus();
  if (name === "overview") loadOverview();
  if (name === "cases") loadCases();
  if (pageInstances[name]) pageInstances[name].load();
}

function currentView() {
  const value = location.hash.replace(/^#/, "");
  return document.querySelector(`[data-view="${CSS.escape(value)}"]`) ? value : "overview";
}

function clearFieldErrors(form) {
  form.querySelectorAll("[aria-invalid]").forEach((control) => control.removeAttribute("aria-invalid"));
  form.querySelectorAll(".field-error").forEach((error) => { error.textContent = ""; });
}

function applyFieldErrors(form, fields) {
  let first = null;
  Object.entries(fields || {}).forEach(([name, message]) => {
    const control = form.elements.namedItem(name);
    const controls = control && control.length ? Array.from(control) : control ? [control] : [];
    controls.forEach((item) => item.setAttribute("aria-invalid", "true"));
    const actual = controls[0];
    if (actual && !first) first = actual;
    const describedIds = actual ? (actual.getAttribute("aria-describedby") || "").split(/\s+/) : [];
    const errorId = describedIds.find((id) => id.endsWith("-error"));
    const error = errorId ? form.querySelector(`#${CSS.escape(errorId)}`) : null;
    if (error) error.textContent = String(message);
  });
  if (first) first.focus();
}

async function submitBusy(form, work) {
  if (pendingSubmissions.has(form)) return pendingSubmissions.get(form);
  const pending = runBusy(form, work);
  pendingSubmissions.set(form, pending);
  try { return await pending; } finally { pendingSubmissions.delete(form); }
}

async function runBusy(form, work) {
  const button = form.querySelector('button[type="submit"]');
  const status = form.querySelector(".form-status");
  clearFieldErrors(form);
  button.disabled = true;
  status.textContent = "正在处理，请稍候…";
  try {
    const data = await work();
    status.textContent = "操作完成。";
    return data;
  } catch (error) {
    form.querySelectorAll('input[type="file"]').forEach((input) => { input.value = ""; });
    if (error instanceof ApiError) applyFieldErrors(form, error.detail.fields);
    status.textContent = error.message || "操作失败。";
    announce(status.textContent, true);
    throw error;
  } finally {
    button.disabled = false;
  }
}

function bytesToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  const pieces = [];
  const chunkSize = 24 * 1024;
  for (let start = 0; start < bytes.length; start += chunkSize) {
    let binary = "";
    const chunk = bytes.subarray(start, Math.min(start + chunkSize, bytes.length));
    for (let index = 0; index < chunk.length; index += 1) binary += String.fromCharCode(chunk[index]);
    pieces.push(btoa(binary));
  }
  return pieces.join("");
}

function readUpload(input, maximum) {
  return new Promise((resolve, reject) => {
    const file = input.files && input.files[0];
    if (!file) { reject(new ApiError({message: "请选择文件。", fields: {[input.name]: "请选择文件。"}})); return; }
    if (file.size > maximum) { reject(new ApiError({message: "文件超过允许大小。", fields: {[input.name]: "文件超过允许大小。"}})); return; }
    const reader = new FileReader();
    reader.addEventListener("load", () => resolve({name: file.name, data: bytesToBase64(reader.result)}));
    reader.addEventListener("error", () => reject(new ApiError({message: "无法读取文件。", fields: {[input.name]: "无法读取文件。"}})));
    reader.readAsArrayBuffer(file);
  });
}

function jsonOptions(value) {
  return {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(value)};
}

function safeDownload(container, label, href) {
  const url = new URL(href, location.origin);
  if (url.origin !== location.origin) return;
  const link = element("a", label);
  link.setAttribute("href", url.pathname + url.search);
  link.setAttribute("download", "");
  container.append(link);
}

function evidenceId(value) {
  const text = String(value);
  return /^log:[1-9][0-9]*$/.test(text) ? `evidence-log-${text.slice(4)}` : "evidence-invalid";
}

function trustedAttackUrl(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.hostname === "attack.mitre.org"
      && url.port === "" && url.username === "" && url.password === ""
      && url.search === "" && url.hash === ""
      && /^\/techniques\/T[0-9]{4}\/(?:[0-9]{3}\/)?$/.test(url.pathname) ? url.href : null;
  } catch (_error) { return null; }
}

function renderCell(cell, column, row) {
  const value = row[column.key];
  if (column.type === "hidden") return;
  if (column.type === "evidence_target") {
    const link = element("a", value || "—");
    link.setAttribute("id", evidenceId(value));
    link.setAttribute("href", `#${evidenceId(value)}`);
    cell.append(link); return;
  }
  if (column.type === "evidence_links") {
    const values = Array.isArray(value) ? value : [];
    values.forEach((item) => {
      const link = element("a", item);
      link.setAttribute("href", `#${evidenceId(item)}`);
      link.addEventListener("click", (event) => {
        event.preventDefault();
        const target = document.getElementById(evidenceId(item));
        if (!target) return;
        const details = target.closest("details");
        if (details) details.open = true;
        target.focus();
      });
      cell.append(link, document.createTextNode(" "));
    });
    if (!values.length) cell.textContent = "—";
    return;
  }
  if (column.type === "attack_link") {
    const href = trustedAttackUrl(row.url);
    if (href) { const link = element("a", value); link.setAttribute("href", href); link.setAttribute("target", "_blank"); link.setAttribute("rel", "noopener noreferrer"); cell.append(link); }
    else cell.textContent = String(value || "—");
    return;
  }
  cell.textContent = Array.isArray(value) ? value.join(", ") : String(value ?? "—");
}

function renderFixedResult(body, data) {
  body.replaceChildren(element("h3", data.title), statusBadge(data.status));
  const cards = element("div", null, "metrics");
  data.summary_cards.forEach((item) => { const card = element("article", null, "metric"); card.append(element("span", item.label), element("strong", item.value)); cards.append(card); });
  body.append(cards);
  if (data.warnings.length) { const list = element("ul", null, "warnings"); data.warnings.forEach((warning) => list.append(element("li", warning))); body.append(list); }
  data.tables.forEach((definition) => {
    const section = element("details");
    section.setAttribute("data-technical-details", "");
    section.open = Boolean(loadPreferences().technical_details_open);
    section.append(element("summary", definition.title));
    const wrap = element("div", null, "table-wrap"); const table = element("table");
    table.append(element("caption", definition.title));
    const head = element("thead"); const header = element("tr");
    definition.columns.filter((column) => column.type !== "hidden").forEach((column) => {
      const headerCell = element("th", column.label); headerCell.setAttribute("scope", "col"); header.append(headerCell);
    }); head.append(header);
    const rows = element("tbody"); definition.rows.forEach((row) => { const tr = element("tr"); definition.columns.filter((column) => column.type !== "hidden").forEach((column) => { const td = element("td"); renderCell(td, column, row); tr.append(td); }); rows.append(tr); });
    table.append(head, rows); wrap.append(table); section.append(wrap); body.append(section);
  });
}

const RESULT_RENDERERS = Object.freeze({
  web_analysis: renderFixedResult,
  dependency_audit: renderFixedResult,
  project_audit: renderFixedResult,
  doctor: renderFixedResult,
  sop_case: renderFixedResult,
  trusted_feature: renderFixedResult,
});

const RESULT_SCHEMAS = Object.freeze({
  web_analysis: {
    statuses: ["completed_local"], downloads: ["json"],
    summary: {required: ["total_events", "suspicious_events", "input_issues"],
      allowed: ["total_events", "suspicious_events", "input_issues", "severity_critical",
        "severity_high", "severity_medium", "severity_low", "severity_info"]}, tables: {
      events: [["timestamp", "text"], ["source_ip", "text"], ["request", "text"],
        ["severity", "text"], ["conclusion", "text"], ["rules", "text"]],
      recommendations: [["request", "text"], ["recommendation", "text"]],
    },
  },
  dependency_audit: {
    statuses: ["completed_clean", "completed_with_findings", "completed_incomplete", "completed_with_findings_and_gaps"],
    downloads: ["json"], summary: {required: ["installed_packages", "confirmed_findings", "indeterminate_findings"],
      allowed: ["installed_packages", "confirmed_findings", "indeterminate_findings"]}, tables: {
      installed_packages: [["name", "text"], ["version", "text"], ["version_valid", "text"]],
      findings: [["package_name", "text"], ["installed_version", "text"], ["severity", "text"],
        ["ghsa_id", "text"], ["fixed_version", "text"], ["summary", "text"]],
      indeterminate_findings: [["package_name", "text"], ["installed_versions", "text"],
        ["ghsa_id", "text"], ["affected_range", "text"], ["fixed_version", "text"], ["reason_code", "text"]],
    },
  },
  project_audit: {
    statuses: ["completed_clean", "completed_with_findings", "completed_incomplete", "completed_with_findings_and_gaps"],
    downloads: ["json", "html"], summary: {required: ["installed_packages", "locked_packages",
      "confirmed_environment_findings", "potential_lock_findings", "version_differences"],
      allowed: ["installed_packages", "locked_packages", "confirmed_environment_findings",
        "potential_lock_findings", "version_differences"]}, tables: {
      installed_packages: [["name", "text"], ["version", "text"], ["version_valid", "text"]],
      locked_packages: [["name", "text"], ["version", "text"], ["source_kind", "text"]],
      version_differences: [["name", "text"], ["installed_versions", "text"], ["locked_versions", "text"], ["status", "text"]],
      environment_findings: [["package_name", "text"], ["installed_version", "text"], ["severity", "text"],
        ["ghsa_id", "text"], ["fixed_version", "text"], ["summary", "text"]],
      environment_indeterminate_findings: [["package_name", "text"], ["installed_versions", "text"],
        ["ghsa_id", "text"], ["reason_code", "text"]],
      lock_findings: [["package_name", "text"], ["locked_version", "text"], ["severity", "text"],
        ["ghsa_id", "text"], ["fixed_version", "text"], ["summary", "text"]],
      lock_indeterminate_findings: [["package_name", "text"], ["locked_version", "text"],
        ["ghsa_id", "text"], ["reason_code", "text"]],
    },
  },
  doctor: {
    statuses: ["ready", "ready_with_warnings", "not_ready"], downloads: ["json"],
    summary: {required: ["pass", "warn", "fail"], allowed: ["pass", "warn", "fail"]}, tables: {
      checks: [["title", "text"], ["status", "text"], ["message", "text"]],
    },
  },
  sop_case: {
    statuses: ["awaiting_review", "approved", "rejected", "needs_investigation"],
    downloads: ["json", "html"], summary: {required: ["severity", "steps", "evidence", "iocs", "attack"],
      allowed: ["severity", "steps", "evidence", "iocs", "attack"]}, tables: {
      steps: [["number", "text"], ["name", "text"], ["status", "text"], ["detail", "text"]],
      agent: [["mode", "text"], ["summary", "text"], ["query_plan", "text"]],
      query: [["matched", "text"], ["retained", "text"], ["invalid_lines", "text"], ["truncated", "text"]],
      evidence: [["id", "evidence_target"], ["timestamp", "text"], ["source_ip", "text"], ["request", "text"]],
      iocs: [["type", "text"], ["value", "text"], ["role", "text"], ["status", "text"], ["evidence_ids", "evidence_links"]],
      attack: [["technique_id", "attack_link"], ["name", "text"], ["status", "text"],
        ["rationale", "text"], ["evidence_ids", "evidence_links"], ["url", "hidden"]],
      recommendations: [["id", "text"], ["text", "text"], ["precondition", "text"],
        ["impact", "text"], ["evidence_ids", "evidence_links"]],
      review: [["decision", "text"], ["reviewer", "text"], ["note", "text"], ["reviewed_at", "text"]],
    }, optionalTables: ["review"],
  },
});

function plainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function validatePresentationSchema(data) {
  if (!plainObject(data) || data.schema !== "svarog.workbench.result.v1"
      || typeof data.kind !== "string" || !RESULT_SCHEMAS[data.kind]
      || typeof data.title !== "string" || !data.title.trim()
      || data.actions_executed !== false || !Array.isArray(data.summary_cards)
      || !Array.isArray(data.warnings) || !Array.isArray(data.tables)
      || !plainObject(data.downloads)) return false;
  const schema = RESULT_SCHEMAS[data.kind];
  if (data.kind === "sop_case" && (typeof data.case_id !== "string"
      || !/^[A-Za-z0-9_-]{1,128}$/.test(data.case_id)
      || !Object.prototype.hasOwnProperty.call(data, "review")
      || (data.review !== null && !plainObject(data.review)))) return false;
  const summaryKeys = data.summary_cards.map((card) => card && card.key);
  const downloadKeys = Object.keys(data.downloads);
  if (!schema.statuses.includes(data.status)
      || data.summary_cards.some((card) => !plainObject(card) || typeof card.key !== "string"
        || typeof card.label !== "string" || !("value" in card))
      || data.warnings.some((warning) => typeof warning !== "string")
      || new Set(summaryKeys).size !== summaryKeys.length
      || summaryKeys.some((key) => !schema.summary.allowed.includes(key))
      || schema.summary.required.some((key) => !summaryKeys.includes(key))
      || downloadKeys.length !== schema.downloads.length
      || schema.downloads.some((name) => typeof data.downloads[name] !== "string")) return false;
  const tables = new Map();
  for (const table of data.tables) {
    if (!plainObject(table) || typeof table.id !== "string" || tables.has(table.id)
        || !schema.tables[table.id] || typeof table.title !== "string"
        || !Array.isArray(table.columns) || !Array.isArray(table.rows)) return false;
    const expected = schema.tables[table.id];
    if (table.columns.length !== expected.length || table.columns.some((column, index) =>
      !plainObject(column) || column.key !== expected[index][0] || column.type !== expected[index][1]
      || typeof column.label !== "string")) return false;
    if (table.rows.some((row) => !plainObject(row)
      || expected.some(([key]) => !Object.prototype.hasOwnProperty.call(row, key)))) return false;
    tables.set(table.id, table);
  }
  const optional = new Set(schema.optionalTables || []);
  return Object.keys(schema.tables).every((name) => optional.has(name) || tables.has(name));
}

function validateFeatureResultSchema(data) {
  if (!plainObject(data) || data.schema !== "svarog.workbench.feature-result.v1"
      || data.kind !== "trusted_feature" || typeof data.feature_id !== "string"
      || !/^[a-z][a-z0-9-]{0,63}$/.test(data.feature_id)
      || typeof data.title !== "string" || !data.title.trim()
      || !["completed", "completed_with_warnings"].includes(data.status)
      || data.actions_executed !== false || !Array.isArray(data.summary_cards)
      || !Array.isArray(data.warnings) || !Array.isArray(data.tables)
      || !plainObject(data.downloads) || Object.keys(data.downloads).length !== 1
      || typeof data.downloads.json !== "string") return false;
  const summaryKeys = new Set();
  for (const card of data.summary_cards) {
    if (!plainObject(card) || typeof card.key !== "string" || !/^[A-Za-z][A-Za-z0-9_-]{0,63}$/.test(card.key)
        || summaryKeys.has(card.key) || typeof card.label !== "string"
        || !["string", "number", "boolean"].includes(typeof card.value)) return false;
    summaryKeys.add(card.key);
  }
  if (data.warnings.some((warning) => typeof warning !== "string")) return false;
  const tableIds = new Set();
  for (const table of data.tables) {
    if (!plainObject(table) || typeof table.id !== "string" || tableIds.has(table.id)
        || typeof table.title !== "string" || !Array.isArray(table.columns)
        || !table.columns.length || !Array.isArray(table.rows)) return false;
    const keys = [];
    for (const column of table.columns) {
      if (!plainObject(column) || typeof column.key !== "string" || keys.includes(column.key)
          || typeof column.label !== "string" || column.type !== "text") return false;
      keys.push(column.key);
    }
    if (table.rows.some((row) => !plainObject(row)
      || keys.some((key) => !Object.prototype.hasOwnProperty.call(row, key)))) return false;
    tableIds.add(table.id);
  }
  return true;
}

function renderPresentation(body, data) {
  const valid = data && data.kind === "trusted_feature"
    ? validateFeatureResultSchema(data) : validatePresentationSchema(data);
  if (!valid || !RESULT_RENDERERS[data.kind]) {
    body.replaceChildren(element("p", "unsupported_result_schema：结果结构缺失或不受支持。", "error-banner"));
    return false;
  }
  RESULT_RENDERERS[data.kind](body, data); return true;
}

function validateFeatureCatalog(data) {
  if (!plainObject(data) || data.schema !== "svarog.workbench.features.v1"
      || !Array.isArray(data.features) || !Array.isArray(data.disabled)) return false;
  const ids = new Set();
  const fieldKinds = new Set(["text", "integer", "boolean", "choice", "workspace_file", "workspace_directory"]);
  const permissions = new Set(["workspace_read", "network", "database", "token"]);
  for (const feature of data.features) {
    if (!plainObject(feature) || typeof feature.feature_id !== "string"
        || !/^[a-z][a-z0-9-]{0,63}$/.test(feature.feature_id) || ids.has(feature.feature_id)
        || typeof feature.title !== "string" || typeof feature.description !== "string"
        || !Number.isInteger(feature.order) || !Array.isArray(feature.permissions)
        || feature.permissions.some((item) => !permissions.has(item)) || !Array.isArray(feature.fields)) return false;
    const names = new Set();
    for (const field of feature.fields) {
      if (!plainObject(field) || typeof field.name !== "string" || names.has(field.name)
          || !/^[a-z][a-z0-9_]{0,63}$/.test(field.name) || typeof field.label !== "string"
          || !fieldKinds.has(field.kind) || typeof field.required !== "boolean"
          || typeof field.help_text !== "string" || !Array.isArray(field.choices)
          || (field.minimum !== null && !Number.isInteger(field.minimum))
          || (field.maximum !== null && !Number.isInteger(field.maximum))) return false;
      names.add(field.name);
    }
    ids.add(feature.feature_id);
  }
  return data.disabled.every((item) => plainObject(item)
    && typeof item.package === "string" && typeof item.code === "string");
}

function featureField(feature, definition) {
  const wrapper = element("div", null, "field");
  const id = `feature-${feature.feature_id}-${definition.name}`;
  const label = element("label", definition.label); label.setAttribute("for", id);
  let control;
  if (definition.kind === "choice") {
    control = element("select");
    definition.choices.forEach((value) => {
      const option = element("option", value); option.setAttribute("value", value); control.append(option);
    });
  } else {
    control = element("input");
    control.setAttribute("type", definition.kind === "integer" ? "number" : definition.kind === "boolean" ? "checkbox" : "text");
    if (definition.minimum !== null) control.setAttribute("min", definition.minimum);
    if (definition.maximum !== null) control.setAttribute("max", definition.maximum);
  }
  control.setAttribute("id", id); control.setAttribute("name", definition.name);
  if (definition.required) control.setAttribute("required", "");
  const helpId = `${id}-help`; const errorId = `${id}-error`;
  control.setAttribute("aria-describedby", `${helpId} ${errorId}`);
  const help = element("p", definition.help_text, "helper"); help.setAttribute("id", helpId);
  wrapper.append(label, control, help);
  const error = element("p", null, "field-error"); error.setAttribute("id", errorId); wrapper.append(error);
  return wrapper;
}

function featureValues(form, fields) {
  const values = {};
  fields.forEach((field) => {
    const control = form.elements.namedItem(field.name);
    if (field.kind === "boolean") values[field.name] = control.checked;
    else if (control.value === "") return;
    else if (field.kind === "integer") values[field.name] = Number(control.value);
    else if (control.value !== "" || field.required) values[field.name] = control.value;
  });
  return values;
}

function installFeatures(catalog) {
  if (!validateFeatureCatalog(catalog)) throw new ApiError({message: "扩展功能清单不受支持。"});
  const navigation = document.querySelector("#feature-navigation");
  const views = document.querySelector("#feature-views");
  navigation.replaceChildren(); views.replaceChildren();
  catalog.features.forEach((feature) => {
    const viewName = `feature-${feature.feature_id}`;
    const link = element("a", feature.title); link.setAttribute("href", `#${viewName}`);
    link.dataset.navView = viewName;
    link.addEventListener("click", (event) => { event.preventDefault(); location.hash = viewName; });
    navigation.append(link);

    const section = element("section", null, "view"); section.dataset.view = viewName; section.hidden = true;
    const titleId = `${viewName}-title`; section.setAttribute("aria-labelledby", titleId);
    const heading = element("div", null, "page-heading"); const headingText = element("div");
    const eyebrow = element("p", "扩展功能", "eyebrow"); const title = element("h1", feature.title); title.setAttribute("id", titleId);
    headingText.append(eyebrow, title, element("p", feature.description)); heading.append(headingText); section.append(heading);
    section.append(element(
      "p",
      "可信模块与工作台进程拥有相同权限；权限标签仅供提示，并非系统沙箱。请只运行已经审查的自有模块。",
      "helper",
    ));
    if (feature.permissions.length) {
      const permissionLabels = {workspace_read: "读取工作区", network: "访问网络", database: "访问数据库", token: "读取 Token"};
      const list = element("ul", null, "permission-list");
      feature.permissions.forEach((permission) => list.append(element("li", permissionLabels[permission])));
      section.append(list);
    }
    const form = element("form", null, "panel form-grid"); form.setAttribute("novalidate", "");
    feature.fields.forEach((field) => form.append(featureField(feature, field)));
    const actions = element("div", null, "form-actions full");
    const button = element("button", "运行功能"); button.setAttribute("type", "submit");
    const status = element("p", null, "form-status"); status.setAttribute("aria-live", "polite");
    actions.append(button, status); form.append(actions);
    const resultPanel = element("section", null, "panel result-panel"); resultPanel.hidden = true;
    resultPanel.setAttribute("aria-live", "polite"); resultPanel.append(element("h2", "运行结果"));
    const resultBody = element("div"); resultBody.setAttribute("data-result-body", ""); resultPanel.append(resultBody);
    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      try {
        const data = await submitBusy(form, () => api(`/api/features/${encodeURIComponent(feature.feature_id)}/run`, jsonOptions(featureValues(form, feature.fields))));
        if (renderPresentation(resultBody, data)) {
          const downloads = element("div", null, "downloads");
          Object.entries(data.downloads || {}).forEach(([name, href]) => safeDownload(downloads, `下载 ${name.toUpperCase()} 报告`, href));
          resultBody.append(downloads);
        }
        resultPanel.hidden = false;
      } catch (_error) { /* live region already updated */ }
    });
    section.append(form, resultPanel); views.append(section);
  });
  document.querySelector("[data-feature-group]").hidden = catalog.features.length === 0;
  showView(currentView());
}

async function loadFeatures() {
  try { installFeatures(await api("/api/features", {method: "GET"})); }
  catch (error) { announce(error.message || "无法加载扩展功能。", true); }
}

function renderResult(targetId, data) {
  const panel = document.querySelector(targetId);
  const body = panel.querySelector("[data-result-body]");
  if (!renderPresentation(body, data)) { panel.hidden = false; return; }
  const downloads = element("div", null, "downloads");
  Object.entries(data.downloads || {}).forEach(([name, href]) => safeDownload(downloads, `下载 ${name.toUpperCase()} 报告`, href));
  body.append(downloads);
  panel.hidden = false;
}

function statusBadge(status) {
  const labels = {awaiting_review: "待复核", approved: "已批准", rejected: "已拒绝", needs_investigation: "需继续调查"};
  const badge = element("span", labels[status] || status || "未知", "status-badge");
  badge.dataset.tone = status === "rejected" ? "danger" : status === "awaiting_review" ? "warning" : "neutral";
  return badge;
}

function caseTable(items, allowOpen) {
  if (!items.length) return element("p", "暂无案件。", "empty-state");
  const table = element("table");
  const head = element("thead");
  const headerRow = element("tr");
  ["创建时间", "标题", "严重度", "状态", "操作"].forEach((label) => headerRow.append(element("th", label)));
  head.append(headerRow);
  const body = element("tbody");
  items.forEach((item) => {
    const row = element("tr");
    row.append(element("td", item.created_at), element("td", item.title), element("td", item.severity));
    const statusCell = element("td"); statusCell.append(statusBadge(item.status)); row.append(statusCell);
    const action = element("td");
    if (allowOpen) {
      const button = element("button", "查看", "secondary");
      button.setAttribute("type", "button");
      button.addEventListener("click", () => openCase(item.case_id));
      action.append(button);
    } else action.textContent = "—";
    row.append(action); body.append(row);
  });
  table.append(head, body);
  return table;
}

async function loadOverview() {
  try {
    const data = await api("/api/overview", {method: "GET"});
    const metrics = document.querySelector("#overview-metrics");
    metrics.replaceChildren();
    [["案件总数", data.total], ["待人工复核", data.awaiting_review], ["Doctor", data.doctor_status === "not_run" ? "尚未检查" : data.doctor_status], ["漏洞 Token", data.token_configured ? "已配置" : "未配置"]].forEach(([label, value]) => {
      const card = element("article", null, "metric"); card.append(element("span", label), element("strong", value)); metrics.append(card);
    });
    document.querySelector("#overview-recent").replaceChildren(caseTable(data.recent || [], false));
    const runs = document.querySelector("[data-recent-runs]");
    runs.replaceChildren();
    (data.recent_runs || []).forEach((run) => {
      const summary = (run.summary_cards || []).map((card) => `${card.label} ${card.value}`).join(" · ");
      runs.append(element("p", `${run.title} · ${run.status}${summary ? ` · ${summary}` : ""}`));
    });
    runs.append(element("p", data.run_history_notice || "运行记录在服务重启后清空。", "helper"));
  } catch (error) { announce(error.message, true); }
}

function casePageSize() {
  const value = Number(loadPreferences().cases_page_size || 20);
  return [10, 20, 50].includes(value) ? value : 20;
}

async function loadCases() {
  const query = document.querySelector("#cases-query").value;
  const status = document.querySelector("#cases-status").value;
  const limit = casePageSize();
  const params = new URLSearchParams({query, status, limit: String(limit), offset: String(caseOffset)});
  try {
    const data = await api(`/api/cases?${params.toString()}`, {method: "GET"});
    document.querySelector("#cases-list").replaceChildren(caseTable(data.items || [], true));
    document.querySelector("#cases-page").textContent = `第 ${Math.floor(caseOffset / limit) + 1} 页 · 共 ${data.total} 项`;
    document.querySelector("#cases-prev").disabled = caseOffset === 0;
    document.querySelector("#cases-next").disabled = caseOffset + limit >= data.total;
  } catch (error) { announce(error.message, true); }
}

async function openCase(caseId) {
  try {
    const data = await api(`/api/cases/${encodeURIComponent(caseId)}`, {method: "GET"});
    const detail = document.querySelector("#case-detail");
    const body = detail.querySelector("[data-case-body]");
    if (!renderPresentation(body, data)) { selectedCaseId = null; document.querySelector("#review-form").hidden = true; detail.hidden = false; return; }
    selectedCaseId = caseId;
    const downloads = element("div", null, "downloads");
    Object.entries(data.downloads || {}).forEach(([name, href]) => safeDownload(downloads, `下载 ${name.toUpperCase()} 案件`, href));
    body.append(downloads);
    document.querySelector("#review-form").hidden = data.review !== null;
    detail.hidden = false;
    detail.scrollIntoView({block: "start"});
  } catch (error) { announce(error.message, true); }
}

function auditPayload(form) {
  const values = new FormData(form);
  const source = values.get("vuln_source");
  return {
    environment: String(values.get("environment") || ""),
    vuln_db: source === "db" ? String(values.get("vuln_db") || "") : null,
    vuln_api: source === "api" ? String(values.get("vuln_api") || "") : null,
  };
}

function loadPreferences() {
  try {
    const parsed = JSON.parse(sessionStorage.getItem(PREF_KEY) || "{}");
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed : {};
  } catch (_error) { return {}; }
}

function savePreferences(value) {
  try { sessionStorage.setItem(PREF_KEY, JSON.stringify(value)); } catch (_error) { announce("无法保存界面偏好。", true); }
}

function applyPreferences() {
  const prefs = loadPreferences();
  if (prefs.default_sop_window) document.querySelector("#sop-window").value = prefs.default_sop_window;
  if (prefs.sop_result_limit) document.querySelector("#sop-limit").value = prefs.sop_result_limit;
  if (prefs.cases_page_size) document.querySelector("#pref-page-size").value = prefs.cases_page_size;
  if (prefs.default_sop_window) document.querySelector("#pref-window").value = prefs.default_sop_window;
  if (prefs.sop_result_limit) document.querySelector("#pref-limit").value = prefs.sop_result_limit;
  document.querySelector("#pref-details").checked = Boolean(prefs.technical_details_open);
  document.querySelectorAll("[data-technical-details]").forEach((details) => { details.open = Boolean(prefs.technical_details_open); });
}

document.querySelectorAll("[data-nav-view], [data-go-view]").forEach((link) => link.addEventListener("click", (event) => {
  event.preventDefault(); location.hash = link.dataset.navView || link.dataset.goView;
}));
window.addEventListener("hashchange", () => showView(currentView()));
document.querySelector("#nav-toggle").addEventListener("click", () => {
  const open = !document.body.classList.contains("nav-open");
  setNavigationOpen(open);
});
mobileNavigation.addEventListener("change", () => setNavigationOpen(false));
document.querySelector("#preferences-open").addEventListener("click", () => {
  document.querySelector("#preferences-drawer").hidden = false;
  document.querySelector("#preferences-open").setAttribute("aria-expanded", "true");
  document.querySelector("#preferences-close").focus();
});
document.querySelector("#preferences-close").addEventListener("click", () => {
  document.querySelector("#preferences-drawer").hidden = true;
  document.querySelector("#preferences-open").setAttribute("aria-expanded", "false");
  document.querySelector("#preferences-open").focus();
});
document.querySelector("#preferences-save").addEventListener("click", () => {
  savePreferences({cases_page_size: document.querySelector("#pref-page-size").value, default_sop_window: document.querySelector("#pref-window").value, sop_result_limit: document.querySelector("#pref-limit").value, technical_details_open: document.querySelector("#pref-details").checked});
  applyPreferences(); announce("界面偏好已保存。");
});
document.querySelector("[data-refresh-overview]").addEventListener("click", loadOverview);
document.querySelector("#sop-log-format").addEventListener("change", (event) => { document.querySelector("[data-nginx-host]").hidden = event.target.value !== "nginx-combined"; });

document.querySelector("#analyze-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { const data = await submitBusy(form, async () => api("/api/analyze", jsonOptions({logs: await readUpload(form.elements.logs, LOG_MAX_BYTES)}))); renderResult("#analyze-result", data); } catch (_error) { /* live region already updated */ }
});
document.querySelector("#python-audit-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try { const data = await submitBusy(form, () => api("/api/audit-python", jsonOptions(auditPayload(form)))); renderResult("#python-result", data); } catch (_error) { /* live region already updated */ }
});
document.querySelector("#project-audit-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const body = auditPayload(form); body.lock_file = form.elements.lock_file.value;
  try { const data = await submitBusy(form, () => api("/api/audit-project", jsonOptions(body))); renderResult("#project-result", data); } catch (_error) { /* live region already updated */ }
});
document.querySelector("#doctor-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget; const body = auditPayload(form); body.lock_file = form.elements.lock_file.value; body.output_directory = form.elements.output_directory.value;
  try { const data = await submitBusy(form, () => api("/api/doctor", jsonOptions(body))); renderResult("#doctor-result", data); } catch (_error) { /* live region already updated */ }
});
document.querySelector("#sop-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  try {
    const data = await submitBusy(form, async () => api("/api/sop", jsonOptions({alert: await readUpload(form.elements.alert, ALERT_MAX_BYTES), logs: await readUpload(form.elements.logs, LOG_MAX_BYTES), log_format: form.elements.log_format.value, log_host: form.elements.log_format.value === "nginx-combined" ? form.elements.log_host.value : null, window_minutes: Number(form.elements.window_minutes.value), limit: Number(form.elements.limit.value), agent_config: form.elements.agent_config.value || null})));
    renderResult("#sop-result", data); selectedCaseId = data.case_id;
    location.hash = "cases";
    showView("cases");
    await openCase(data.case_id);
  } catch (_error) { /* live region already updated */ }
});
document.querySelector("#cases-filter").addEventListener("submit", (event) => { event.preventDefault(); caseOffset = 0; loadCases(); });
document.querySelector("#cases-prev").addEventListener("click", () => { caseOffset = Math.max(0, caseOffset - casePageSize()); loadCases(); });
document.querySelector("#cases-next").addEventListener("click", () => { caseOffset += casePageSize(); loadCases(); });
document.querySelector("#review-form").addEventListener("submit", async (event) => {
  event.preventDefault(); const form = event.currentTarget;
  if (!selectedCaseId) { announce("请先选择案件。", true); return; }
  try { const data = await submitBusy(form, () => api(`/api/cases/${encodeURIComponent(selectedCaseId)}/review`, jsonOptions({decision: form.elements.decision.value, reviewer: form.elements.reviewer.value, note: form.elements.note.value}))); await openCase(data.case_id); await loadCases(); } catch (_error) { /* live region already updated */ }
});

if (window.SvarogPages) {
  const context = Object.freeze({api, json: jsonOptions, busy: submitBusy,
    announce, fieldErrors: applyFieldErrors});
  Object.entries(window.SvarogPages).forEach(([name, initialize]) => {
    if (typeof initialize === "function") pageInstances[name] = initialize(context);
  });
}
applyPreferences();
setNavigationOpen(false);
showView(currentView());
loadFeatures();
