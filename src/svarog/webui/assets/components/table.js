"use strict";

window.SvarogUI = Object.freeze({
  text(tag, value, className) {
    const node = document.createElement(tag);
    node.textContent = value === undefined || value === null ? "—" : String(value);
    if (className) node.className = className;
    return node;
  },
  table(columns, rows, decorate) {
    const wrap = document.createElement("div");
    wrap.className = "table-wrap";
    if (!rows.length) {
      wrap.append(window.SvarogUI.text("p", "暂无记录。", "empty-state"));
      return wrap;
    }
    const table = document.createElement("table");
    const head = document.createElement("thead");
    const heading = document.createElement("tr");
    columns.forEach((column) => {
      const cell = window.SvarogUI.text("th", column.label);
      cell.scope = "col";
      heading.append(cell);
    });
    if (decorate) heading.append(window.SvarogUI.text("th", "操作"));
    head.append(heading);
    const body = document.createElement("tbody");
    rows.forEach((row) => {
      const tr = document.createElement("tr");
      columns.forEach((column) => tr.append(window.SvarogUI.text("td", column.value(row))));
      if (decorate) {
        const cell = document.createElement("td");
        decorate(cell, row);
        tr.append(cell);
      }
      body.append(tr);
    });
    table.append(head, body);
    wrap.append(table);
    return wrap;
  },
  metrics(values) {
    const grid = document.createElement("div");
    grid.className = "metrics";
    values.forEach(([label, value]) => {
      const card = document.createElement("article");
      card.className = "metric";
      card.append(window.SvarogUI.text("span", label), window.SvarogUI.text("strong", value));
      grid.append(card);
    });
    return grid;
  },
  detail(title, node) {
    const details = document.createElement("details");
    details.append(window.SvarogUI.text("summary", title), node);
    return details;
  },
});

window.SvarogPages = window.SvarogPages || Object.create(null);
