# Remove Top Safety Strip Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove the complete top safety strip and the investigation-flow subtitle from the Svarog workbench without leaving unused styles or layout space.

**Architecture:** This is a static asset cleanup. The HTML element and its dedicated CSS rules are removed, while a static contract test prevents the strip from returning.

**Tech Stack:** Semantic HTML, CSS, pytest.

---

### Task 1: Remove the safety strip

**Files:**
- Modify: `tests/webui/test_assets.py`
- Modify: `src/svarog/webui/assets/index.html`
- Modify: `src/svarog/webui/assets/app.css`

- [ ] **Step 1: Change the static contract test first**

Replace the positive assertion with:

```python
assert "核心工作流只读 · 未自动处置" not in html
assert "告警 → Agent 分析 → 日志查询 → IOC → ATT&amp;CK → 建议 → 人工确认。" not in html
assert "safety-strip" not in html
assert ".safety-strip" not in css
```

- [ ] **Step 2: Run the focused test and verify the expected failure**

Run:

```powershell
python -m pytest -p no:cacheprovider -o addopts='' tests/webui/test_assets.py::test_shell_has_exact_navigation_views_and_security_landmarks -q
```

Expected: failure because the current HTML still contains the investigation-flow subtitle.

- [ ] **Step 3: Remove the element and dedicated styles**

Delete this element from `index.html`:

```html
<p class="safety-strip"><span aria-hidden="true">●</span> 核心工作流只读 · 未自动处置</p>
```

Also delete this subtitle:

```html
<p>告警 → Agent 分析 → 日志查询 → IOC → ATT&amp;CK → 建议 → 人工确认。</p>
```

Delete all three `.safety-strip` rules from `app.css`, including the mobile rule. Do not add a replacement or placeholder.

- [ ] **Step 4: Run focused and complete verification**

Run:

```powershell
python -m pytest -p no:cacheprovider -o addopts='' tests/webui/test_assets.py -q
python -m pytest -p no:cacheprovider -o addopts='' -q -rs
git diff --check
```

Expected: zero failures; only documented platform-specific skips remain.

- [ ] **Step 5: Commit the change**

```powershell
git add src/svarog/webui/assets/index.html src/svarog/webui/assets/app.css tests/webui/test_assets.py docs/superpowers/plans/2026-09-12-remove-top-safety-strip.md
git commit -m "style: remove top safety strip"
```
