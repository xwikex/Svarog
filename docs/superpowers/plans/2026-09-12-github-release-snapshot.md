# GitHub Release Snapshot Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Produce a clean GitHub-ready Svarog folder authored by xwikex that a Windows user can install and open within five minutes.

**Architecture:** Add release metadata, two fail-fast Windows launchers, and a first-screen quick start to the maintained source tree. After repository verification, copy an explicit allowlist into `C:\Users\18201\Desktop\project\release\Svarog`, excluding development internals and local data, then independently build and inspect the exported snapshot.

**Tech Stack:** Python 3.11+, setuptools/PEP 621, Windows batch, pytest, PowerShell, Git.

---

### Task 1: Define release metadata and user-facing files

**Files:**
- Create: `tests/release/test_release_assets.py`
- Create: `LICENSE`
- Create: `SECURITY.md`
- Modify: `pyproject.toml`
- Modify: `README.md`

- [ ] **Step 1: Write failing release-asset tests**

Add tests that parse `pyproject.toml` and assert:

```python
assert project["authors"] == [{"name": "xwikex"}]
assert project["license"] == {"file": "LICENSE"}
assert "License :: OSI Approved :: MIT License" in project["classifiers"]
assert "Copyright (c) 2026 xwikex" in license_text
assert readme.index("## 5 分钟打开 Web UI") < readme.index("## 本地可视化工作台")
```

Also assert `SECURITY.md` tells users not to submit real Tokens, logs, databases, or business data in public issues.

- [ ] **Step 2: Run the tests and verify the expected failure**

Run:

```powershell
python -m pytest -p no:cacheprovider -o addopts='' tests/release/test_release_assets.py -q
```

Expected: fail because release metadata and files do not exist yet.

- [ ] **Step 3: Add minimal GitHub metadata**

Add to `[project]` in `pyproject.toml`:

```toml
authors = [{name = "xwikex"}]
license = {file = "LICENSE"}
keywords = ["security", "log-analysis", "vulnerability-audit", "sbom"]
classifiers = [
  "License :: OSI Approved :: MIT License",
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3.11",
  "Operating System :: OS Independent",
]
```

Create the standard MIT License with `Copyright (c) 2026 xwikex`. Create `SECURITY.md` with safe private-reporting guidance and no invented email or repository URL.

- [ ] **Step 4: Add a first-screen five-minute quick start**

Insert `## 5 分钟打开 Web UI` near the top of README. It must explain ZIP extraction, Python 3.11+, double-clicking `install.bat`, double-clicking `start-ui.bat`, opening `http://127.0.0.1:8765/`, keeping the terminal open, and stopping with `Ctrl+C`. Include equivalent PowerShell commands and a short failure table.

- [ ] **Step 5: Run release-asset tests**

Run the focused test file and expect all tests to pass.

### Task 2: Add safe Windows launchers

**Files:**
- Create: `install.bat`
- Create: `start-ui.bat`
- Modify: `tests/release/test_release_assets.py`

- [ ] **Step 1: Add failing launcher contract tests**

Assert both launchers use `cd /d "%~dp0"`; `install.bat` checks Python 3.11, creates `.venv`, installs the local project, checks every error level, and never embeds a remote package index; `start-ui.bat` requires `.venv\Scripts\python.exe`, binds `127.0.0.1`, uses a workspace-contained SQLite path, and contains neither `0.0.0.0` nor an automatic browser command.

- [ ] **Step 2: Run the launcher tests and verify missing-file failures**

Run the release test file and expect failures for missing `install.bat` and `start-ui.bat`.

- [ ] **Step 3: Implement the launchers**

`install.bat` must choose `py -3` or `python`, validate `sys.version_info >= (3, 11)`, create `.venv`, run `.venv\Scripts\python.exe -m pip install --disable-pip-version-check .`, and fail with a clear message at each boundary.

`start-ui.bat` must run:

```bat
".venv\Scripts\python.exe" -m svarog ui --host 127.0.0.1 --port 8765 --workspace "." --case-db ".svarog\cases.sqlite3"
```

It prints `http://127.0.0.1:8765/`, tells the user to keep the window open, and never opens the browser itself.

- [ ] **Step 4: Run launcher and full repository tests**

Run:

```powershell
python -m pytest -p no:cacheprovider -o addopts='' tests/release/test_release_assets.py -q
python -m pytest -p no:cacheprovider -o addopts='' -q -rs
git diff --check
```

Expected: zero failures and only documented platform-specific skips.

- [ ] **Step 5: Commit maintained release files**

```powershell
git add LICENSE SECURITY.md install.bat start-ui.bat README.md pyproject.toml tests/release/test_release_assets.py docs/superpowers/plans/2026-09-12-github-release-snapshot.md
git commit -m "docs: prepare five-minute GitHub release"
```

### Task 3: Generate and independently verify the clean snapshot

**Output:**
- Create: `C:\Users\18201\Desktop\project\release\Svarog`

- [ ] **Step 1: Create the destination using an allowlist**

Create a new empty destination and copy only:

```text
src, samples, tests,
docs/SOP使用说明.md, docs/UI使用说明.md,
.dockerignore, .gitattributes, .gitignore,
Dockerfile, LICENSE, README.md, SECURITY.md,
install.bat, start-ui.bat, pyproject.toml
```

Do not copy `.git`, `.worktrees`, `.venv`, caches, builds, reports, databases, environment files, test temporary directories, internal plans, or historical acceptance records.

- [ ] **Step 2: Scan the exported tree**

Fail if forbidden names or extensions are present, or if text files contain common private-key headers, Bearer credentials, current-machine absolute paths, or known local Token assignment patterns. Confirm `docs/superpowers` is absent.

- [ ] **Step 3: Test and build from the exported tree**

Run the release test suite from the destination. Build a Wheel with:

```powershell
python -m pip wheel --no-cache-dir --no-deps --no-build-isolation . --wheel-dir C:\Users\18201\Desktop\project\release\.verification\wheel
```

Inspect the Wheel for all Web UI assets and `svarog.features.file_hash`. Install it into an isolated target and parse `ui --workspace .` without calling `serve`.

- [ ] **Step 4: Produce a release manifest**

Create `RELEASE-MANIFEST.txt` in the destination containing the snapshot date, author, version, source commit, file count, verification result, Wheel name/hash, and an explicit statement that no server or browser was started during packaging.

- [ ] **Step 5: Final source and destination checks**

Confirm the maintained source worktree is clean, the destination has no nested `.git`, and the destination README begins with the five-minute user path. Report the absolute destination path and exact verification counts.
