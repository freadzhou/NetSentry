# Repository Guidelines

## Project Structure & Module Organization
NetSentry is a small Python desktop app built with PyQt6. Entry points are [`run.py`](/var/home/sss/Workspace/NetSentry/run.py) for local development and [`main.py`](/var/home/sss/Workspace/NetSentry/main.py) as an alternate launcher. Core monitoring logic lives in `core/`, including process and network collection plus threat evaluation in `core/threats/`. UI code is in `ui/`, and shared helpers such as formatting and port lookup live in `utils/`. Runtime data is stored under `config/`, especially `config/settings.json` and `config/threats/threat_db.json`.

## Build, Test, and Development Commands
- `uv install`: install project dependencies from `pyproject.toml` and `uv.lock`.
- `uv run python run.py`: start the desktop app with the default development launcher.
- `uv run python main.py`: run the alternate entry point.
- `./start.sh`: Linux convenience wrapper for `uv run python run.py`.
- `uv run python -m py_compile core ui utils *.py`: quick syntax check across the repository.

## Coding Style & Naming Conventions
Use Python 3.10+ with 4-space indentation and UTF-8 source files. Follow the existing module layout: `snake_case` for files, functions, and variables; `PascalCase` for Qt widgets, dataclasses, and other classes; uppercase constants for sort modes and platform flags. Keep UI text and labels consistent with the current Chinese-language interface. No formatter or linter configuration is checked in, so keep changes style-consistent with surrounding code and avoid large unrelated refactors.

## Testing Guidelines
There is no committed automated test suite yet. For new logic, add focused tests under a future `tests/` directory using `pytest`, with names like `test_monitor.py` or `test_threats.py`. Until that exists, validate changes with `uv run python -m py_compile core ui utils *.py` and a manual run of `uv run python run.py`, especially for UI behavior, refresh timing, and threat database updates.

## Commit & Pull Request Guidelines
Recent history uses short, imperative commit messages such as `Update README.md` and `Add files via upload`. Prefer clearer subject lines like `Add process risk summary` or `Fix Linux theme toggle`. Keep commits scoped to one change. Pull requests should include a brief summary, affected modules, manual test notes, linked issues if applicable, and screenshots or short recordings for UI changes.

## Security & Configuration Tips
Do not commit machine-specific secrets or local-only settings. Treat `config/threats/threat_db.json` as managed data: document schema changes and avoid ad hoc edits without verifying update behavior.
