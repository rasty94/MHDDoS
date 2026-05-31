# Changelog
All notable changes to this project will be documented in this file.

## [Unreleased]
### Added
- **OSINT Tools Integration Workspace**:
  - **theHarvester**: passive reconnaissance wrapper implemented and mapped to `utils/osint/theharvester_wrapper.py`.
  - **Mr.Holmes**: UI/CLI framework wrapper (`utils/osint/mrholmes_wrapper.py`).
  - **Shodan API**: Custom IP/search lookup client over `shodan` official Python library (`utils/osint/shodan_client.py`).
  - **Unified Data Models**: Pydantic structured output models representing hosts, emails, domains, and artifacts.
- **Continuous Integration (CI)**: GitHub Actions basic pipeline replacing direct deployments. Added `ruff` and `black` hooks.
- **Test Infrastructure (`pytest`)**: Added tests with mocks in `tests/test_osint_api.py` targeting OSINT endpoints.
- **App/Dashboard Overhaul**:
  - Implemented a dedicated "OSINT Tools" tab inside `app.py`.
  - Allowed fetching `shodan` and `theHarvester` directly tracking state in Streamlit.
- **Configuration Security**:
  - Included Pydantic validation via `utils/config_model.py`.
  - Supported strictly typed `presets` loading via JSON schemas.
- **Resource Monitoring (Upcoming/In-Progress)**: Prepped Prometheus metric exposure and `psutil` safe-guards to restrict the tool when CPU/Memory is saturated.

### Changed
- Refactored `.gitignore` to prevent tracking `.venv`/`venv` and MacOS `.DS_Store`.
- Modified `requirements.txt` to include `uv`, `typer`, `pydantic`, `pytest` and `shodan` and `pre-commit`.
- Improved `.dockerignore` context efficiency (removing over 448MB of unneeded data caching).

### Fixed
- Fixed raw empty Exceptions parsing via `with suppress(Exception):`.
