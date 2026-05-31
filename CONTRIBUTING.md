# Contributing to MHcheck

Thank you for your interest in contributing! This document details the process for contributing to the repository.

## Development Setup

1. **Clone the Repository:**
   ```bash
   git clone https://github.com/MatrixTM/MHcheck.git
   cd MHcheck
   ```
2. **Install Dependencies via `uv` or `pip`:**
   ```bash
   pip install uv
   uv pip install -r requirements.txt
   ```
3. **Setup Pre-commit Hooks:**
   We enforce formatting (`black`), sorting (`isort`), and linting (`ruff`) on every commit.
   ```bash
   pre-commit install
   ```

## Pull Request Process

1. Fork the repo and create your branch from `main`.
2. Ensure your code passes all lint checks. You can trigger them manually:
   `pre-commit run --all-files`
3. Write unit tests for new features. We use `pytest`:
   `pytest tests/`
4. Update `CHANGELOG.md` with your contributions in the `[Unreleased]` section.
5. Create a descriptive Pull Request with before/after screenshots if applicable.

## Guidelines
- **No Malicious Usage:** Code contributed must not violate local or international cybersecurity laws. Our tool handles "stress testing" for educational and analytical limits checks only. 
- Try to make the integration modular (if adding a new method, add it inside `methods/` and update models).
