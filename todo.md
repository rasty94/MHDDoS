# MHcheck Improvement Roadmap

This document lists recommended architectural, performance, and feature improvements for the MHcheck repository.

## 🐳 Docker & Build Optimization
- [x] **Optimize Build Context (`.dockerignore`)**
  * *Problem:* Currently, building the Docker image transfers over `448 MB` of local build context (e.g., the virtual environment `venv/`, git history, python cache files).
  * *Solution:* Create a `.dockerignore` file in the root directory to exclude heavy folders and prevent copying development cache to the container. (Completed)
- [x] **Migrate to `uv` inside Dockerfile**
  * *Problem:* Standard `pip` dependency resolution and wheel compilation take a long time during container builds (around 40 seconds).
  * *Solution:* Integrate Astral's `uv` inside the `Dockerfile` for near-instant package installation.

## 🖥️ Streamlit App Features
- [x] **System Resource Monitor (Host Health)**
  * *Description:* Since `psutil` is already a requirement, read and plot the host CPU and Memory utilization during active stress tests to prevent self-denial-of-service.
- [x] **Proxy Manager Tab**
  * *Description:* Create a dedicated tab in the Streamlit dashboard to check, download, and refresh proxy lists directly from the proxy providers listed in `config.json` without needing to trigger a test first.
- [x] **PDF/CSV Report Export**
  * *Description:* Add an "Export Stats" button to download a summary of the stress test metrics (PPS, BPS, duration, target) as a CSV or PDF file.
- [x] **Preset Configurations**
  * *Description:* Allow saving target and parameter configurations as "Presets" (e.g., "Layer 7 Bypass CF", "Layer 4 UDP Flood") for rapid execution.

## ⚙️ Refactoring & Code Quality
- [x] **Modularize `start.py`**
  * *Problem:* `start.py` is a monolithic file with over 1,800 lines of code. This makes maintenance and testing difficult.
  * *Solution:* Split the monolithic script into separate modules:
    * `methods/layer4.py` — Layer 4 attack methods.
    * `methods/layer7.py` — Layer 7 request flooders.
    * `utils/proxy.py` — Proxy downloader, parsing, and check logic.
    * `utils/networking.py` — Utilities such as resolver, ping, etc.
- [x] **Improve Error Handling & Logging**
  * *Problem:* Frequent use of `with suppress(Exception):` and empty `except:` blocks masks network errors and socket failures.
  * *Solution:* Implement clean, contextual exception handling that reports precise socket or DNS errors back to the logs (and therefore back to the Streamlit UI).
