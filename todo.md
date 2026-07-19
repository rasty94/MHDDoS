# MHcheck Improvement Roadmap

Las 7 épicas estratégicas de la plataforma de **auditoría de postura continua**
fueron implementadas el 2026-06-11. Este archivo conserva el estado y lista las
mejoras incrementales que quedan por encima de ellas.

## Estado actual
- [x] Tareas completadas: ver [done.md](file:///Users/antoniorodriguez/GITHUB-RASTY/megascript/done.md) (registro histórico)

## Épicas implementadas ✅
- [x] **A — Inventario, monitorización y alertas**: activos en SQLite, scheduler de flota, alertas (webhook/Slack/Telegram/email)
- [x] **B — API-first y gate CI/CD**: FastAPI (`api.py`), comando `cyber gate`, workflows Trivy y audit-gate
- [x] **C — Inteligencia de vulnerabilidades**: CVE/CVSS vía NVD/OSV, HIBP, fuentes premium theHarvester
- [x] **D — Compliance e informes**: OWASP ASVS/CIS/PCI-DSS/NIST + informe HTML con tendencia
- [x] **E — Auth, RBAC y multi-tenant**: PBKDF2, roles, tenant; login gate en Streamlit
- [x] **F — Remediación asistida por IA**: Claude (claude-opus-4-8) con fallback heurístico
- [x] **G — Fundación**: paquete `audit_platform`, ruff 0 errores, mypy limpio, gate cobertura 75%, Docker hardening, tests CLI, Mr.Holmes retirado

---

## Mejoras incrementales pendientes (sobre las épicas)

### Auditoría continua
- [x] Export de informe a PDF nativo (hoy HTML imprimible) sin dependencias de sistema pesadas
- [x] Programar el `FleetScheduler` como servicio/cron en producción (deployment dedicado)
- [x] Panel de inventario y gestión de activos dentro del dashboard de Streamlit

### Inteligencia y cobertura
- [x] Cachear enriquecimiento CVE (NVD/OSV) para respetar rate limits y acelerar re-escaneos
- [x] Caso de uso real de HIBP en la UI (consulta de emails de theHarvester)
- [x] Aumentar cobertura de tests del scheduler y de los canales de alertas (envío real mockeado)

### Plataforma y distribución
- [x] Empaquetar `audit_platform` como distribución instalable (pyproject build/entry points)
- [x] Persistencia de sesión de auth en Streamlit más robusta (cookies firmadas / expiración)
- [x] Documentar despliegue multi-tenant y rotación de credenciales

---

## Épica H — Limpieza de estructura y deuda técnica

_Auditoría estructural (graphify + ponytail) del 2026-07-19. El grafo reveló dos
proyectos conviviendo en un repo: el legado ofensivo (`start.py`, `app.py`) y la
plataforma de auditoría (`audit_platform/`, `api.py`, `cli.py`, `utils/`)._

### Cortes (bajo riesgo — nada de esto está referenciado)

- [x] **Borrar `methods/layer4.py` + `methods/layer7.py`** (~1112 líneas) — código muerto: nada hacía `from methods`. Copias duplicadas de `Layer4`/`HttpFlood` que ya viven en `start.py`. Limpiadas también las referencias a `methods*` en `pyproject.toml`. Tests 59/59 verdes tras el borrado.
- [x] **Borrar scripts one-off de dev en la raíz**: `refactor.py`, `modularize.py`, `fix_common_imports.py` (~162 líneas). Toqueteos AST de usar-y-tirar.
- [x] **Borrar/ignorar dumps regenerables**: `ruff_output.txt`, `ruff_output_fix.txt`, `ruff_check.txt`, `.coverage`, `skills-lock.json` → añadidos a `.gitignore` (+ `.mypy_cache/`, `.pytest_cache/`).
- [x] **Borrar `common_header.py`** (208 líneas) — código muerto: nadie lo importa. Duplicaba `bcolors`/`Counter` (ya presentes en `start.py` y `utils/common.py`). Referencia en `pyproject.toml` limpiada.
- [x] **Fix bug latente en `utils/osint/vuln_intel.py`** — `Vulnerability` usada en anotaciones (líneas 48/66) antes de definirse (línea 83). Funcionaba solo por lazy-annotations de Python 3.14 (PEP 649); rompería en <3.14. Resuelto con `from __future__ import annotations`. Ruff limpio, 59/59 tests.
- [ ] **Consolidar dependencias**: `requirements.txt` duplica las 21 deps de `pyproject.toml`. NO borrado: es load-bearing (Dockerfile, CI, README, CONTRIBUTING lo usan). Consolidar exige migrar esos 4 a `pip install .` — pendiente por riesgo de romper el build.
- [x] **Retirar `mrholmes` del todo** — wrapper deprecated y no-funcional (placeholder + warning), estaba expuesto como pestaña "🕵️ Mr.Holmes" en el dashboard y comando `cyber osint mrholmes`. Borrado `utils/osint/mrholmes_wrapper.py`, pestaña de Streamlit (tabs 5→4), comando CLI, imports en `app.py`/`cli.py`, test, ignores en `pyproject.toml` y mención en `README.md`. Ruff limpio, 58/58 tests.

### Estructura (decisiones de fondo)

- [ ] **Separar legado ofensivo de la plataforma**: mover `start.py`/`app.py`/`common_header.py` a `legacy/` (o a su propio repo). `audit_platform/__init__.py` ya declara la intención ("kept deliberately separate"); falta ejecutarla en el layout.
- [ ] **Resolver la extracción a medias de `methods/`**: `methods/` era `start.py` a medio modularizar y nunca se cableó. Alternativa a borrarlo: terminar la extracción (que `start.py` importe de `methods/` y elimine sus copias inline). Una de las dos copias debe morir.
- [ ] **Revisar el barrel `audit_platform/__init__.py`** (30 re-exports): infla el acoplamiento aparente (`CyberAnalysisAdapter`/`score_findings` como god-nodes de 46 aristas). Mantener solo si se publica como API pública; si no, importar directo de `utils.*`.
- [ ] **Subir cohesión de "Audit Platform & Auth"** (score 0.06): mezcla auth + alerts + barrel. Al dividir el barrel, la comunidad se separa sola en piezas enfocadas.

_Impacto estimado de los cortes: ~-1274 líneas, -1 fuente de deps, -5 archivos de ruido._
