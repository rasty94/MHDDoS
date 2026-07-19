# Done — Registro de tareas completadas

Este archivo registra las tareas que se han completado y trasladado desde `todo.md`.

- 2026-05-31: Revisar `todo.md` y resumir estado
- 2026-05-31: Proponer y documentar mejoras concretas
- 2026-05-31: Actualizar `todo.md` con tareas detalladas
- 2026-06-11: Integrar theHarvester (DNS, emails, subdominios)
- 2026-06-11: Integrar Mr.Holmes (indicadores relevantes)
- 2026-06-11: Integrar Shodan API (búsquedas, host lookup)
- 2026-06-11: Escribir tests para integraciones OSINT
- 2026-06-11: Añadir CLI (Typer) para presets y OSINT
- 2026-06-11: Validación de config.json y presets con Pydantic
- 2026-06-11: Añadir CI (GitHub Actions) y pre-commit (ruff, black, isort)
- 2026-06-11: Exponer métricas Prometheus y límites de recursos
- 2026-06-11: Integrar módulos OSINT en app Streamlit
- 2026-06-11: Revisión y migración a imagen base Docker python:3.14-alpine para mitigar vulnerabilidades y relanzar localmente con 0 vulnerabilidades
- 2026-06-11: Higiene de dependencias (deduplicar pydantic y resolver conflicto prometheus-client en requirements.txt)
- 2026-06-11: Forzar SHODAN_API_KEY por entorno y avisar de uso deprecado de config.json para secretos
- 2026-06-11: Análisis TLS profundo (versión de protocolo, cifrado, hallazgos por TLS débil y expiración <30 días)
- 2026-06-11: Detección de vulnerabilidades en Nmap (script NSE vulners poblando HostInfo.vulnerabilities)
- 2026-06-11: Motor de scoring de postura (0-100 + grado A-F) en utils/scoring.py
- 2026-06-11: Persistencia de auditorías en SQLite y detección de drift (utils/storage.py)
- 2026-06-11: Comandos CLI cyber audit/diff/history para auditoría continua e histórica
- 2026-06-11: Tests para scoring y persistencia (14 tests en verde)
- 2026-06-11: Score, histórico y diff integrados en el dashboard de Streamlit (pestaña History & Drift)
- 2026-06-11: Épica A — Inventario de activos (SQLite), scheduler de flota y motor de alertas (webhook/Slack/Telegram/email)
- 2026-06-11: Épica B — API REST (FastAPI) con audit/gate/history/diff/assets/fleet + comando `cyber gate` y workflows Trivy y audit-gate
- 2026-06-11: Épica C — Inteligencia de vulnerabilidades (CVE/CVSS vía NVD/OSV), HIBP y expansión de fuentes theHarvester
- 2026-06-11: Épica D — Motor de compliance (OWASP ASVS/CIS/PCI-DSS/NIST) e informe HTML con sparkline de tendencia
- 2026-06-11: Épica E — Autenticación (PBKDF2), RBAC y multi-tenant; login gate opcional en Streamlit
- 2026-06-11: Épica F — Remediación asistida por IA (Claude/Anthropic SDK, modelo claude-opus-4-8) con fallback heurístico
- 2026-06-11: Épica G — Paquete audit_platform separado del arsenal ofensivo; ruff 0 errores (de 371); mypy limpio; gate de cobertura 75% (real 80%); endurecimiento de red Docker; tests CLI typer; Mr.Holmes retirado (deprecado)
- 2026-06-11: Verificación final — 56 tests en verde, ruff/mypy limpios, imágenes Docker reconstruidas y redeploy (dashboard:8501, api:8000) verificados

(Registro generado automáticamente por el asistente durante la sesión.)
