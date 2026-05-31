# MHcheck Improvement Roadmap

Este documento lista tareas propuestas, priorizadas y las nuevas integraciones OSINT solicitadas.

- ## Estado actual
- [ ] Tareas completadas: ver `done.md` (registro histórico)

## Tareas prioritarias (Alta)
- [x] Actualizar `todo.md` con tareas detalladas
- [x] Integrar `theHarvester` (módulo wrapper): crear `utils/osint/theharvester.py`, envolver consultas DNS, emails, subdominios.
- [x] Integrar `Mr.Holmes` (módulo wrapper): crear `utils/osint/mrholmes.py`, exponer detección e indicadores relevantes.
- [x] Integración Shodan API: crear `utils/osint/shodan_client.py`, soportar búsquedas, host lookup y límites de rate.
- [x] Escribir tests para integraciones OSINT (pytest + fixtures de mock)

## Tareas de calidad y refactor (Media)
- [x] Añadir CLI (`typer`) para ejecutar presets y módulos OSINT sin Streamlit
- [x] Validación de `config.json` y `presets` con `pydantic`
- [x] Añadir CI (GitHub Actions) para lint/tests/builds (ruff, black, mypy, pytest)
- [x] Configurar `pre-commit` (ruff, black, isort)

## Observabilidad, seguridad y documentación (Baja/Medio)
- [x] Exponer métricas Prometheus y endpoints de health/readiness (implementado en `utils/security.py`)
- [x] Añadir límites de seguridad y checks de recursos (CPU/RAM/concurrency) (implementado en `utils/security.py`)
- [x] Documentación: `README.md` (ejemplos de OSINT), `CONTRIBUTING.md`, `CHANGELOG.md`
- [x] Integrar módulos OSINT en app Streamlit

## Notas sobre integraciones OSINT
- theHarvester: se puede invocar por CLI o envolver sus módulos. Preferible implementar como wrapper que normalice outputs (json) y gestione timeouts.
- Mr.Holmes: evaluar opciones para importar como dependencia o ejecutar como proceso aislado; normalizar salidas.
- Shodan: requiere clave API; añadir configuración segura en `config.json` y comprobar límites.

Si quieres, implemento una de las integraciones (theHarvester/Mr.Holmes/Shodan) ahora como primer PR. Indica cuál prefieres arrancar primero.
