# Changelog

## 1.1.0 — 2026-11-14

Arreglos de categorías generales tras el held-out de 0.1.0, y un tercer banco limpio.

### Arreglos (categorías, no literales)
- `comandos.py` (nuevo): análisis estructural por tokens (chmod con cualquier orden de banderas sobre rutas del sistema; systemctl/service/sc con opciones intercaladas sobre servicios de seguridad; `cd` + `rm -rf *`; tubería Windows; secretos empaquetados hacia ssh/nc; destinos `s3://` / `gs://` / rclone / azcopy fuera de la lista del dueño).
- `reglas_v11.py` (nuevo): bind shell, telnet pipe, Heartbleed, SQLi `EXISTS` / `OR ('a'='a`, `php://filter`, `python -m http.server`, `smbclient put`, `reg …\Run` + mshta, «agrégame al grupo docker», formateo del disco principal, etc.
- Lectura de `~/.ssh/*.pub` ya no se trata como secreto.
- El held-out original (semilla 20261231) **quedó contaminado** porque se usó para guiar estos arreglos. Se sigue reportando, etiquetado.

### Congelación y held-out 2
- Código 1.1.0 congelado: SHA-256 `804c1d63de978d9de22af8543655e4ba578371710ef465906e97fcd0e057b7be` (sobre `agente_puro_ciber/*.py`).
- `eval/banco_heldout2.py` (semilla 20270101, 325 casos) escrito después, corrido una vez, sin ajustes posteriores.
- Held-out 2: detección 77.6 %, PERMITIR en maliciosos 6, falsos positivos 0, ejecuciones no autorizadas 0.

### Pruebas
- 174 unittest (113 CVA + 61 de la especialidad, incluidas las de los arreglos 1.1).
- Demo 9/9.

## 0.1.0 — 2026-11-14

Primera versión. Ver historial anterior en el tarball 0.1.0 si se conserva.
