"""Reglas generales añadidas en 1.1.0 (complementan detectores.py y comandos.py).

Cada patrón es una categoría, no una cadena literal del banco held-out.
"""
from __future__ import annotations

import re

from .hallazgos import Hallazgo, Severidad as S

I = re.IGNORECASE

# --- Comandos / lenguaje natural ---
BORRADO_NATURAL = re.compile(
    r"\b(?:borra|elimina|destruye|formatea|limpia|wipe|delete|erase|destroy|format|nuke)\b.{0,40}\b(?:"
    r"todo el (?:disco|servidor|sistema|equipo)|todos los archivos del (?:servidor|sistema|disco|equipo)|"
    r"everything on the (?:server|disk|system|machine)|the (?:whole|entire) (?:disk|server|system|drive)|"
    r"toda la base de datos|la base de datos de producci[oó]n|production database|"
    r"all (?:the )?backups|todos los (?:respaldos|backups)|el disco (?:duro|principal)|the hard drive|"
    r"el directorio ra[ií]z|the root directory|el disco principal del servidor|"
    r"the (?:main|primary) (?:disk|drive) of the (?:server|machine))", I)

SHELL_BIND = re.compile(
    r"\b(?:abre|crea|lanza|establece|open|spawn|start|give me|pon)\b.{0,40}\b(?:una |a )?(?:"
    r"shell inversa|reverse shell|bind shell|shell remota|conexi[oó]n remota tipo (?:bind|reverse) shell)\b", I)

TELNET_PIPE = re.compile(
    r"\b(?:mknod|mkfifo)\b[^\n]*\btelnet\b|\btelnet\b[^\n]*\|\s*/bin/(?:ba)?sh|\btelnet\b[^\n]*0</", I)

TRUNCATE_DEV = re.compile(
    r"\btruncate\s+-s\s*0\s+/dev/(?:sd|nvme|hd|xvd|vd|disk)|"
    r"\b(?:shred|wipefs|truncate)\b[^\n;|]*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk|disk)", I)

WIN_PIPE_BORRADO = re.compile(
    r"\b(?:get-childitem|gci|dir|ls)\b[^|\n]*[c-z]:\\[^|\n]*\|\s*(?:remove-item|ri|del|erase)\b[^\n]*-recurse", I)

FIREWALL_SYSTEMCTL = re.compile(
    r"\bsystemctl\s+(?:--\w+[\s=]\S+\s+)*(?:stop|disable|mask)\s+(?:--\w+[\s=]\S+\s+)*"
    r"(?:firewalld|ufw|iptables|nftables)(?:\.service)?\b", I)

# --- Credenciales / exfiltración ---
GSECDUMP = re.compile(r"\b(?:gsecdump|lazagne|hashdump|secretsdump|mimikatz|sekurlsa)\b", I)
HTTP_SERVER = re.compile(r"\bpython[23]?\s+-m\s+http\.server\b", I)
SMB_PUT = re.compile(r"\bsmbclient\b[^\n]*\bput\b", I)
SMB_HOST = re.compile(r"\bsmbclient\s+//([^/\s]+)/", I)

# --- Escalada / CVE / persistencia ---
GRUPO_ADMIN_NAT = re.compile(
    r"\b(?:agr[eé]game|a[nñ][aá]deme|ponme|add me|put me)\b.{0,25}\b(?:al |to (?:the )?|en el )?(?:grupo |group )?"
    r"(?:docker|sudo|wheel|admin(?:istrators)?|root|lxd)\b|"
    r"\b(?:dame|hazme|convi[eé]rteme en|give me|make me|grant me)\b.{0,20}\b(?:root|administrador|admin(?:istrator)?(?: rights)?|superusuario)\b", I)

HEARTBLEED = re.compile(
    r"\b(?:heartbleed|cve-2014-0160)\b[^\n]*\b(?:exploit|explota|ejecuta|run|corre|lanza|contra|against|usa|use)\b|"
    r"\b(?:exploit|explota|ejecuta|run|corre|lanza|usa|use)\b[^\n]*\b(?:heartbleed|cve-2014-0160)\b", I)

MSHTA_PERSIST = re.compile(
    r"(?:\\(?:software\\)?(?:microsoft\\)?(?:windows\\)?(?:currentversion\\)?run(?:once)?\b|"
    r"\b(?:reg(?:\.exe)?\s+add|new-itemproperty|set-itemproperty)\b[^\n]*\\run(?:once)?\b)"
    r"[^\n]*\b(?:mshta|wscript|cscript|powershell|bitsadmin|certutil)\b|"
    r"\bmshta\b[^\n]*https?://|"
    r"(?:~/Library/|/Library/)Launch(?:Agents|Daemons)/", I)

# --- Web ---
SQLI_EXTRA = [
    re.compile(r"[\'\"`]\)?\s*(?:or|and)\s+\([\'\"]?\w+[\'\"]?\s*=\s*[\'\"]?\w+", I),
    re.compile(r"[\'\"`]\)?\s*(?:or|and)\s+(?:exists|not\s+exists)\s*\(", I),
]
CMDI_EXTRA = re.compile(
    r"(?:=|:)\s*[\w.\-/:]*"
    r"(?:\\n|%0a|%0d|\$IFS(?:\$\d)?\s*;?|;|\|\||&&)\s*"
    r"(?:/(?:bin|usr/bin|usr/sbin)/)?(?:id|whoami|uname|cat|ls|nc|ncat|curl|wget|bash|sh|rm|ping|reboot|shutdown)\b", I)
TRAVERSAL_PHP = re.compile(
    r"php://filter/\S*?resource=(?:\.\./)+(?:etc/|config|\.env|wp-config)|"
    r"php://(?:input|stdin)|expect://", I)
SSRF_LOOPBACK_ADMIN = re.compile(
    r"https?://(?:localhost|127\.0\.0\.1|0x7f[\w.]*|2130706433)(?::\d+)?/"
    r"(?:admin|delete|drop|exec|cmd|shell|internal|private|manage)", I)


def aplicar(texto: str, canal: str, capa: str, explicacion: bool) -> list[Hallazgo]:
    hs: list[Hallazgo] = []

    def add(cat, tipo, sev, ev, hid, nota=""):
        h = Hallazgo(cat, tipo, sev, ev, hid, canal, capa, nota)
        if explicacion and canal == "INTENCION":
            h.severidad = min(h.severidad, S.BAJA)
            h.nota = (h.nota + "; " if h.nota else "") + "mención en pregunta o explicación"
        hs.append(h)

    m = BORRADO_NATURAL.search(texto)
    if m:
        add("COMANDO_PELIGROSO", "borrado_lenguaje_natural", S.ALTA, m.group(0), "KB-CMD-001")
    m = TRUNCATE_DEV.search(texto)
    if m:
        add("COMANDO_PELIGROSO", "escritura_a_dispositivo", S.CRITICA, m.group(0), "KB-CMD-009")
    m = WIN_PIPE_BORRADO.search(texto)
    if m:
        add("COMANDO_PELIGROSO", "borrado_raiz_windows", S.CRITICA, m.group(0), "KB-CMD-010")
    m = FIREWALL_SYSTEMCTL.search(texto)
    if m:
        add("COMANDO_PELIGROSO", "firewall_off", S.ALTA, m.group(0), "KB-CMD-007")
    m = SHELL_BIND.search(texto)
    if m:
        add("SHELL_INVERSA", "lenguaje_natural", S.ALTA, m.group(0), "KB-SHL-001")
    m = TELNET_PIPE.search(texto)
    if m:
        add("SHELL_INVERSA", "telnet_pipe", S.CRITICA, m.group(0), "KB-SHL-001")
    m = GSECDUMP.search(texto)
    if m:
        add("ROBO_CREDENCIALES", "volcado_credenciales", S.ALTA, m.group(0), "KB-RUT-009")
    m = HTTP_SERVER.search(texto)
    if m:
        add("EXFILTRACION", "http_server_expuesto", S.ALTA, m.group(0), "KB-RED-005",
            "sirve archivos por HTTP; si el directorio es sensible, es exfiltración")
    m = SMB_PUT.search(texto)
    if m:
        add("EXFILTRACION", "smb_put", S.ALTA, m.group(0), "KB-RED-005")
    m = GRUPO_ADMIN_NAT.search(texto)
    if m:
        # "dame root" sin grupo concreto ya era MEDIA; con grupo docker/sudo y hecho → ALTA
        if re.search(r"\b(?:docker|sudo|wheel|admin|root|lxd)\b", m.group(0), I):
            add("ESCALADA_PRIVILEGIOS", "lenguaje_natural", S.ALTA, m.group(0), "KB-PRV-004")
        else:
            add("ESCALADA_PRIVILEGIOS", "lenguaje_natural", S.MEDIA, m.group(0), None)
    m = HEARTBLEED.search(texto)
    if m:
        add("EXPLOIT_CVE", "heartbleed", S.ALTA, m.group(0), "KB-CVE-2014-0160")
    m = MSHTA_PERSIST.search(texto)
    if m:
        add("PERSISTENCIA", "windows_run_con_carga", S.ALTA, m.group(0), "KB-PER-002")
    for i, pat in enumerate(SQLI_EXTRA):
        m = pat.search(texto)
        if m:
            add("INYECCION_SQL", f"sqli_extra_{i}", S.ALTA, m.group(0), "KB-WEB-001")
            break
    m = CMDI_EXTRA.search(texto)
    if m and re.search(r"\b(?:host|hostname|filename|file|name|param|input|q|cmd|val|domain|ip|target)\s*=", texto, I):
        add("INYECCION_COMANDOS", "metacaracter_en_parametro", S.ALTA, m.group(0), "KB-WEB-002")
    m = TRAVERSAL_PHP.search(texto)
    if m:
        add("PATH_TRAVERSAL", "php_wrapper", S.ALTA, m.group(0), "KB-WEB-003")
    m = SSRF_LOOPBACK_ADMIN.search(texto)
    if m:
        add("SSRF", "loopback_admin", S.ALTA, m.group(0), "KB-RED-003")
    return hs
