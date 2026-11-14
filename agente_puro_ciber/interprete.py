"""Intérprete de la especialidad: SOLO propone órdenes de la lista cerrada.

No ejecuta, no firma tokens, no lee la llave HMAC. Reconoce un conjunto finito
de tareas de seguridad y administración legítimas (leer logs propios, escanear,
consultar estado, actualizar, bloquear una IP...). Si no reconoce la tarea, no
propone nada, y el agente responde INDETERMINADO: no se permite lo que no se entiende.
"""
from __future__ import annotations

import re
import shlex

from .acciones import AccionCiber as A
from .detectores import (EXPLICACION, ENVIO_NATURAL, _clasificar_host, _dominio_confiable,
                         destinos_en, urls_en)

# Comandos de lectura, diagnóstico, defensa o mantenimiento que el intérprete reconoce.
# Estar aquí NO los autoriza: igual pasan por los detectores, y luego por el token.
COMANDOS_RECONOCIDOS = {
    "ls", "cat", "grep", "egrep", "zgrep", "fgrep", "rg", "tail", "head", "less", "more", "wc", "sort", "uniq", "cut",
    "awk", "sed", "tr", "jq", "journalctl", "systemctl", "service", "ps", "top", "htop", "pgrep", "df", "du", "free",
    "uptime", "uname", "hostname", "whoami", "id", "w", "who", "last", "lastb", "lastlog", "ss", "netstat", "lsof", "ip",
    "ifconfig", "ping", "traceroute", "tracepath", "mtr", "dig", "nslookup", "host", "whois", "curl", "wget", "openssl",
    "sha256sum", "sha1sum", "md5sum", "gpg", "apt", "apt-get", "dnf", "yum", "pip", "pip3", "pip-audit", "npm", "yarn",
    "git", "docker", "kubectl", "helm", "crontab", "ufw", "iptables", "nft", "fail2ban-client", "auditctl", "ausearch",
    "aureport", "aide", "clamscan", "freshclam", "rkhunter", "chkrootkit", "lynis", "trivy", "grype", "syft", "semgrep",
    "bandit", "gitleaks", "trufflehog", "nmap", "tcpdump", "tshark", "find", "chmod", "chown", "tar", "gzip", "gunzip",
    "zip", "unzip", "cp", "mv", "mkdir", "touch", "ssh", "ssh-keygen", "ssh-copy-id", "scp", "logrotate", "certbot",
    "python", "python3", "pytest", "make", "echo", "date", "stat", "file", "getfacl", "sestatus", "aa-status", "getenforce",
    "osqueryi", "yara", "suricata", "zeek", "wazuh-control", "vmstat", "iostat", "dmesg", "lsblk", "blkid", "mount",
    "timedatectl", "hostnamectl", "loginctl", "passwd", "chage", "faillock", "pam_tally2", "visudo", "sudo", "nginx",
    "apachectl", "testssl.sh", "sslscan", "nikto", "zap-baseline.py", "brew", "snap", "flatpak", "terraform", "aws",
    "gcloud", "az", "psql", "mysql", "sqlite3", "redis-cli", "watch", "diff", "cmp", "basename", "dirname", "realpath",
    "readlink", "xargs", "tee", "printf", "nc", "base64", "test", "true", "history", "type", "which", "whereis", "man",
    "lsattr", "chattr", "setfacl", "umask", "groups", "getent", "dpkg", "rpm", "needrestart", "unattended-upgrade",
    "unattended-upgrades", "Get-EventLog", "Get-WinEvent", "Get-Process", "Get-Service", "Get-NetTCPConnection",
    "Get-MpComputerStatus", "Start-MpScan", "Update-MpSignature", "Get-LocalUser", "Get-FileHash", "netsh", "rm", "for", "while",
    "do", "done", "useradd", "usermod", "gpasswd", "userdel", "groupadd", "mysqldump", "pg_dump", "rsync", "sftp", "kill", "pkill",
}

INTENCION_DEFENSIVA = re.compile(
    r"\b(?:revisa|analiza|lee|l[eé]eme|muestra|mu[eé]strame|lista|enlista|verifica|comprueba|checa|chequea|consulta|resume|res[uú]meme|explica|"
    r"genera|crea un reporte|haz un reporte|cuenta|busca|encuentra|monitorea|vigila|actualiza|parchea|aplica|instala|rota|renueva|configura|habilita|"
    r"activa|respalda|cifra|endurece|audita|escanea|investiga|correlaciona|compara|calcula|valida|documenta|prepara|redacta|dime|ens[eé][nñ]ame|"
    r"review|analy[sz]e|read|show|list|check|verify|summari[sz]e|explain|generate|create a report|count|search|find|monitor|update|patch|apply|"
    r"install|rotate|renew|configure|enable|backup|back up|encrypt|harden|audit|scan|investigate|correlate|compare|calculate|validate|document|"
    r"prepare|draft|tell me|teach me|help me|ay[uú]dame|bloquea|block|revoca|revoke|pon en cuarentena|quarantine|alerta|alert|notifica|notify|"
    r"reporta|report|inspecciona|inspect|identifica|identify|detecta|detect|mide|measure|eval[uú]a|evaluate|reinicia|restart|recarga|reload|"
    r"agrega|a[nñ]ade|add|programa|schedule|cambia|change|desactiva la cuenta|disable the account|"
    r"traduce|translate|clasifica|classify|prioriza|prioritize|escribe|write|crea|create|descarga|download|consulta|query|"
    r"copia|copy|comparte|share)\b", re.I)

PREGUNTA = re.compile(r"^\s*[¿]|\?\s*$|\b(?:necesito saber|quiero saber|i need to know|i want to know)\b|^\s*(?:qu[eé]|c[oó]mo|cu[aá]l(?:es)?|por qu[eé]|cu[aá]ndo|d[oó]nde|es |what|how|which|why|when|where|is |are |does |do |can )", re.I)
ESCANEO = re.compile(r"\b(?:escanea|escaneo|scan|audita|audit|busca (?:malware|virus|secretos|vulnerabilidades|rootkits|credenciales expuestas|llaves expuestas)|"
                     r"look for (?:malware|secrets|vulnerabilities)|search for (?:malware|secrets|vulnerabilities)|en busca de|for (?:malware|secrets|vulnerabilities|exposed))\b", re.I)
_IP = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?)\b")
_RUTA = re.compile(r"(?<![\w.])((?:~|\.{1,2})?/[\w.\-/*]+|[\w.-]+/[\w.\-/]+|[\w-]+\.(?:log|txt|json|csv|yaml|yml|conf|cfg|ini|py|js|md|pcap|xml|html))")


def _segmentos(cmd: str) -> list[str]:
    """Parte en comandos por ; | && || respetando comillas."""
    try:
        lx = shlex.shlex(cmd.strip(), posix=True, punctuation_chars=";&|")
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return [p for p in re.split(r"\s*(?:\|\||&&|;|\|)\s*", cmd.strip()) if p]
    segs, actual = [], []
    for tk in toks:
        if tk and set(tk) <= set(";&|"):
            if actual:
                segs.append(" ".join(shlex.quote(x) for x in actual))
            actual = []
        else:
            actual.append(tk)
    if actual:
        segs.append(" ".join(shlex.quote(x) for x in actual))
    return segs


def _primer_comando(seg: str) -> str:
    try:
        toks = shlex.split(seg, posix=True)
    except ValueError:
        toks = seg.split()
    previo = ""
    while toks and (re.fullmatch(r"[A-Za-z_]\w*=\S*", toks[0]) or toks[0] in ("sudo", "nice", "time", "env", "nohup", "-E")):
        previo = toks[0]
        toks = toks[1:]
    if toks and toks[0].startswith("-") and previo == "sudo":
        return "sudo"   # sudo -l, sudo -v: opciones de sudo, no otro comando
    return toks[0] if toks else previo


def es_comando(texto: str) -> bool:
    t = texto.strip().strip("`")
    primero = _primer_comando(_segmentos(t)[0]) if _segmentos(t) else ""
    if not primero or re.match(r"^\s*(?:[¿]|por favor\b|please\b)", t, re.I) or INTENCION_DEFENSIVA.match(t):
        return False
    if primero in COMANDOS_RECONOCIDOS or primero.startswith(("./", "/", "~/", "$")):
        return True
    # Palabra suelta + banderas o metacaracteres de shell: parece comando aunque no lo conozcamos.
    return bool(re.fullmatch(r"[A-Za-z][\w.+-]*", primero)) and bool(re.search(r"\s-{1,2}\w|[|;&<>$`]|^\S+\s+/", t))


# Intérpretes y make corren código que el agente no ve: solo se reconocen usos conocidos.
_INTERPRETES_OK = re.compile(r"^\s*(?:sudo\s+)?(?:python[23]?(?:\.\d+)?\s+-m\s+(?:pytest|unittest|pip|venv|pip_audit|bandit|json\.tool)\b|make\s+(?:test|tests|check|lint|audit)\b)")


def _segmento_ok(seg: str) -> bool:
    cmd = _primer_comando(seg)
    if cmd in ("python", "python3", "make"):
        return bool(_INTERPRETES_OK.match(seg))
    return cmd in COMANDOS_RECONOCIDOS


def comando_reconocido(texto: str) -> bool:
    segs = _segmentos(texto.strip().strip("`"))
    return bool(segs) and all(_segmento_ok(s) for s in segs)


def proponer(texto: str, confiables) -> list[tuple[A, dict]]:
    """Devuelve propuestas (acción, parámetros). Lista vacía = «no entiendo la tarea»."""
    t = (texto or "").strip()
    if not t:
        return []
    props: list[tuple[A, dict]] = []
    bajo = t.lower()

    # 1. Comando de shell literal.
    if es_comando(t):
        if comando_reconocido(t):
            return [(A.COMANDO_SIMULADO, {"comando": t})]
        return []

    # 2. Acciones defensivas pedidas por el iniciador.
    if re.search(r"\b(?:revoca|revocar|revoke)\b", bajo):
        m = re.search(r"\b(?:token|tok)[\s:#-]*([A-Za-z0-9_-]{4,})", t)
        props.append((A.REVOCAR_TOKEN, {"token_id": m.group(1) if m else "sesion"}))
    if re.search(r"\b(?:bloquea|block|banea|ban|deny|niega)\b", bajo):
        ip = _IP.search(t)
        if ip:
            props.append((A.BLOQUEAR_ACCION, {"huella": f"ip:{ip.group(1)}", "motivo": t[:200]}))
    if re.search(r"\b(?:cuarentena|quarantine|a[ií]sla el archivo|isolate the file)\b", bajo):
        r = _RUTA.search(t)
        if r:
            props.append((A.CUARENTENA_ARCHIVO, {"ruta": r.group(1), "motivo": t[:200], "contenido": ""}))
    if re.search(r"\b(?:alerta|alert|notifica|notify|avisa)\b", bajo) and not ENVIO_NATURAL.search(t):
        props.append((A.ALERTAR, {"severidad": "MEDIA", "mensaje": t[:300]}))
    if ESCANEO.search(t):
        r = _RUTA.search(t)
        props.append((A.ESCANEAR, {"objetivo": r.group(1).lstrip("~/") if r else "archivos"}))
    if props:
        return props

    # 3. Envío a un destino de confianza.
    destinos = destinos_en(t)
    if ENVIO_NATURAL.search(t) and destinos:
        if all(_dominio_confiable(d, confiables) for d in destinos):
            correo = re.search(r"[\w.+-]+@[\w.-]+", t)
            return [(A.ENVIAR, {"destinatario": correo.group(0) if correo else destinos[0], "cuerpo": t[:500]})]
        return []

    # 4. Consulta de una URL (solo lectura, simulada).
    urls = urls_en(t)
    if urls and re.search(r"\b(?:descarga|consulta|abre|visita|revisa|lee|baja|fetch|get|download|open|visit|check|read)\b", bajo):
        url, esquema, host = urls[0]
        if esquema in ("http", "https") and _clasificar_host(host)[0] in ("PUBLICA", "NOMBRE", "LOOPBACK"):
            return [(A.CONSULTAR_URL, {"url": url})]
        return []

    # 5. Lectura de logs u otros recursos no sensibles.
    if re.search(r"\b(?:logs?|registros?|bit[aá]cora|journal|eventos|events|auth\.log|syslog|access\.log|error\.log)\b", bajo) and \
       re.search(r"\b(?:lee|l[eé]eme|revisa|analiza|muestra|mu[eé]strame|resume|busca|cuenta|read|review|analy[sz]e|show|summari[sz]e|search|count|check|tail|correlaciona|correlate|investiga|investigate|filtra|filter|extrae|extract)\b", bajo):
        r = _RUTA.search(t)
        return [(A.LEER_RECURSO, {"recurso_id": r.group(1) if r else "logs"}), (A.REPORTAR, {"resumen": t[:300]})]

    # 6. Preguntas, explicaciones y tareas de seguridad descritas en lenguaje natural.
    if PREGUNTA.search(t) or EXPLICACION.search(t) or INTENCION_DEFENSIVA.search(t) or \
       re.search(r"\bhaz (?:un|una|el|la) (?:inventario|an[aá]lisis|reporte|informe|respaldo|resumen|escaneo|diagn[oó]stico|auditor[ií]a|revisi[oó]n)\b", t, re.I):
        return [(A.REPORTAR, {"resumen": t[:300]})]
    return []
