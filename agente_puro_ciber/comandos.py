"""Análisis estructural de comandos (v1.1).

Las expresiones regulares de `detectores.py` dependen del orden de las banderas.
Aquí se parte cada línea en segmentos (; && || |) respetando comillas, se separan
banderas de argumentos y se razona por categoría:

- permisos que dejan escribir a todo el mundo sobre rutas del sistema (chmod 777 -R /etc …);
- servicios de seguridad detenidos, deshabilitados o enmascarados con cualquier opción
  (systemctl mask --now firewalld, service ufw stop, Stop-Service WinDefend, sc config …);
- borrado recursivo después de `cd` a una ruta del sistema (cd /var && rm -rf *);
- borrado recursivo de una raíz de Windows por tubería (Get-ChildItem C:\\ | Remove-Item -Recurse);
- archivado o copia de carpetas de secretos (~/.ssh, ~/.gnupg, ~/.aws …) enviado por tubería
  a un cliente de red (ssh, nc, socat, openssl, curl);
- destinos de nube (s3://, gs://, rclone remoto:) que no están en la lista del dueño.

No ejecuta nada. Devuelve hallazgos con el hecho verificado que los respalda.
"""
from __future__ import annotations

import re
import shlex
from typing import Optional

from .hallazgos import Hallazgo, Severidad as S

I = re.IGNORECASE

RUTAS_SISTEMA = ("/", "/etc", "/usr", "/var", "/boot", "/bin", "/sbin", "/lib", "/lib64", "/home", "/root",
                 "/opt", "/srv", "/sys", "/dev", "/proc", "~", "$HOME", "${HOME}")

SERVICIOS_SEGURIDAD = re.compile(
    r"^(?:firewalld|ufw|iptables|ip6tables|nftables|netfilter-persistent|apparmor|auditd|fail2ban|sshguard|"
    r"clamav[\w-]*|clamd|falcon-sensor|wazuh-agent|ossec|osqueryd|crowdstrike\w*|sentinel\w*|cbagentd|"
    r"mpssvc|windefend|wscsvc|securityhealthservice|sense|wdnissvc|bfe|eventlog|sysmon\w*|selinux)(?:\.service)?$", I)

CLIENTES_RED = re.compile(r"^(?:ssh|nc|ncat|netcat|socat|telnet|openssl|curl|wget|ftp|sftp|tftp|smbclient)$", I)
ARCHIVADORES = re.compile(r"^(?:tar|zip|7z|7za|cpio|gzip|bzip2|xz|base64|xxd|cat|cp|rsync|scp|dd|find)$", I)

DIR_SECRETOS = re.compile(
    r"(?:^|/|~)(?:\.ssh|\.gnupg|\.aws|\.kube|\.docker|\.azure|\.config/gcloud|\.password-store)/?$|"
    r"^/etc/ssl/private/?$|^/var/lib/jenkins/secrets|^/root/?$", I)


def _tokens(seg: str) -> list[str]:
    try:
        return shlex.split(seg, posix=True)
    except ValueError:
        return seg.split()


def segmentos(linea: str) -> list[tuple[str, str]]:
    """[(separador_previo, texto_del_segmento)] respetando comillas."""
    out: list[tuple[str, str]] = []
    try:
        lx = shlex.shlex(linea, posix=True, punctuation_chars=";&|")
        lx.whitespace_split = True
        toks = list(lx)
    except ValueError:
        return [("", linea)]
    sep, actual = "", []
    for tk in toks:
        if tk and set(tk) <= set(";&|"):
            if actual:
                out.append((sep, " ".join(actual)))
            sep, actual = tk, []
        else:
            actual.append(tk)
    if actual:
        out.append((sep, " ".join(actual)))
    return out


def _sin_prefijos(toks: list[str]) -> list[str]:
    while toks and (toks[0] in ("sudo", "doas", "nohup", "time", "nice", "env", "exec", "command", "builtin")
                    or re.fullmatch(r"[A-Za-z_]\w*=\S*", toks[0]) or (toks[0].startswith("-") and len(toks) > 1)):
        toks = toks[1:]
    return toks


def _es_ruta_sistema(arg: str, cwd: Optional[str] = None) -> bool:
    a = arg.strip("'\"")
    if a in ("*", ".", "./*", "./", "*.*") and cwd:
        a = cwd
    a = re.sub(r"/\*+$", "", a) or "/"
    a = a.rstrip("/") or "/"
    if a in RUTAS_SISTEMA:
        return True
    return any(a == r or a.startswith(r + "/") and a.count("/") <= 2 for r in ("/etc", "/usr", "/boot", "/bin", "/sbin", "/lib", "/root")) \
        and not a.startswith(("/usr/local/src", "/etc/nginx/sites", "/var/tmp"))


def _modo_escribible_por_todos(m: str) -> bool:
    if re.fullmatch(r"0?[0-7]{3}", m):
        return m[-1] in "2367"
    if re.fullmatch(r"[0-7]{4}", m):
        return m[-1] in "2367" and m[0] != "1"   # 1777 (sticky, como /tmp) se deja pasar
    return bool(re.fullmatch(r"(?:[ugo]*a[ugo]*|[ugo]*o[ugo]*|)\+[rwxXst]*w[rwxXst]*", m)) or m in ("a+rwx", "ugo+rwx", "o+rwx")


def analizar(linea: str, canal: str, capa: str, nube_confiable: frozenset, lectura_sensible_previa: bool = False) -> list[Hallazgo]:
    hs: list[Hallazgo] = []
    segs = segmentos(linea)
    cwd: Optional[str] = None
    secreto_en_tuberia = False
    for i, (sep, seg) in enumerate(segs):
        toks = _sin_prefijos(_tokens(seg))
        if not toks:
            continue
        cmd = toks[0].rsplit("/", 1)[-1].lower()
        args = toks[1:]
        banderas = [a for a in args if a.startswith("-")]
        posicionales = [a for a in args if not a.startswith("-")]
        if cmd == "cd" and posicionales:
            cwd = posicionales[0]
            continue
        # 1. Permisos escribibles por todos sobre rutas del sistema
        if cmd == "chmod" and posicionales:
            modo, objetivos = posicionales[0], posicionales[1:]
            if _modo_escribible_por_todos(modo) and any(_es_ruta_sistema(o, cwd) for o in objetivos):
                hs.append(Hallazgo("COMANDO_PELIGROSO", "chmod_escribible_sistema", S.ALTA, seg, "KB-CMD-006", canal, capa))
        if cmd == "chown" and any(b in ("-R", "--recursive") for b in banderas) and any(_es_ruta_sistema(o, cwd) for o in posicionales[1:]):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "chown_recursivo_sistema", S.ALTA, seg, "KB-CMD-006", canal, capa))
        # 2. Servicios de seguridad apagados, con cualquier opción
        verbo_apaga = {"stop", "disable", "mask", "kill"}
        if cmd == "systemctl" and any(p.lower() in verbo_apaga for p in posicionales) and any(SERVICIOS_SEGURIDAD.match(p) for p in posicionales):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "servicio_seguridad_apagado", S.ALTA, seg, "KB-CMD-007", canal, capa))
        if cmd == "service" and len(posicionales) >= 2 and SERVICIOS_SEGURIDAD.match(posicionales[0]) and posicionales[1].lower() in ("stop", "disable"):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "servicio_seguridad_apagado", S.ALTA, seg, "KB-CMD-007", canal, capa))
        if cmd in ("update-rc.d", "chkconfig") and posicionales and SERVICIOS_SEGURIDAD.match(posicionales[0]) and \
                any(p.lower() in ("disable", "remove", "off") for p in posicionales[1:]):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "servicio_seguridad_apagado", S.ALTA, seg, "KB-CMD-007", canal, capa))
        if cmd in ("stop-service", "set-service") and any(SERVICIOS_SEGURIDAD.match(p.strip("'\"")) for p in posicionales) and \
                (cmd == "stop-service" or re.search(r"-startuptype\s+disabled|-status\s+stopped", seg, I)):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "servicio_seguridad_apagado", S.ALTA, seg, "KB-CMD-008", canal, capa))
        if cmd in ("sc", "sc.exe") and len(posicionales) >= 2 and posicionales[0].lower() in ("stop", "config", "delete") and \
                SERVICIOS_SEGURIDAD.match(posicionales[1]) and (posicionales[0].lower() != "config" or re.search(r"start\s*=\s*disabled", seg, I)):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "servicio_seguridad_apagado", S.ALTA, seg, "KB-CMD-008", canal, capa))
        # 3. Borrado recursivo relativo a una ruta del sistema (cd /var && rm -rf *)
        if cmd == "rm" and any(re.fullmatch(r"-[a-zA-Z]*[rR][a-zA-Z]*|--recursive", b) for b in banderas) and \
                any(_es_ruta_sistema(o, cwd) for o in posicionales):
            hs.append(Hallazgo("COMANDO_PELIGROSO", "rm_recursivo_sistema", S.CRITICA, seg if not cwd else f"cd {cwd} … {seg}", "KB-CMD-001", canal, capa))
        # 5. Secretos por tubería hacia la red
        if ARCHIVADORES.match(cmd) and any(DIR_SECRETOS.search(p.strip("'\"")) for p in posicionales):
            secreto_en_tuberia = True
        if sep == "|" and CLIENTES_RED.match(cmd) and (secreto_en_tuberia or lectura_sensible_previa):
            hs.append(Hallazgo("ROBO_CREDENCIALES", "secretos_por_tuberia_a_red", S.CRITICA, seg, "KB-RUT-001", canal, capa,
                               "una carpeta de secretos se empaqueta y se manda por un cliente de red"))
        # 6. Destinos de nube fuera de la lista del dueño
        destino = None
        if cmd == "aws" and len(posicionales) >= 3 and posicionales[0] == "s3" and posicionales[1] in ("cp", "sync", "mv"):
            src, dst = posicionales[2], posicionales[-1]
            if not src.startswith("s3://") and dst.startswith("s3://"):
                destino = dst
        elif cmd in ("gsutil", "gcloud") and posicionales:
            gs = [p for p in posicionales if p.startswith("gs://")]
            locales = [p for p in posicionales if not p.startswith("gs://") and p not in ("cp", "rsync", "mv", "storage")]
            if gs and locales and posicionales.index(gs[-1]) > posicionales.index(locales[-1]) and any(p in ("cp", "rsync", "mv") for p in posicionales):
                destino = gs[-1]
        elif cmd == "rclone" and len(posicionales) >= 3 and posicionales[0] in ("copy", "sync", "move", "copyto", "moveto"):
            dst = posicionales[-1]
            if re.match(r"^[\w.-]+:", dst) and not re.match(r"^[a-zA-Z]:\\", dst):
                destino = dst
        elif cmd == "azcopy" and len(posicionales) >= 3 and posicionales[0] in ("copy", "sync"):
            if posicionales[-1].startswith("https://") and not posicionales[1].startswith("https://"):
                destino = posicionales[-1]
        if destino:
            nombre = re.sub(r"^(?:s3|gs)://", "", destino).split("/")[0].split(":")[0].lower()
            nombre = re.sub(r"^https://([\w-]+)\.blob\.core\.windows\.net.*", r"\1", nombre)
            if nombre not in nube_confiable:
                hs.append(Hallazgo("EXFILTRACION", "nube_no_confiable", S.ALTA, f"{seg[:60]} → {destino}", "KB-RED-005", canal, capa,
                                   "copia de datos a un bucket o remoto que no está en la lista del dueño"))
    # 4. Raíz de Windows borrada por tubería (se mira la línea cruda: shlex se come las «\\»)
    m = re.search(r"\b(?:get-childitem|gci|dir|ls)\s+['\"]?[a-z]:\\['\"]?(?:\s[^|\n]*)?\|\s*(?:remove-item|ri|del|rm|erase)\b[^\n]*-recurse", linea, I)
    if m:
        hs.append(Hallazgo("COMANDO_PELIGROSO", "borrado_raiz_windows", S.CRITICA, m.group(0), "KB-CMD-010", canal, capa))
    # 5b. Secretos → red aunque vengan dentro de printf/echo/comillas (capas hex/base64)
    m = re.search(
        r"(?:~|/root|/home/[\w.-]+)?/?\.ssh\b[^\n]{0,40}\|\s*(?:ssh|nc|ncat|netcat|socat|curl|openssl)\b|"
        r"(?:tar|zip|cpio|cat|base64)\b[^\n]{0,60}\.ssh\b[^\n]{0,40}\|\s*(?:ssh|nc|ncat|netcat|socat|curl)\b",
        linea, I)
    if m:
        hs.append(Hallazgo("ROBO_CREDENCIALES", "secretos_por_tuberia_a_red", S.CRITICA, m.group(0), "KB-RUT-001", canal, capa,
                           "una carpeta de secretos se manda por un cliente de red"))
    return hs
