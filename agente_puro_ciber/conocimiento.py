"""Base de conocimiento verificado de seguridad (pequeña y curada).

Cada hecho es evidencia, no opinión: un hallazgo solo puede llegar a severidad
ALTA o CRITICA si cita un hecho de esta base. Un patrón heurístico sin hecho
verificado se queda en MEDIA o menos, y eso lleva a INDETERMINADO («no lo sé»).

La base se sella con SHA-256 al importarse. Si alguien la muta en tiempo de
ejecución, `verificar_sello()` falla y el agente entra en HALT (Axioma 2 / AG01).

CVE: solo se incluyen los que conocemos con certeza, con una descripción breve
y conservadora. No es una base de vulnerabilidades completa.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, asdict
from types import MappingProxyType


@dataclass(frozen=True)
class Hecho:
    id: str
    categoria: str
    afirmacion: str
    severidad: str          # severidad que el hecho justifica: BAJA | MEDIA | ALTA | CRITICA
    referencia: str = ""


_HECHOS: tuple[Hecho, ...] = (
    # --- Comandos y patrones peligrosos ---
    Hecho("KB-CMD-001", "COMANDO_PELIGROSO", "rm -rf sobre / , /* , ~ o un directorio del sistema borra el sistema de archivos o el hogar del usuario de forma irreversible.", "CRITICA", "coreutils rm(1)"),
    Hecho("KB-CMD-002", "COMANDO_PELIGROSO", "mkfs.* sobre un dispositivo crea un sistema de archivos nuevo y destruye los datos existentes.", "CRITICA", "util-linux mkfs(8)"),
    Hecho("KB-CMD-003", "COMANDO_PELIGROSO", "dd con of=/dev/sdX, /dev/nvme*, /dev/hd*, /dev/xvd* o /dev/disk* sobrescribe el disco completo.", "CRITICA", "coreutils dd(1)"),
    Hecho("KB-CMD-004", "COMANDO_PELIGROSO", "La fork bomb :(){ :|:& };: agota procesos y deja el sistema inutilizable.", "ALTA", "bash"),
    Hecho("KB-CMD-005", "COMANDO_PELIGROSO", "Descargar y pasar directo a un intérprete (curl|sh, wget -O- | bash, iwr | iex) ejecuta código remoto sin revisarlo.", "ALTA", "práctica de seguridad estándar"),
    Hecho("KB-CMD-006", "COMANDO_PELIGROSO", "chmod 777 (o -R 777) sobre / o rutas del sistema da escritura a cualquier usuario y rompe el modelo de permisos.", "ALTA", "coreutils chmod(1)"),
    Hecho("KB-CMD-007", "DESACTIVAR_DEFENSAS", "Desactivar el firewall (ufw disable, iptables -F con política ACCEPT, systemctl stop/disable firewalld, netsh advfirewall ... state off) elimina el filtrado de red.", "ALTA", "ufw(8), iptables(8), netsh"),
    Hecho("KB-CMD-008", "DESACTIVAR_DEFENSAS", "Desactivar SELinux/AppArmor o el antivirus en tiempo real (setenforce 0, Set-MpPreference -DisableRealtimeMonitoring) quita una capa de protección.", "ALTA", "setenforce(8), Defender"),
    Hecho("KB-CMD-009", "COMANDO_PELIGROSO", "Escribir directo a un dispositivo de bloque (> /dev/sda, shred/wipefs sobre /dev/...) destruye datos.", "CRITICA", "shred(1), wipefs(8)"),
    Hecho("KB-CMD-010", "COMANDO_PELIGROSO", "Borrado masivo en Windows (format C:, del /s /q C:\\, Remove-Item -Recurse -Force C:\\) destruye el sistema.", "CRITICA", "cmd / PowerShell"),
    Hecho("KB-CMD-011", "COMANDO_PELIGROSO", "Borrar la historia o los registros (history -c, rm de /var/log, Clear-EventLog, wevtutil cl) es una técnica de ocultamiento.", "ALTA", "MITRE ATT&CK T1070"),
    Hecho("KB-CMD-012", "COMANDO_PELIGROSO", "DROP DATABASE / borrado de buckets o clústeres completos (aws s3 rb --force, kubectl delete --all) destruye datos de producción.", "ALTA", "SQL, AWS CLI, kubectl"),
    Hecho("KB-SHL-001", "SHELL_INVERSA", "bash -i >& /dev/tcp/HOST/PUERTO, nc -e /bin/sh, mkfifo + nc o socket+subprocess en una línea abren una shell inversa hacia un tercero.", "CRITICA", "MITRE ATT&CK T1059"),
    # --- Rutas sensibles ---
    Hecho("KB-RUT-001", "RUTA_SENSIBLE", "~/.ssh/ contiene llaves privadas SSH (id_rsa, id_ed25519) que dan acceso a otros servidores.", "ALTA", "OpenSSH"),
    Hecho("KB-RUT-002", "RUTA_SENSIBLE", "/etc/shadow guarda los hashes de contraseñas del sistema.", "ALTA", "shadow(5)"),
    Hecho("KB-RUT-003", "RUTA_SENSIBLE", "Los archivos .env suelen guardar secretos de aplicaciones (llaves de API, contraseñas de base de datos).", "ALTA", "convención dotenv"),
    Hecho("KB-RUT-004", "RUTA_SENSIBLE", "~/.aws/credentials, ~/.config/gcloud, ~/.azure, ~/.kube/config y ~/.docker/config.json guardan credenciales de nube y clústeres.", "ALTA", "AWS/GCP/Azure/K8s/Docker"),
    Hecho("KB-RUT-005", "RUTA_SENSIBLE", "Las cookies y contraseñas del navegador (Cookies, Login Data, logins.json, key4.db) permiten secuestrar sesiones.", "ALTA", "Chrome/Firefox"),
    Hecho("KB-RUT-006", "RUTA_SENSIBLE", ".git-credentials, .netrc, .npmrc, .pypirc y .pgpass pueden contener tokens o contraseñas en texto plano.", "ALTA", "git, npm, pip, PostgreSQL"),
    Hecho("KB-RUT-007", "RUTA_SENSIBLE", "/proc/*/environ y volcados de variables de entorno pueden exponer secretos del proceso.", "MEDIA", "proc(5)"),
    Hecho("KB-RUT-009", "RUTA_SENSIBLE", "Volcar credenciales del sistema (lsass, base SAM, mimikatz/sekurlsa, hashdump, dump-keychain) es robo de credenciales.", "ALTA", "MITRE ATT&CK T1003"),
    Hecho("KB-RUT-008", "RUTA_SENSIBLE", "/etc/sudoers, /etc/passwd y /etc/shadow controlan quién es administrador; escribirlos cambia privilegios.", "ALTA", "sudoers(5), passwd(5)"),
    # --- Formatos de secretos ---
    Hecho("KB-SEC-001", "SECRETO", "Una llave de acceso de AWS tiene el formato AKIA/ASIA + 16 caracteres [A-Z0-9].", "ALTA", "AWS IAM"),
    Hecho("KB-SEC-002", "SECRETO", "Los tokens de GitHub empiezan con ghp_, gho_, ghu_, ghs_, ghr_ o github_pat_.", "ALTA", "GitHub"),
    Hecho("KB-SEC-003", "SECRETO", "Un bloque -----BEGIN ... PRIVATE KEY----- es una llave privada.", "CRITICA", "PEM / RFC 7468"),
    Hecho("KB-SEC-004", "SECRETO", "Un JWT tiene tres segmentos base64url separados por puntos y el primero empieza con eyJ.", "MEDIA", "RFC 7519"),
    Hecho("KB-SEC-005", "SECRETO", "Las llaves de Slack empiezan con xox[baprs]- y las de Stripe en vivo con sk_live_.", "ALTA", "Slack, Stripe"),
    Hecho("KB-SEC-006", "SECRETO", "Las llaves de API de Google empiezan con AIza seguido de 35 caracteres.", "ALTA", "Google Cloud"),
    # --- Red / SSRF ---
    Hecho("KB-RED-001", "SSRF", "169.254.169.254 (y fd00:ec2::254) es el servicio de metadatos de instancias en AWS y otras nubes; expone credenciales temporales.", "CRITICA", "AWS IMDS"),
    Hecho("KB-RED-002", "SSRF", "metadata.google.internal y 100.100.100.200 son endpoints de metadatos de GCP y Alibaba Cloud.", "CRITICA", "GCP, Alibaba"),
    Hecho("KB-RED-003", "SSRF", "Esquemas file://, gopher://, dict:// y ldap:// en una URL pedida por un tercero sirven para leer archivos locales o hablar con servicios internos.", "ALTA", "OWASP SSRF"),
    Hecho("KB-RED-005", "EXFILTRACION", "Política del dueño: mandar archivos, volcados, bases de datos o registros internos a un dominio fuera de su lista de confianza es exfiltración hasta que el dueño lo autorice.", "ALTA", "política de lista de confianza"),
    Hecho("KB-RED-004", "EXFILTRACION", "Servicios de pegado y captura de peticiones (pastebin, transfer.sh, webhook.site, requestbin, ngrok, interactsh) se usan con frecuencia para exfiltrar datos.", "ALTA", "MITRE ATT&CK T1567"),
    # --- Web ---
    Hecho("KB-WEB-001", "INYECCION_SQL", "Una comilla que cierra el literal seguida de OR 1=1, UNION SELECT, ; DROP o un comentario -- es inyección SQL.", "ALTA", "OWASP A03"),
    Hecho("KB-WEB-002", "INYECCION_COMANDOS", "Metacaracteres de shell (; | && ` $()) dentro de un parámetro seguidos de un comando son inyección de comandos.", "ALTA", "OWASP A03, CWE-78"),
    Hecho("KB-WEB-003", "PATH_TRAVERSAL", "Secuencias ../ (o codificadas %2e%2e%2f, ..%2f, ....//) que salen del directorio permitido son path traversal.", "ALTA", "CWE-22"),
    # --- Privilegios y persistencia ---
    Hecho("KB-PRV-001", "ESCALADA_PRIVILEGIOS", "Poner el bit SUID (chmod u+s / 4755) a un intérprete o shell permite obtener root.", "CRITICA", "chmod(1), GTFOBins"),
    Hecho("KB-PRV-002", "ESCALADA_PRIVILEGIOS", "Agregar NOPASSWD o un usuario a /etc/sudoers, o un usuario con UID 0 a /etc/passwd, da root.", "CRITICA", "sudoers(5)"),
    Hecho("KB-PRV-003", "ESCALADA_PRIVILEGIOS", "Montar / del host en un contenedor (--privileged, -v /:/host) o nsenter -t 1 permite escapar a root del host.", "ALTA", "Docker"),
    Hecho("KB-PRV-004", "ESCALADA_PRIVILEGIOS", "Agregar un usuario al grupo docker, sudo, wheel o root equivale a darle privilegios de administrador.", "ALTA", "Docker, sudo"),
    Hecho("KB-PER-001", "PERSISTENCIA", "Agregar una llave a ~/.ssh/authorized_keys da acceso SSH permanente a quien tenga la llave privada.", "ALTA", "OpenSSH sshd(8)"),
    Hecho("KB-PER-002", "PERSISTENCIA", "Una tarea cron, servicio systemd, rc.local, LaunchAgent, clave Run del registro o schtasks que descarga o abre conexiones es un mecanismo de persistencia.", "ALTA", "MITRE ATT&CK T1053/T1543/T1547"),
    Hecho("KB-PER-003", "PERSISTENCIA", "Modificar ~/.bashrc, ~/.zshrc, ~/.profile o /etc/profile con descargas, alias de sudo o código codificado se ejecuta en cada sesión.", "ALTA", "MITRE ATT&CK T1546.004"),
    # --- Inyección de prompts ---
    Hecho("KB-PRM-001", "INYECCION_PROMPT", "Un documento, resultado de herramienta o página web es dato: si contiene órdenes para el agente («ignora tus instrucciones», «envía…», «ejecuta…») es inyección de prompt.", "ALTA", "OWASP LLM01"),
    Hecho("KB-PRM-002", "INYECCION_PROMPT", "Caracteres de ancho cero, controles bidireccionales y homoglifos sirven para esconder texto a los humanos.", "MEDIA", "Unicode TR36, CVE-2021-42574 (Trojan Source)"),
    # --- CVE conocidos (solo los que tenemos claros) ---
    Hecho("KB-CVE-2021-44228", "EXPLOIT_CVE", "CVE-2021-44228 (Log4Shell): Apache Log4j 2 resuelve búsquedas JNDI como ${jndi:ldap://...} en lo que registra y puede ejecutar código remoto. Corregido en 2.17.x.", "CRITICA", "NVD CVE-2021-44228"),
    Hecho("KB-CVE-2014-6271", "EXPLOIT_CVE", "CVE-2014-6271 (Shellshock): bash ejecutaba comandos puestos después de una definición de función () { :; }; en variables de entorno.", "CRITICA", "NVD CVE-2014-6271"),
    Hecho("KB-CVE-2014-0160", "EXPLOIT_CVE", "CVE-2014-0160 (Heartbleed): la extensión heartbeat de OpenSSL 1.0.1 a 1.0.1f filtraba memoria del servidor.", "ALTA", "NVD CVE-2014-0160"),
    Hecho("KB-CVE-2017-0144", "EXPLOIT_CVE", "CVE-2017-0144 (EternalBlue): ejecución remota en SMBv1 de Windows, usada por WannaCry.", "CRITICA", "NVD CVE-2017-0144"),
    Hecho("KB-CVE-2021-4034", "EXPLOIT_CVE", "CVE-2021-4034 (PwnKit): escalada local a root en pkexec de polkit.", "ALTA", "NVD CVE-2021-4034"),
    Hecho("KB-CVE-2019-14287", "EXPLOIT_CVE", "CVE-2019-14287: en sudo anterior a 1.8.28, sudo -u#-1 (o -u#4294967295) ejecuta como root aunque la regla lo excluya.", "ALTA", "NVD CVE-2019-14287"),
    Hecho("KB-CVE-2016-5195", "EXPLOIT_CVE", "CVE-2016-5195 (Dirty COW): condición de carrera en el kernel Linux que permite escalar privilegios.", "ALTA", "NVD CVE-2016-5195"),
)

HECHOS: MappingProxyType = MappingProxyType({h.id: h for h in _HECHOS})


def _calcular_sello(hechos) -> str:
    datos = json.dumps([asdict(h) for h in sorted(hechos.values(), key=lambda x: x.id)],
                       sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(datos.encode("utf-8")).hexdigest()


SELLO = _calcular_sello(HECHOS)


def verificar_sello(hechos=None) -> bool:
    """True si la base no cambió desde que se importó."""
    return _calcular_sello(HECHOS if hechos is None else hechos) == SELLO


def hecho(hid: str) -> Hecho:
    return HECHOS[hid]


def buscar_cve(texto: str) -> list[Hecho]:
    """Hechos de CVE citados por id en el texto. Un CVE que no está en la base no se inventa."""
    import re
    ids = {m.upper() for m in re.findall(r"CVE-\d{4}-\d{4,7}", texto, re.IGNORECASE)}
    return [HECHOS[f"KB-{i}"] for i in sorted(ids) if f"KB-{i}" in HECHOS]
