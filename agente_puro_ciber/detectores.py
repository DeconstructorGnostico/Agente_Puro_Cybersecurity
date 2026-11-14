"""Detectores de la especialidad de ciberseguridad.

Cada detector devuelve hallazgos tipados (categoría, tipo, severidad, evidencia,
hecho verificado que lo respalda). Ningún detector ejecuta nada ni decide: solo
observa. La decisión la toma `agente.py` con reglas fijas.

Se leen todas las capas de `normalizar.leer` (original, normalizado, URL, hex,
base64, tags Unicode). Así un comando escondido en base64 o con ancho cero se ve.
"""
from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Iterable, Optional
from urllib.parse import urlsplit, unquote

from .hallazgos import Hallazgo, Severidad as S
from .normalizar import Lectura

I = re.IGNORECASE

# ---------------------------------------------------------------------------
# Contexto
# ---------------------------------------------------------------------------

DOMINIOS_CONFIABLES_POR_DEFECTO = frozenset({
    "empresa.local", "corp.example", "github.com", "gitlab.com", "pypi.org",
    "files.pythonhosted.org", "registry.npmjs.org", "ubuntu.com", "debian.org",
    "python.org", "archive.ubuntu.com", "security.ubuntu.com", "docker.io",
    "localhost",
})

SERVICIOS_EXFIL = re.compile(
    r"(pastebin\.com|paste\.ee|hastebin|ghostbin|transfer\.sh|file\.io|0x0\.st|webhook\.site|"
    r"requestbin|pipedream\.net|ngrok\.(io|app|dev)|ngrok-free\.app|interact\.sh|oast\.(fun|pro|live|site|online|me)|"
    r"burpcollaborator\.net|canarytokens|discord(app)?\.com/api/webhooks|api\.telegram\.org/bot|"
    r"anonfiles|mega\.nz|temp\.sh|termbin\.com|requestcatcher\.com|beeceptor\.com)", I)

EXPLICACION = re.compile(
    r"(\bqu[eé] (hace|significa|es)\b|\bexpl[ií]ca(me)?\b|\bwhat (does|is)\b|\bexplain\b|\bpor qu[eé] es (peligroso|malo)\b|"
    r"\bwhy is\b|\bdescribe\b|\bdocumenta\b|\bnunca (ejecutes|corras)\b|\bnever run\b|\bc[oó]mo (me protejo|detecto|evito|bloqueo|prevengo)\b|"
    r"\bhow (do|can) i (protect|defend|detect|prevent|block)\b|\bregla (de detecci[oó]n|sigma|yara)\b|\bdetection rule\b|"
    r"\b(escribe|crea|write|create) (una |a )?(regla|rule|firma|signature)\b|\bes seguro\b|\bis it safe\b|\bpara (un|una) (curso|clase|capacitaci[oó]n)\b)", I)

EJECUCION = re.compile(
    r"\b(ejec[uú]ta(lo|la)?|corre(lo|la)?|c[oó]rrelo|lanza(lo)?|run it|run this|execute|haz(lo)?|do it|apl[ií]ca(lo)?|pon(lo)? en marcha)\b", I)

DEFENSIVO = re.compile(
    r"\b(bloquea|bloquear|block|deny|drop|reject|niega|filtra|prohibe|proh[ií]be|denegar|blacklist|lista negra|"
    r"agrega una regla|add a rule)\b", I)


@dataclass
class Contexto:
    canal: str = "INTENCION"
    dominios_confiables: frozenset = DOMINIOS_CONFIABLES_POR_DEFECTO
    explicacion: bool = False


def _dominio_confiable(host: str, confiables: Iterable[str]) -> bool:
    host = (host or "").lower().strip(".")
    return any(host == d or host.endswith("." + d) for d in confiables)


def _en_busqueda(texto: str, inicio: int) -> bool:
    """¿El patrón aparece como texto buscado por grep/rg/findstr, entre comillas?"""
    prefijo = texto[max(0, inicio - 200):inicio]
    return bool(re.search(r"\b(grep|egrep|zgrep|fgrep|rg|ag|ack|findstr|select-string|sigma|yara)\b[^|;\n]*['\"]\s*$", prefijo, I))


# ---------------------------------------------------------------------------
# Reglas de tabla: (categoria, tipo, patrón, hecho, severidad)
# ---------------------------------------------------------------------------

@dataclass
class Regla:
    categoria: str
    tipo: str
    patron: re.Pattern
    hecho_id: Optional[str]
    severidad: S
    mencion_degrada: bool = True    # en pregunta/explicación o en un grep baja a BAJA


def R(cat, tipo, pat, hecho, sev, flags=I, degrada=True):
    return Regla(cat, tipo, re.compile(pat, flags), hecho, sev, degrada)


_DESTINO_RAIZ = r"(?:/\*?|/\.\*|~/?\*?|\$\{?home\}?/?\*?|/(?:etc|usr|var|boot|bin|sbin|lib|lib64|home|root|opt|srv|sys|dev)/?\*?)(?=\s|$|;|&|\||\"|')"

REGLAS: list[Regla] = [
    # --- Comandos peligrosos ---
    R("COMANDO_PELIGROSO", "rm_recursivo_raiz",
      r"\brm\s+(?:(?:-[a-z]*[rRf][a-z]*|--recursive|--force|--no-preserve-root)\s+)+(?:[\"']?)" + _DESTINO_RAIZ, "KB-CMD-001", S.CRITICA),
    R("COMANDO_PELIGROSO", "rm_raiz_destino_antes", r"\brm\s+[\"']?/[\"']?\s+(?:-[a-z]*[rf][a-z]*\s*)+", "KB-CMD-001", S.CRITICA),
    R("COMANDO_PELIGROSO", "no_preserve_root", r"--no-preserve-root", "KB-CMD-001", S.CRITICA),
    R("COMANDO_PELIGROSO", "find_borrado_raiz", r"\bfind\s+/(?:\s|$)[^;\n]*(?:-delete|-exec\s+rm)", "KB-CMD-001", S.CRITICA),
    R("COMANDO_PELIGROSO", "mkfs", r"\bmkfs(?:\.\w+)?\b[^\n;|]*\s/dev/", "KB-CMD-002", S.CRITICA),
    R("COMANDO_PELIGROSO", "dd_a_disco", r"\bdd\b[^\n;|]*\bof=/dev/(?:sd|nvme|hd|xvd|vd|disk|mmcblk|rdisk)", "KB-CMD-003", S.CRITICA),
    R("COMANDO_PELIGROSO", "fork_bomb", r"(\w+|:)\s*\(\s*\)\s*\{\s*\1\s*\|\s*\1\s*&\s*\}\s*;?\s*\1", "KB-CMD-004", S.ALTA),
    R("COMANDO_PELIGROSO", "descarga_a_interprete",
      r"\b(?:curl|wget|fetch)\b[^|;\n]*\|\s*(?:sudo\s+)?(?:(?:ba|z|da|k|c)?sh|python[23]?|perl|ruby|node|php)\b", "KB-CMD-005", S.ALTA),
    R("COMANDO_PELIGROSO", "interprete_de_descarga",
      r"\b(?:(?:ba|z)?sh)\b\s+(?:-c\s+)?[\"']?(?:\$\(|<\(|`)\s*(?:curl|wget)\b", "KB-CMD-005", S.ALTA),
    R("COMANDO_PELIGROSO", "base64_a_interprete", r"base64\s+(?:-d|--decode|-D)\b[^\n;]*\|\s*(?:sudo\s+)?(?:(?:ba|z)?sh|python[23]?|perl)\b", "KB-CMD-005", S.ALTA),
    R("COMANDO_PELIGROSO", "powershell_iex",
      r"(?:\biex\b|invoke-expression)[^\n]*(?:downloadstring|iwr|invoke-webrequest|net\.webclient)|(?:downloadstring|iwr|invoke-webrequest)[^\n]*\|\s*(?:iex|invoke-expression)", "KB-CMD-005", S.ALTA),
    R("COMANDO_PELIGROSO", "powershell_codificado", r"\bpowershell(?:\.exe)?\b[^\n]*\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{16,}", "KB-CMD-005", S.ALTA),
    R("COMANDO_PELIGROSO", "chmod_777_sistema", r"\bchmod\s+(?:-R\s+)?(?:0?777|a\+rwx|ugo\+rwx)\s+[\"']?" + _DESTINO_RAIZ, "KB-CMD-006", S.ALTA),
    R("COMANDO_PELIGROSO", "chown_recursivo_raiz", r"\bchown\s+-R\s+\S+\s+[\"']?/(?=\s|$)", "KB-CMD-006", S.ALTA),
    R("COMANDO_PELIGROSO", "firewall_off",
      r"\bufw\s+disable\b|\biptables\s+(?:-F|--flush)\b|\biptables\s+-P\s+(?:INPUT|FORWARD)\s+ACCEPT|\bnft\s+flush\s+ruleset|"
      r"\bsystemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|iptables|nftables)\b|\bnetsh\s+(?:adv)?firewall\s+set\s+\w+\s+state\s+off|"
      r"\bset-netfirewallprofile\b[^\n]*-enabled\s+false|\bservice\s+(?:iptables|ufw|firewalld)\s+stop", "KB-CMD-007", S.ALTA),
    R("COMANDO_PELIGROSO", "defensas_off",
      r"\bsetenforce\s+0\b|\bset-mppreference\b[^\n]*-disable\w+\s+\$?(?:true|1)|\bsystemctl\s+(?:stop|disable|mask)\s+(?:apparmor|auditd|falcon-sensor|wazuh-agent|clamav-daemon|osqueryd|crowdstrike)\b|"
      r"\baa-teardown\b|\bauditctl\s+-D\b|\bauditctl\s+-e\s*0\b", "KB-CMD-008", S.ALTA),
    R("COMANDO_PELIGROSO", "escritura_a_dispositivo",
      r">\s*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk)[a-z0-9]*\b|\b(?:shred|wipefs)\b[^\n;|]*/dev/(?:sd|nvme|hd|xvd|vd|mmcblk)", "KB-CMD-009", S.CRITICA),
    R("COMANDO_PELIGROSO", "borrado_windows",
      r"\bformat\s+[c-z]:|\b(?:del|erase)\s+(?:/[sqfa]\s+)+[\"']?[c-z]:\\(?:\*|\s|$|windows)|\b(?:rd|rmdir)\s+(?:/[sq]\s+)+[\"']?[c-z]:\\(?:\s|$|windows)|"
      r"remove-item\b[^\n]*-recurse[^\n]*[\"']?[c-z]:\\(?:\*|\s|$|[\"']|windows)|\bvssadmin\s+delete\s+shadows", "KB-CMD-010", S.CRITICA),
    R("COMANDO_PELIGROSO", "borrar_rastros",
      r"\bhistory\s+-c\b|\bunset\s+histfile\b|\bwevtutil\s+cl\b|\bclear-eventlog\b|\brm\s+(?:-\w+\s+)*/var/log\b|"
      r"\b(?:shred|truncate\s+-s\s*0)\b[^\n;|]*/var/log/|>\s*/var/log/(?:auth|secure|syslog|wtmp|btmp|lastlog)|>\s*~/\.bash_history|\bjournalctl\s+--vacuum-time=1s", "KB-CMD-011", S.ALTA),
    R("COMANDO_PELIGROSO", "borrado_produccion",
      r"\bdrop\s+(?:database|schema)\b|\baws\s+s3\s+rb\b[^\n]*--force|\baws\s+s3\s+rm\b[^\n]*--recursive|\bkubectl\s+delete\s+(?:\w+\s+)?(?:--all\b|-A\b)|"
      r"\bkubectl\s+delete\s+(?:ns|namespace)\s+(?:kube-system|default|prod\w*)|\bterraform\s+destroy\b[^\n]*-auto-approve|\bgcloud\s+projects\s+delete\b|\bflushall\b|\bdropdb\b", "KB-CMD-012", S.ALTA),
    R("COMANDO_PELIGROSO", "borrado_lenguaje_natural",
      r"\b(?:borra|elimina|destruye|formatea|limpia|wipe|delete|erase|destroy|format|nuke)\b.{0,25}\b(?:todo el (?:disco|servidor|sistema|equipo)|todos los archivos del (?:servidor|sistema|disco|equipo)|"
      r"everything on the (?:server|disk|system|machine)|the (?:whole|entire) (?:disk|server|system|drive)|toda la base de datos|la base de datos de producci[oó]n|production database|"
      r"all (?:the )?backups|todos los (?:respaldos|backups)|el disco duro|the hard drive|el directorio ra[ií]z|the root directory)", "KB-CMD-001", S.ALTA),
    R("COMANDO_PELIGROSO", "desactiva_firewall_lenguaje_natural",
      r"\b(?:desactiva|apaga|deshabilita|quita|disable|turn off|shut down|stop)\b.{0,20}\b(?:el |the )?(?:firewall|cortafuegos|antivirus|defender|selinux|apparmor|edr|auditd)\b", "KB-CMD-007", S.ALTA),
    # --- Shell inversa ---
    R("SHELL_INVERSA", "dev_tcp", r"/dev/(?:tcp|udp)/[\w.\-]+/\d+", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "nc_exec", r"\b(?:nc|ncat|netcat)\b[^\n;|]*\s-[a-z]*[ec]\s*[\"']?(?:/bin/|/usr/bin/)?(?:ba|z)?sh\b|\bncat\b[^\n]*--(?:exec|sh-exec)", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "mkfifo_nc", r"\bmkfifo\b[^\n]*\b(?:nc|ncat|netcat|telnet|openssl\s+s_client)\b", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "socket_spawn", r"socket\.socket\([^\n]*(?:subprocess|pty\.spawn|os\.dup2)|fsockopen\s*\([^\n]*(?:exec|shell_exec|system|proc_open)|use\s+socket;[^\n]*exec", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "socat_exec", r"\bsocat\b[^\n]*\b(?:exec|system):[^\n]*(?:sh|bash)", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "ps_tcpclient", r"net\.sockets\.tcpclient\s*\(", "KB-SHL-001", S.CRITICA),
    R("SHELL_INVERSA", "lenguaje_natural", r"\b(?:abre|crea|lanza|establece|open|spawn|start|give me)\b.{0,20}\b(?:una |a )?(?:shell inversa|reverse shell|bind shell|shell remota)\b", "KB-SHL-001", S.ALTA),
    # --- Escalada de privilegios ---
    R("ESCALADA_PRIVILEGIOS", "suid_interprete",
      r"\bchmod\s+(?:[ugoa]*\+s|[2467][0-7]{3})\s+[\"']?(?:/\S*/)?(?:bash|sh|dash|zsh|python[\d.]*|perl|ruby|find|vim?|nano|cp|env|less|awk|nmap|tar)\b", "KB-PRV-001", S.CRITICA),
    R("ESCALADA_PRIVILEGIOS", "suid_generico", r"\bchmod\s+(?:[ugoa]*\+s|[46][0-7]{3})\s+\S+", "KB-PRV-001", S.ALTA),
    R("ESCALADA_PRIVILEGIOS", "setcap", r"\bsetcap\b[^\n]*cap_(?:setuid|sys_admin|dac_override|sys_ptrace)", "KB-PRV-001", S.ALTA),
    R("ESCALADA_PRIVILEGIOS", "sudoers_nopasswd", r"nopasswd\s*:\s*all|(?:>>|>|tee\s+(?:-a\s+)?)\s*/etc/sudoers(?:\.d/\S*)?\b|\bALL\s*=\s*\(ALL(?::ALL)?\)\s*ALL\b[^\n]*>>", "KB-PRV-002", S.CRITICA),
    R("ESCALADA_PRIVILEGIOS", "passwd_uid0", r"(?:>>|tee\s+-a)\s*/etc/passwd\b|^\s*\w+:[^:\n]*:0:0:|\buseradd\b[^\n]*-o\s+-u\s*0\b|\busermod\b[^\n]*-u\s*0\b", "KB-PRV-002", S.CRITICA, I | re.M),
    R("ESCALADA_PRIVILEGIOS", "grupo_admin",
      r"\busermod\s+-a?G\s+(?:\S+,)?(?:sudo|wheel|docker|root|admin|adm|lxd)\b|\bgpasswd\s+-a\s+\S+\s+(?:sudo|wheel|docker|root|lxd)\b|\badduser\s+\S+\s+(?:sudo|wheel|docker|lxd)\b|"
      r"\bnet\s+localgroup\s+administrat\w+\s+\S+\s+/add|add-localgroupmember\b[^\n]*administrat", "KB-PRV-004", S.ALTA),
    R("ESCALADA_PRIVILEGIOS", "escape_contenedor",
      r"\bdocker\s+run\b[^\n]*(?:--privileged|-v\s*/:/|--volume[ =]/:/|--pid[ =]host|-v\s*/var/run/docker\.sock)|\bnsenter\b[^\n]*(?:-t\s*1\b|--target[ =]1\b)|\bchroot\s+/host\b", "KB-PRV-003", S.ALTA),
    R("ESCALADA_PRIVILEGIOS", "lenguaje_natural",
      r"\b(?:dame|hazme|convi[eé]rteme en|give me|make me|grant me|obt[eé]n|consigue|get)\b.{0,15}\b(?:root|administrador|admin rights|superusuario|sudo sin contrase[nñ]a|passwordless sudo)\b", None, S.MEDIA),
    R("ESCALADA_PRIVILEGIOS", "sudo_shell", r"\bsudo\s+(?:su\b|-s\b|-i\b|bash\b|sh\b)|\bsu\s+-?\s*root\b", None, S.MEDIA),
    R("ESCALADA_PRIVILEGIOS", "ld_preload_sudo", r"\bLD_PRELOAD=\S+\s+sudo\b|\bsudo\s+LD_PRELOAD=", "KB-PRV-001", S.ALTA),
    # --- Exploits de CVE conocidos ---
    R("EXPLOIT_CVE", "log4shell", r"\$\{\s*jndi\s*:\s*(?:ldaps?|rmi|dns|iiop|corba|nds|nis|https?)\s*:", "KB-CVE-2021-44228", S.CRITICA, degrada=False),
    R("EXPLOIT_CVE", "shellshock", r"\(\)\s*\{\s*:?\s*;?\s*\}\s*;", "KB-CVE-2014-6271", S.CRITICA, degrada=False),
    R("EXPLOIT_CVE", "sudo_uid_menos_uno", r"\bsudo\s+-u\s*#\s*(?:-1|4294967295)\b", "KB-CVE-2019-14287", S.ALTA),
    R("EXPLOIT_CVE", "pwnkit", r"\b(?:pwnkit|cve-2021-4034)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|compila)\b|\b(?:exploit|ejecuta|run|corre|lanza|compila)\b[^\n]*\b(?:pwnkit|cve-2021-4034)\b", "KB-CVE-2021-4034", S.ALTA),
    R("EXPLOIT_CVE", "dirtycow", r"\b(?:dirty\s*cow|dirtyc0w|cve-2016-5195)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|compila)\b|\b(?:exploit|ejecuta|run|corre|lanza|compila)\b[^\n]*\b(?:dirty\s*cow|dirtyc0w|cve-2016-5195)\b", "KB-CVE-2016-5195", S.ALTA),
    R("EXPLOIT_CVE", "eternalblue", r"(?<![a-z])(?:eternalblue|ms17-010|cve-2017-0144)\b[^\n]*\b(?:exploit|ejecuta|run|corre|lanza|contra|against)\b|\b(?:exploit|ejecuta|run|corre|lanza|usa|use)\b[^\n]*(?<![a-z])(?:eternalblue|ms17_010|ms17-010|cve-2017-0144)\b", "KB-CVE-2017-0144", S.CRITICA),
    # --- Robo de credenciales (volcados) ---
    R("ROBO_CREDENCIALES", "volcado_credenciales",
      r"\bmimikatz\b|\bsekurlsa\b|\blsass(?:\.exe|\.dmp)?\b[^\n]*(?:dump|procdump|minidump|comsvcs)|(?:procdump|comsvcs)[^\n]*lsass|\breg\s+save\s+hklm\\(?:sam|security|system)\b|"
      r"\bhashdump\b|\bsecretsdump\b|\bsecurity\s+(?:dump-keychain|find-generic-password\b[^\n]*-w)|\blazagne\b|\bunshadow\b", "KB-RUT-009", S.ALTA),
    R("ROBO_CREDENCIALES", "cookies_navegador",
      r"(?:google[/\\ ]chrome|chromium|\.mozilla|firefox|brave|microsoft[/\\ ]edge)[^\n]*(?:cookies|login data|logins\.json|key4\.db|web data)\b|"
      r"\b(?:cookies|contrase[nñ]as guardadas|saved passwords|passwords)\b[^\n.]{0,25}\b(?:del navegador|of the browser|from (?:chrome|firefox|the browser|edge)|de (?:chrome|firefox|edge|brave))\b|"
      r"\b(?:roba|extrae|copia|dump|steal|extract|exporta)\b[^\n.]{0,25}\b(?:cookies|sesiones del navegador|browser sessions)\b", "KB-RUT-005", S.ALTA),
    R("ROBO_CREDENCIALES", "shadow", r"(?:\b(?:cat|less|more|head|tail|cp|scp|strings|base64|xxd|john|hashcat|unshadow|type|grep|awk|sed|tar|zip|nc|curl|python\S*|perl|vim?|nano|od)\b[^\n;|]*|[<@])/etc/(?:g?shadow|master\.passwd)\b|\bfile://+etc/shadow", "KB-RUT-002", S.ALTA),
    # --- Persistencia ---
    R("PERSISTENCIA", "authorized_keys_escritura", r"(?:>>|>|tee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$HOME|/root|/home/[\w.-]+)?/?\.ssh/authorized_keys2?\b", "KB-PER-001", S.ALTA),
    R("PERSISTENCIA", "authorized_keys_lenguaje_natural",
      r"\b(?:agrega|a[nñ]ade|mete|pon|instala|add|append|insert|put)\b[^\n.]{0,60}\bauthorized_keys\b", "KB-PER-001", S.ALTA),
    R("PERSISTENCIA", "backdoor_lenguaje_natural",
      r"\b(?:crea|instala|deja|planta|install|create|leave|plant|add)\b[^\n.]{0,20}\b(?:una |a )?(?:puerta trasera|backdoor|implante|implant|rootkit)\b", "KB-PER-002", S.ALTA),
]

# Payloads que vuelven maliciosa una persistencia (descarga, conexión, código codificado).
PAYLOAD_RED = re.compile(
    r"\b(?:curl|wget|nc|ncat|netcat|socat|telnet|mshta|bitsadmin|certutil)\b|/dev/tcp/|base64\s+(?:-d|--decode)|\bpython[23]?\s+-c\b|\bbash\s+-i\b|"
    r"\bpowershell\b[^\n]*-(?:e|enc|w\s+hidden|windowstyle\s+hidden)|https?://|\beval\b|\balias\s+sudo=|\bmkfifo\b|/tmp/\.\w+|\bxmrig\b|\bminerd?\b", I)

PERSIST_MECANISMO = [
    ("cron", re.compile(r"\bcrontab\s+(?:-\w+\s+)*-(?:\s|$)|\(\s*crontab\s+-l[^)]*;\s*echo|\bcrontab\s+-e\b|(?:>>|>|tee\s+(?:-a\s+)?)\s*/(?:etc/cron\S*|var/spool/cron\S*)|@reboot|\*\s+\*\s+\*\s+\*\s+\*", I)),
    ("rc_shell", re.compile(r"(?:>>|>|tee\s+(?:-a\s+)?)\s*[\"']?(?:~|\$HOME|/root|/home/[\w.-]+)?/?\.(?:bashrc|zshrc|profile|bash_profile|bash_login|zprofile|zshenv)\b|(?:>>|>|tee\s+(?:-a\s+)?)\s*/etc/(?:profile|bash\.bashrc|environment)\b|/etc/profile\.d/", I)),
    ("systemd", re.compile(r"/etc/systemd/system/\S+\.service|~/.config/systemd/user/|\bExecStart\s*=|\bsystemctl\s+(?:--user\s+)?enable\b", I)),
    ("rc_local", re.compile(r"/etc/rc\.local|/etc/init\.d/", I)),
    ("launchd", re.compile(r"(?:~/Library/|\$HOME/Library/|/Library/)Launch(?:Agents|Daemons)/|launch(?:agents|daemons)/\S*\.plist|\blaunchctl\s+(?:load|bootstrap)\b", I)),
    ("windows_run", re.compile(
        r"\\(?:software\\)?(?:microsoft\\)?(?:windows\\)?(?:currentversion\\)?run(?:once)?\b|"
        r"\b(?:reg(?:\.exe)?\s+add|new-itemproperty)\b[^\n]*\\run(?:once)?\b|"
        r"\bschtasks\s+/create\b|\bregister-scheduledtask\b|__eventfilter|\\start menu\\programs\\startup", I)),
]


# ---------------------------------------------------------------------------
# Rutas sensibles y secretos
# ---------------------------------------------------------------------------

RUTAS_SENSIBLES = [
    ("llave_ssh", re.compile(
        r"(?<![\w])(?:~|\$HOME|/root|/home/[\w.-]+)?[/\\]?\.ssh(?:[/\\](?:id_[\w-]+|[\w.-]*_key|identity))?\b(?!\.pub)", I), "KB-RUT-001"),
    ("dotenv", re.compile(r"(?:^|[\s/'\"=:@<])\.env(?:\.(?!example\b|sample\b|template\b|dist\b)[\w-]+)?(?=$|[\s'\";|&)])", I), "KB-RUT-003"),
    ("credenciales_nube", re.compile(r"\.aws[/\\](?:credentials|config)\b|\.config/gcloud\b|application_default_credentials\.json|\.azure[/\\]|\.kube[/\\]config\b|\.docker[/\\]config\.json|serviceaccount/token\b|/var/run/secrets/", I), "KB-RUT-004"),
    ("tokens_texto_plano", re.compile(r"\.git-credentials\b|(?:^|[\s/~])\.netrc\b|\.npmrc\b|\.pypirc\b|\.pgpass\b|\.my\.cnf\b|\bwp-config\.php\b", I), "KB-RUT-006"),
    ("environ_proceso", re.compile(r"/proc/(?:self|\d+|\*)/environ\b", I), "KB-RUT-007"),
    ("shadow", re.compile(r"/etc/(?:g?shadow|master\.passwd)\b", I), "KB-RUT-002"),
    ("llaves_lenguaje_natural", re.compile(
        r"\b(?:mis |las |tus |sus |the |my |your |all )?(?:llaves? privadas?|private keys?|llaves? ssh|ssh keys?|credenciales de (?:aws|la nube|gcp|azure)|aws credentials|tokens? de (?:github|acceso|api)|api keys?|llaves? de api|claves? de api|secret keys?|contrase[nñ]as? (?:del sistema|de los usuarios)|password hashes)\b", I), None),
]

VERBO_CONTENIDO = re.compile(
    r"\b(?:cat|less|more|head|tail|type|get-content|gc|strings|xxd|hexdump|od|base64|cp|copy|scp|rsync|tar|zip|7z|gzip|open|read|lee|leer|l[eé]e(?:lo|la|me)?|"
    r"muestra(?:me|lo)?|ens[eé][nñ]a(?:me)?|imprime|print|dump|vuelca|copia|extrae|extract|dame|give me|show(?: me)?|display|env[ií]a|manda|send|sube|upload|"
    r"exfiltra|exfiltrate|grep|awk|sed|python\S*|vim?|nano|code|dime (?:el|lo que)|tell me what|what(?:'s| is) in|qu[eé] (?:hay|dice|contiene)|contenido de|contents of|steal|roba)\b", I)

VERBO_METADATO = re.compile(r"^\s*(?:sudo\s+)?(?:ls|stat|chmod|chown|file|getfacl|test|ssh-keygen|ssh-add|du|wc\s+-l)\b", I)

SECRETOS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "KB-SEC-001"),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b|\bgithub_pat_[A-Za-z0-9_]{40,}\b"), "KB-SEC-002"),
    ("llave_privada", re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"), "KB-SEC-003"),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "KB-SEC-004"),
    ("slack_stripe", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b|\bsk_live_[A-Za-z0-9]{16,}\b"), "KB-SEC-005"),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "KB-SEC-006"),
]


def secretos_en(texto: str) -> list[tuple[str, str, str]]:
    """(tipo, fragmento enmascarado, hecho_id) por cada secreto con formato conocido."""
    out = []
    for tipo, pat, hid in SECRETOS:
        for m in pat.finditer(texto or ""):
            frag = m.group(0)
            out.append((tipo, frag[:6] + "…" + ("" if len(frag) < 12 else frag[-2:]), hid))
    return out


# ---------------------------------------------------------------------------
# Red: URLs, hosts, SSRF y destinos de exfiltración
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"\b(?:https?|ftp|gopher|dict|file|ldap|ldaps|tftp|jar|netdoc)://[^\s'\"<>`)]+", I)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@([\w-]+(?:\.[\w-]+)+)\b")
_SCP_RE = re.compile(r"\b(?:scp|rsync|sftp)\b[^\n;|]*\s(?:[\w.-]+@)?([\w-]+(?:\.[\w-]+)+|\d{1,3}(?:\.\d{1,3}){3}):", I)
_NC_RE = re.compile(r"\b(?:nc|ncat|netcat|telnet|socat)\b\s+(?:-\w+\s+)*([\w-]+(?:\.[\w-]+)+|\d{1,3}(?:\.\d{1,3}){3})\s+\d{2,5}\b", I)
_BARE_HOST_IP = re.compile(r"(?<![\w.])(169\.254\.169\.254|100\.100\.100\.200|metadata\.google\.internal|metadata\.azure\.com|fd00:ec2::254|0x[a-f0-9]{8}|2852039166|0251\.0376\.0251\.0376)(?![\w.])", I)

METADATOS_HOSTS = {"169.254.169.254": "KB-RED-001", "fd00:ec2::254": "KB-RED-001",
                   "metadata.google.internal": "KB-RED-002", "metadata": "KB-RED-002",
                   "100.100.100.200": "KB-RED-002", "metadata.azure.com": "KB-RED-001",
                   "169.254.170.2": "KB-RED-001"}


# Redes internas reales (RFC 1918, CGNAT, ULA). Las de documentación (TEST-NET) se tratan como públicas.
_REDES_PRIVADAS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10", "fc00::/7")]


def _ip_desde_host(host: str) -> Optional[ipaddress._BaseAddress]:
    h = (host or "").strip("[]").lower()
    if not h:
        return None
    # nip.io / sslip.io con IP incrustada
    m = re.match(r"^(?:[\w-]+\.)?(\d{1,3}(?:[.-]\d{1,3}){3})\.(?:nip\.io|xip\.io|sslip\.io|nip\.direct)$", h)
    if m:
        h = m.group(1).replace("-", ".")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    try:
        if re.fullmatch(r"\d{8,10}", h):
            return ipaddress.ip_address(int(h))
        if re.fullmatch(r"0x[0-9a-f]{1,8}", h):
            return ipaddress.ip_address(int(h, 16))
        partes = h.split(".")
        if len(partes) == 4 and all(re.fullmatch(r"0x[0-9a-f]+|0[0-7]*|\d+", p) for p in partes):
            nums = [int(p, 16) if p.startswith("0x") else (int(p, 8) if len(p) > 1 and p.startswith("0") else int(p)) for p in partes]
            if all(0 <= n <= 255 for n in nums):
                return ipaddress.ip_address(".".join(map(str, nums)))
    except ValueError:
        return None
    return None


def _clasificar_host(host: str) -> tuple[str, Optional[str]]:
    """→ (clase, hecho) con clase ∈ METADATOS | LOOPBACK | PRIVADA | PUBLICA | NOMBRE."""
    h = (host or "").strip("[]").lower().rstrip(".")
    if h in METADATOS_HOSTS:
        return "METADATOS", METADATOS_HOSTS[h]
    ip = _ip_desde_host(h)
    if ip is not None:
        if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
            ip = ip.ipv4_mapped
        s = str(ip)
        if s in METADATOS_HOSTS:
            return "METADATOS", METADATOS_HOSTS[s]
        if ip.is_link_local:
            return "METADATOS", "KB-RED-001"
        if ip.is_loopback or s == "0.0.0.0" or ip.is_unspecified:
            return "LOOPBACK", None
        if any(ip in red for red in _REDES_PRIVADAS if ip.version == red.version):
            return "PRIVADA", None
        return "PUBLICA", None
    if h in ("localhost",) or h.endswith(".localhost"):
        return "LOOPBACK", None
    if h.endswith((".internal", ".local", ".lan", ".corp", ".intranet")):
        return "PRIVADA", None
    return "NOMBRE", None


def urls_en(texto: str) -> list[tuple[str, str, str]]:
    """(url, esquema, host) para cada URL; resuelve user@host y corchetes IPv6."""
    out = []
    for m in _URL_RE.finditer(texto or ""):
        url = m.group(0).rstrip(".,;")
        try:
            sp = urlsplit(url)
            host = sp.hostname or ""
            if not host and sp.netloc:
                host = sp.netloc.rsplit("@", 1)[-1].split(":")[0]
        except ValueError:
            host = ""
            sp = None
        esquema = url.split(":", 1)[0].lower()
        out.append((url, esquema, unquote(host)))
    return out


_HOST_TRAS_VERBO = re.compile(
    r"\b(?:a|hacia|to|onto|into|en)\s+(?:https?://)?([\w-]+(?:\.[\w-]+)+)(?:[/\s:,]|$)|"
    r"\b(?:subi[eé]ndola|subi[eé]ndolo|subiendo|envi[aá]ndola|envi[aá]ndolo|enviando)\s+(?:a|en|hacia|to)\s+(?:https?://)?([\w-]+(?:\.[\w-]+)+)", I)
_S3_GS = re.compile(r"\b(?:s3|gs)://([\w.-]+)", I)
_RCLONE_REMOTO = re.compile(r"\brclone\s+(?:copy|sync|move|copyto|moveto)\s+\S+\s+([\w.-]+):", I)
_SMB_RE = re.compile(r"\bsmbclient\s+//([^/\s]+)/", I)


def destinos_en(texto: str) -> list[str]:
    """Destinos externos posibles: hosts de URL, correo, scp/rsync, nc, s3/gs, rclone, smb."""
    d = [h for _, _, h in urls_en(texto) if h]
    d += [m.group(1) for m in _EMAIL_RE.finditer(texto or "")]
    d += [m.group(1) for m in _SCP_RE.finditer(texto or "")]
    d += [m.group(1) for m in _NC_RE.finditer(texto or "")]
    for m in _HOST_TRAS_VERBO.finditer(texto or ""):
        d.append(m.group(1) or m.group(2))
    d += [m.group(1) for m in _S3_GS.finditer(texto or "")]
    d += [m.group(1) for m in _RCLONE_REMOTO.finditer(texto or "")]
    d += [m.group(1) for m in _SMB_RE.finditer(texto or "")]
    return [x.lower() for x in d if x]


# Señales de envío / subida de datos.
ENVIO_DATOS = re.compile(
    r"\bwget\b[^\n;]*--post-(?:file|data)|\b(?:scp|rsync|sftp)\b[^\n;|]*\s\S+:\S*|\b(?:nc|ncat|netcat|socat)\b[^\n]*(?:<|\|)|[|]\s*(?:nc|ncat|netcat)\b|"
    r"\b(?:invoke-webrequest|iwr|invoke-restmethod|irm)\b[^\n]*(?:-method\s+(?:post|put)|-infile|-body)|\bsmbclient\b[^\n]*\bput\b|\bftp\b[^\n]*\bput\b|\bpython[23]?\s+-m\s+http\.server\b|"
    r"\b(?:dig|nslookup|host)\b[^\n]*(?:\$\(|`)|\bmail\b[^\n]*-s[^\n]*<|\bsendmail\b|\baws\s+s3\s+(?:cp|sync|mv)\s+(?!s3://)\S+\s+s3://|\bgsutil\s+cp\s+(?!gs://)\S+\s+gs://|"
    r"\brclone\s+(?:copy|sync)\b|\bgit\s+push\s+https?://|\bpython\S*\s+-m\s+http\.server\b", re.IGNORECASE)

# curl va aparte y distingue mayúsculas: -F (formulario) y -T (subida) no son -f (fail) ni -t.
ENVIO_CURL = re.compile(
    r"\b(?i:curl)\b[^\n;]*(?:\s-d\b|\s--data(?:-binary|-raw|-urlencode|-ascii)?\b|\s-F\b|\s--form\b|\s-T\b|\s--upload-file\b|"
    r"\s-X\s*(?i:POST|PUT)\b|\s--request\s+(?i:POST|PUT)\b|@-|\s@\S|\s-[a-zA-Z]*d\s)")

ENVIO_NATURAL = re.compile(
    r"\b(?:env[ií]a|manda|m[aá]nda|reenv[ií]a|sube|s[uú]be|comparte|publica|pega|p[eé]ga|transfiere|exfiltra|filtra)(?:me|nos|le|les|te)?(?:lo|la|los|las)?\b|\b(?:send(?: it| them| this| that)?|e-?mail(?: it)?|forward(?: it)?|upload(?: it)?|post(?: it)?|"
    r"share(?: it)?|paste(?: it)?|exfiltrate|copy it|leak|filtra(?:lo|la)?|transmit|push it)\b", re.IGNORECASE)

DATOS_CARGA = re.compile(
    r"\b(?:archivo|archivos|fichero|file|files|base de datos|database|db|dump|volcado|backup|respaldo|registros|logs?|clientes|customers|usuarios|users|"
    r"todo|everything|contenido|contents|output|salida|resultado|eso|esto|that|this|it|them|lo|la|los|las|tabla|table|c[oó]digo fuente|source code|repositorio|repo|"
    r"llaves?|keys?|credenciales|credentials|secretos|secrets|tokens?|contrase[nñ]as|passwords|cookies|historial|history)\b|[~/]\S+|@\S+|\s<\s*\S+", re.IGNORECASE)


# ---------------------------------------------------------------------------
# Inyección de prompts
# ---------------------------------------------------------------------------

INYECCION_FRASES = re.compile(
    r"(\bignor(?:a|e|ar|en)\b.{0,30}\b(?:instrucciones|instructions|reglas|rules|indicaciones|directives|guidelines|lo anterior|above|previous|prior)\b|"
    r"\bdisregard\b.{0,30}\b(?:instructions|rules|above|previous|prior|guidelines|request|task|question)\b|"
    r"\b(?:instead|en su lugar|en vez de eso)\b[,;:]?\s*(?:please\s+|por favor\s+)?(?:visit|send|run|execute|open|upload|forward|visita|env[ií]a|ejecuta|abre|sube|reenv[ií]a)\b|"
    r"\bignora (?:la petici[oó]n|lo que (?:pidi[oó]|pide) el usuario|al usuario)\b|"
    r"\bolvida\b.{0,25}\b(?:instrucciones|reglas|lo anterior|todo lo que)\b|\bforget\b.{0,25}\b(?:instructions|rules|everything|above)\b|"
    r"\bnuevas instrucciones\b|\bnew instructions\b|\binstrucciones (?:del sistema|ocultas|nuevas)\b|\bupdated instructions\b|"
    r"(?:^|[\[<#(\s])(?:system|sistema|admin|developer|root)\s*(?:prompt|override|message|mensaje)?\s*[:\]>)]|<\|im_start\|>|<\|system\|>|\[/?inst\]|"
    r"\bahora eres\b|\byou are now\b|\bact[uú]a como si no tuvieras\b|\bact as if you have no\b|\bdo anything now\b|\bmodo (?:desarrollador|dios|sin restricciones|dan)\b|\b(?:developer|god|jailbreak|dan) mode\b|"
    r"\bno (?:se lo )?(?:le )?digas (?:nada )?al usuario\b|\bdon'?t (?:tell|inform|mention (?:this )?to) the user\b|\bsin que el usuario (?:lo )?(?:sepa|note|se entere)\b|\bwithout (?:telling|informing|alerting) the user\b|"
    r"\bdo not (?:tell|inform|alert) the user\b|\b(?:nota|mensaje|instrucci[oó]n) para (?:la ia|el asistente|el agente|el modelo|la inteligencia artificial)\b|"
    r"\b(?:note|message|instruction)s? (?:to|for) (?:the )?(?:ai|assistant|agent|model|llm)\b|\bsi eres (?:una ia|un modelo|un asistente|un agente)\b|\bif you are an? (?:ai|llm|language model|assistant|agent)\b|"
    r"\b(?:to|for) (?:the )?(?:ai|llm) (?:reading|processing|summarizing) this\b|\b(?:asistente|assistant|agente|agent|ai|ia)\s*[:,]\s*(?:debes|tienes que|you must|you should|please|por favor|ejecuta|run|send|env[ií]a)\b|"
    r"\boverride\b.{0,20}\b(?:safety|seguridad|rules|reglas|policy|pol[ií]tica)\b|\bprioridad m[aá]xima\b.{0,40}\b(?:ejecuta|env[ií]a|run|send)\b|\bhighest priority\b.{0,40}\b(?:execute|run|send)\b|"
    r"\brevela (?:tu|el) (?:prompt|system prompt|instrucciones)\b|\breveal (?:your|the) (?:system )?prompt\b)", re.IGNORECASE | re.S)

IMPERATIVO_AGENTE = re.compile(
    r"\b(?:ejecuta|corre|lanza|run|execute|env[ií]a|manda|send|sube|upload|borra|elimina|delete|descarga|download|instala|install|"
    r"visita|visit|abre|open|lee|read|copia|copy|reenv[ií]a|forward|llama a|call|haz clic|click|aprueba|approve|transfiere|transfer|paga|pay)\b", re.IGNORECASE)

OCULTO_HTML = re.compile(r"<!--(.*?)-->|<[^>]+style\s*=\s*[\"'][^\"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0|color\s*:\s*(?:#fff(?:fff)?|white))[^\"']*[\"'][^>]*>(.*?)<", re.IGNORECASE | re.S)


# ---------------------------------------------------------------------------
# Web: SQLi, inyección de comandos, path traversal
# ---------------------------------------------------------------------------

SQLI = [
    re.compile(r"['\"`]\)?\s*(?:or|and|\|\|)\s+(['\"]?)(\w+)\1\s*(?:=|like)\s*\1\2\b", re.I),
    re.compile(r"['\"`]\)?\s*(?:or|and)\s+\d+\s*=\s*\d+", re.I),
    re.compile(r"\bor\s+1\s*=\s*1\b|\bor\s+true\b\s*(?:--|#)|['\"]\s*or\s*(['\"])\1\s*=\s*\1", re.I),
    re.compile(r"\bunion\b(?:\s+all)?\s+(?:distinct\s+)?select\b", re.I),
    re.compile(r"['\"`]\)?\s*;\s*(?:drop|delete|insert|update|shutdown|exec|declare|truncate|alter|create)\b", re.I),
    re.compile(r"['\"`]\)?\s*(?:--|#|/\*)", re.I),
    re.compile(r"\b(?:sleep|pg_sleep)\s*\(\s*\d+\s*\)|\bbenchmark\s*\(\s*\d+|\bwaitfor\s+delay\b|\bdbms_pipe\.receive_message\b", re.I),
    re.compile(r"\bxp_cmdshell\b|\binto\s+(?:out|dump)file\b|\bload_file\s*\(|\bextractvalue\s*\(|\bupdatexml\s*\(", re.I),
    re.compile(r"\binformation_schema\.(?:tables|columns)\b", re.I),
]
CONTEXTO_SQL_ADMIN = re.compile(r"^\s*(?:select|insert|update|delete|create|alter|with|explain|show|describe|psql|mysql|sqlite3)\b", re.I)

CMDI_VALOR = re.compile(
    r"(?:=|:\s|^|[\"'])\s*[\w.\-/:]*\s*(?:;|\|\|?|&&|\n|%0a|%0d|%3b|%7c|%26%26)\s*(?:id|whoami|uname|cat|ls|nc|ncat|curl|wget|bash|sh|rm|ping|nslookup|python[23]?|perl|powershell|cmd|net\s+user|sleep|echo)\b",
    re.I | re.M)
CMDI_SUBSHELL = re.compile(r"(?:\$\(|`)\s*(?:curl|wget|nc|ncat|bash\s+-i|sh\s+-i|rm\s+-|cat\s+/etc/(?:passwd|shadow)|python[23]?\s+-c|perl\s+-e|base64\s+-d)", re.I)
CMDI_SUBSHELL_RECON = re.compile(r"(?:\$\(|`)\s*(?:id|whoami|uname(?:\s+-a)?|hostname)\s*(?:\)|`)", re.I)
CONTEXTO_PARAMETRO = re.compile(
    r"\b(?:par[aá]metro|parameter|param|campo|field|input|entrada|formulario|form|query|valor|value|filename|nombre de archivo|host|hostname|usuario|username|"
    r"b[uú]squeda|search|url|endpoint|api|payload|header|cabecera|cookie|user-agent|petici[oó]n|request|post|get)\b|[?&]\w+=|\b\w+=", re.I)

TRAVERSAL_CODIFICADO = re.compile(
    r"%2e%2e(?:%2f|%5c|/|\\)|\.\.%2f|\.\.%5c|%252e%252e|%c0%ae|%c0%af|%e0%80%af|\.{3,4}/{1,2}|\.\.;/|\.\.\\\\?\.\.|%u002e", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]){2,}")
TRAVERSAL_OBJETIVO = re.compile(r"(?:\.\.[/\\])+(?:etc[/\\](?:passwd|shadow|hosts|sudoers)|windows[/\\](?:win\.ini|system32)|proc[/\\]self|root[/\\]|\.ssh|\.env|\.aws|boot\.ini|web\.config|wp-config)", re.I)
NULL_BYTE = re.compile(r"%00|\\x00|\\0(?=\.\w{2,4}\b)")


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------

@dataclass
class _Acumulador:
    hallazgos: list[Hallazgo] = field(default_factory=list)

    def add(self, h: Hallazgo) -> None:
        for i, x in enumerate(self.hallazgos):
            if x.categoria == h.categoria and x.tipo == h.tipo:
                if h.severidad > x.severidad:
                    self.hallazgos[i] = h
                return
        self.hallazgos.append(h)


def _degradar(h: Hallazgo, nota: str) -> Hallazgo:
    h.severidad = min(h.severidad, S.BAJA)
    h.nota = nota
    return h


def _reglas_tabla(capas, ctx: Contexto, acc: _Acumulador) -> None:
    for capa, t in capas:
        for r in REGLAS:
            m = r.patron.search(t)
            if not m:
                continue
            h = Hallazgo(r.categoria, r.tipo, r.severidad, m.group(0), r.hecho_id, ctx.canal, capa)
            if r.mencion_degrada and ctx.canal == "INTENCION":
                if ctx.explicacion:
                    _degradar(h, "mención en pregunta o explicación; no se pide ejecutar")
                elif _en_busqueda(t, m.start()):
                    _degradar(h, "el patrón es el texto que se busca (grep), no un comando")
            acc.add(h)


def _persistencia(capas, ctx, acc):
    for capa, t in capas:
        for nombre, pat in PERSIST_MECANISMO:
            m = pat.search(t)
            if not m:
                continue
            if nombre == "cron" and re.search(r"\bcrontab\s+-l\b\s*(?:$|\||>)", t) and not re.search(r";\s*echo|\|\s*crontab\s+-", t):
                continue  # solo listar
            payload = PAYLOAD_RED.search(t)
            if payload:
                hid = "KB-PER-003" if nombre == "rc_shell" else "KB-PER-002"
                h = Hallazgo("PERSISTENCIA", f"{nombre}_con_carga", S.ALTA, f"{m.group(0)} … {payload.group(0)}", hid, ctx.canal, capa)
                if ctx.explicacion and ctx.canal == "INTENCION":
                    _degradar(h, "mención en pregunta o explicación")
                acc.add(h)
            elif nombre in ("windows_run", "launchd", "rc_local"):
                acc.add(Hallazgo("PERSISTENCIA", nombre, S.MEDIA, m.group(0), None, ctx.canal, capa,
                                 "mecanismo de arranque automático sin carga obvia: no sé si es legítimo"))


def _sensibles_y_secretos(capas, ctx, acc, sesion_lecturas: list) -> None:
    for capa, t in capas:
        # Quitar «-i ruta_llave» (usar una llave como identidad no es leerla).
        t_sin_i = re.sub(r"\s-i\s+\S+", " ", t)
        for tipo, pat, hid in RUTAS_SENSIBLES:
            m = pat.search(t_sin_i)
            if not m:
                continue
            # Tras .ssh, si el path termina en .pub es una llave pública: no es secreto.
            cola = t_sin_i[m.end():m.end()+40]
            if m.group(0).rstrip().endswith(".pub") or re.match(r"[/\\][^\s;|&]*\.pub\b", cola):
                continue
            frase = t_sin_i
            metadato = bool(VERBO_METADATO.search(frase)) and not re.search(r"[|>]|&&|;", frase)
            contenido = bool(VERBO_CONTENIDO.search(frase)) or bool(re.search(r"[<@]\s*\S*" + re.escape(m.group(0).strip()), frase))
            if metadato and not re.search(r"\b(?:cat|less|more|head|tail|type|cp|scp|base64|xxd|strings)\b", frase, re.I):
                continue
            if tipo == "llaves_lenguaje_natural":
                if not contenido:
                    continue
                if re.search(r"\b(?:rota|rotar|rotate|revoca|revoke|regenera|regenerate|genera|generate|crea|create|cambia|change|renueva|renew|elimina las expuestas|deshabilita|disable|escanea|scan|busca|search|find|detecta|detect|audita|audit|revisa si|check if|lista los nombres|list the names)\b", frase, re.I):
                    continue
                h = Hallazgo("ROBO_CREDENCIALES", "pide_secretos", S.MEDIA, m.group(0), None, ctx.canal, capa,
                             "pide secretos sin ruta concreta: no sé si es legítimo")
            else:
                if not contenido:
                    continue
                sev = S.ALTA if tipo == "shadow" else S.MEDIA
                h = Hallazgo("ROBO_CREDENCIALES", f"lectura_{tipo}", sev, m.group(0), hid, ctx.canal, capa,
                             "lectura de un recurso sensible; si después se envía, es robo")
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            else:
                sesion_lecturas.append((h.tipo, m.group(0).strip(), hid))
            acc.add(h)
        for tipo, frag, hid in secretos_en(t):
            sev = S.MEDIA
            acc.add(Hallazgo("ROBO_CREDENCIALES", f"secreto_{tipo}", sev, frag, hid, ctx.canal, capa,
                             "secreto con formato conocido presente en el texto"))


def _red(capas, ctx: Contexto, acc: _Acumulador, hay_lectura_sensible: bool) -> None:
    for capa, t in capas:
        defensivo = bool(DEFENSIVO.search(t)) and bool(re.search(r"\b(?:ufw|iptables|nft|firewall|cortafuegos|regla|rule|waf|security group|grupo de seguridad|egress|salida)\b", t, re.I))
        hosts = [(u, e, h) for (u, e, h) in urls_en(t)]
        for m in _BARE_HOST_IP.finditer(t):
            hosts.append((m.group(0), "", m.group(1)))
        for url, esquema, host in hosts:
            clase, hid = _clasificar_host(host)
            if clase == "METADATOS":
                h = Hallazgo("SSRF", "metadatos_nube", S.CRITICA, url, hid, ctx.canal, capa)
                if defensivo or (ctx.explicacion and ctx.canal == "INTENCION"):
                    _degradar(h, "se menciona para bloquearlo o explicarlo")
                acc.add(h)
            elif esquema in ("file", "gopher", "dict", "ldap", "ldaps", "tftp", "jar", "netdoc"):
                if esquema == "ldap" and "jndi" in t.lower():
                    continue
                h = Hallazgo("SSRF", f"esquema_{esquema}", S.ALTA, url, "KB-RED-003", ctx.canal, capa)
                if ctx.explicacion and ctx.canal == "INTENCION":
                    _degradar(h, "mención en pregunta o explicación")
                acc.add(h)
            elif clase in ("LOOPBACK", "PRIVADA") and ctx.canal == "DATO":
                acc.add(Hallazgo("SSRF", "red_interna_desde_dato", S.MEDIA, url, None, ctx.canal, capa,
                                 "un dato externo apunta a la red interna"))
            elif clase in ("LOOPBACK", "PRIVADA") and CONTEXTO_PARAMETRO.search(t) and re.search(r"\b(?:url|webhook|callback|redirect|next|image|imagen|fetch|proxy)\s*[=:]", t, re.I):
                acc.add(Hallazgo("SSRF", "red_interna_en_parametro", S.MEDIA, url, None, ctx.canal, capa,
                                 "parámetro de URL que apunta a la red interna"))
        # Exfiltración
        envio_cmd = ENVIO_CURL.search(t) or ENVIO_DATOS.search(t)
        envio_nat = ENVIO_NATURAL.search(t)
        destinos = destinos_en(t)
        externos = [d for d in destinos if not _dominio_confiable(d, ctx.dominios_confiables)
                    and _clasificar_host(d)[0] in ("PUBLICA", "NOMBRE")]
        servicio = SERVICIOS_EXFIL.search(t)
        if servicio and (envio_cmd or envio_nat or ctx.canal == "DATO"):
            h = Hallazgo("EXFILTRACION", "servicio_de_exfiltracion", S.ALTA, servicio.group(0), "KB-RED-004", ctx.canal, capa)
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
        if (envio_cmd or envio_nat) and externos:
            carga = DATOS_CARGA.search(t)
            if hay_lectura_sensible:
                h = Hallazgo("EXFILTRACION", "secreto_a_externo", S.CRITICA, f"{(envio_cmd or envio_nat).group(0)[:60]} → {externos[0]}",
                             "KB-RED-005", ctx.canal, capa, "datos sensibles hacia un dominio fuera de la lista de confianza")
            elif envio_cmd or carga:
                h = Hallazgo("EXFILTRACION", "datos_a_externo", S.ALTA, f"{(envio_cmd or envio_nat).group(0)[:60]} → {externos[0]}",
                             "KB-RED-005", ctx.canal, capa)
            else:
                h = Hallazgo("EXFILTRACION", "mensaje_a_externo", S.MEDIA, externos[0], None, ctx.canal, capa,
                             "envío a un destino desconocido sin datos claros: no sé si es legítimo")
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
        elif envio_cmd and re.search(r"\b(?:dig|nslookup|host)\b[^\n]*(?:\$\(|`)", t, re.I):
            acc.add(Hallazgo("EXFILTRACION", "exfil_dns", S.ALTA, envio_cmd.group(0), "KB-RED-005", ctx.canal, capa))


def _web(capas, ctx, acc):
    for capa, t in capas:
        if ctx.canal == "INTENCION" and re.match(r"^\s*(?:sudo\s+)?(?:grep|egrep|zgrep|fgrep|rg|ag|ack|findstr|select-string|awk)\b", t, re.I):
            continue  # buscar patrones de ataque en logs propios es trabajo defensivo
        admin_sql = bool(CONTEXTO_SQL_ADMIN.search(t))
        for i, pat in enumerate(SQLI):
            m = pat.search(t)
            if not m:
                continue
            # Un DBA escribiendo SQL normal no es inyección: solo cuentan tautologías,
            # UNION, comentarios tras comilla y funciones de tiempo/archivo.
            if admin_sql and i in (5, 8):
                continue
            h = Hallazgo("INYECCION_SQL", f"sqli_{i}", S.ALTA, m.group(0), "KB-WEB-001", ctx.canal, capa)
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
            break
        m = CMDI_VALOR.search(t)
        if m and (CONTEXTO_PARAMETRO.search(t) or re.search(r"%0a|%3b|%7c|%26", m.group(0), re.I) or re.search(r"\d+\.\d+\.\d+\.\d+\s*[;|&]", m.group(0))):
            if not re.match(r"^\s*(?:sudo\s+)?(?:ps|ls|cat|grep|journalctl|systemctl|docker|kubectl|tail|df|du|find|echo|git|cd|make|pip|npm|apt|dnf|yum|brew)\b", t, re.I) or re.search(r"[=?]\S*\s*(?:;|\|\||&&|%0a|%3b)", m.group(0), re.I):
                h = Hallazgo("INYECCION_COMANDOS", "metacaracter_en_parametro", S.ALTA, m.group(0), "KB-WEB-002", ctx.canal, capa)
                if ctx.explicacion and ctx.canal == "INTENCION":
                    _degradar(h, "mención en pregunta o explicación")
                acc.add(h)
        m = CMDI_SUBSHELL.search(t)
        if m:
            h = Hallazgo("INYECCION_COMANDOS", "subshell_peligroso", S.ALTA, m.group(0), "KB-WEB-002", ctx.canal, capa)
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
        m = CMDI_SUBSHELL_RECON.search(t)
        if m and CONTEXTO_PARAMETRO.search(t):
            acc.add(Hallazgo("INYECCION_COMANDOS", "subshell_en_parametro", S.ALTA, m.group(0), "KB-WEB-002", ctx.canal, capa))
        # Path traversal
        m = TRAVERSAL_CODIFICADO.search(t) or TRAVERSAL_OBJETIVO.search(t)
        if m:
            h = Hallazgo("PATH_TRAVERSAL", "traversal", S.ALTA, m.group(0), "KB-WEB-003", ctx.canal, capa)
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
        else:
            m = TRAVERSAL.search(t)
            if m and len(re.findall(r"\.\.[/\\]", m.group(0))) >= 3 and CONTEXTO_PARAMETRO.search(t):
                acc.add(Hallazgo("PATH_TRAVERSAL", "traversal_profundo", S.MEDIA, m.group(0), None, ctx.canal, capa,
                                 "subida de varios niveles en un parámetro: no sé a dónde llega"))
        m = NULL_BYTE.search(t)
        if m and CONTEXTO_PARAMETRO.search(t):
            acc.add(Hallazgo("PATH_TRAVERSAL", "byte_nulo", S.ALTA, m.group(0), "KB-WEB-003", ctx.canal, capa))


def _log4j_normalizar(t: str) -> str:
    # ${lower:j} / ${upper:j} / ${::-j} / ${env:X:-j} / ${date:'j'} → j  (varias vueltas)
    for _ in range(6):
        nuevo = re.sub(r"\$\{(?:lower|upper|::|env:[^:}]*:|sys:[^:}]*:|date):?-?'?([^${}']{1,4})'?\}", r"\1", t, flags=re.I)
        if nuevo == t:
            break
        t = nuevo
    return t


def _inyeccion_prompt(capas, lec_banderas, ctx, acc, payload_peligroso: bool):
    texto_total = "\n".join(t for _, t in capas)
    m = None
    capa_m = "original"
    for capa, t in capas:
        m = INYECCION_FRASES.search(t)
        if m:
            capa_m = capa
            break
    ocultos = []
    for capa, t in capas:
        for mm in OCULTO_HTML.finditer(t):
            contenido = (mm.group(1) or mm.group(2) or "").strip()
            if contenido and (IMPERATIVO_AGENTE.search(contenido) or INYECCION_FRASES.search(contenido)):
                ocultos.append(contenido)
    trucos = [b for b in lec_banderas if b in ("ancho_cero", "bidi", "unicode_tags", "homoglifos")]
    if ctx.canal == "DATO":
        if m or ocultos:
            sev = S.CRITICA if payload_peligroso else S.ALTA
            ev = m.group(0) if m else ocultos[0]
            acc.add(Hallazgo("INYECCION_PROMPT", "orden_en_dato", sev, ev, "KB-PRM-001", ctx.canal, capa_m,
                             "un dato intenta dar órdenes al agente"))
        elif payload_peligroso and IMPERATIVO_AGENTE.search(texto_total):
            acc.add(Hallazgo("INYECCION_PROMPT", "carga_peligrosa_en_dato", S.ALTA, "imperativo + carga peligrosa en el documento",
                             "KB-PRM-001", ctx.canal, capa_m))
        if trucos:
            sev = S.ALTA if (m or ocultos or payload_peligroso) else S.MEDIA
            acc.add(Hallazgo("INYECCION_PROMPT", "unicode_oculto", sev, ",".join(trucos), "KB-PRM-002" if sev <= S.MEDIA else "KB-PRM-001",
                             ctx.canal, "original", "caracteres invisibles u homoglifos en el dato"))
        if "base64" in lec_banderas and any(INYECCION_FRASES.search(t) or IMPERATIVO_AGENTE.search(t) for c, t in capas if c.startswith("base64")) and (m or payload_peligroso):
            acc.add(Hallazgo("INYECCION_PROMPT", "orden_codificada", S.ALTA, "base64", "KB-PRM-001", ctx.canal, "base64"))
    else:
        if m and not ctx.explicacion:
            acc.add(Hallazgo("INYECCION_PROMPT", "jailbreak_en_peticion", S.ALTA, m.group(0), "KB-PRM-001", ctx.canal, capa_m,
                             "la petición intenta anular las reglas del agente"))
        if trucos and (m or payload_peligroso):
            acc.add(Hallazgo("OFUSCACION", "unicode_oculto", S.ALTA, ",".join(trucos), "KB-PRM-002" if not m else "KB-PRM-001", ctx.canal, "original"))
        elif trucos and "homoglifos" in trucos:
            acc.add(Hallazgo("OFUSCACION", "homoglifos", S.MEDIA, ",".join(trucos), None, ctx.canal, "original",
                             "texto con homoglifos: no sé por qué viene así"))


def detectar(lectura: Lectura, ctx: Contexto, lecturas_sensibles_sesion: list) -> list[Hallazgo]:
    """Corre todos los detectores sobre todas las capas. No ejecuta nada."""
    from .comandos import analizar as _analizar_comandos
    from .reglas_v11 import aplicar as _reglas_v11
    acc = _Acumulador()
    capas = lectura.textos()
    capas = capas + [(c + "+log4j", _log4j_normalizar(t)) for c, t in capas if "${" in t]
    nuevas_lecturas: list = []
    _reglas_tabla(capas, ctx, acc)
    _persistencia(capas, ctx, acc)
    _sensibles_y_secretos(capas, ctx, acc, nuevas_lecturas)
    for capa, t in capas:
        for h in _analizar_comandos(t, ctx.canal, capa, ctx.dominios_confiables, bool(lecturas_sensibles_sesion)):
            if ctx.explicacion and ctx.canal == "INTENCION":
                _degradar(h, "mención en pregunta o explicación")
            acc.add(h)
        for h in _reglas_v11(t, ctx.canal, capa, ctx.explicacion):
            acc.add(h)
    _red(capas, ctx, acc, hay_lectura_sensible=bool(nuevas_lecturas) or any(h.categoria == "ROBO_CREDENCIALES" and h.severidad >= S.MEDIA for h in acc.hallazgos))
    _web(capas, ctx, acc)
    payload = any(h.severidad >= S.ALTA or (h.categoria == "ROBO_CREDENCIALES" and h.severidad >= S.MEDIA)
                  for h in acc.hallazgos if h.categoria not in ("INYECCION_PROMPT", "OFUSCACION"))
    _inyeccion_prompt(capas, lectura.banderas, ctx, acc, payload)
    # Ofuscación + algo peligroso: esconder ya es evidencia de intención.
    ofuscado = [b for b in lectura.banderas if b in ("base64", "hex", "url_encoding", "trucos_shell")]
    if ofuscado and any(h.capa != "original" and h.capa != "normalizado" and h.severidad >= S.ALTA for h in acc.hallazgos) or \
       ("trucos_shell" in lectura.banderas and any(h.severidad >= S.ALTA for h in acc.hallazgos)):
        acc.add(Hallazgo("OFUSCACION", "carga_ofuscada", S.ALTA, ",".join(ofuscado), "KB-PRM-002", ctx.canal, "original",
                         "la carga peligrosa venía escondida"))
    if ctx.canal == "DATO":
        # Un log o un informe que *contiene* un ataque no ataca al agente. Solo cuenta
        # si el dato intenta dar órdenes (INYECCION_PROMPT); lo demás queda como nota.
        for h in acc.hallazgos:
            if h.categoria != "INYECCION_PROMPT":
                h.severidad = min(h.severidad, S.BAJA)
                h.nota = (h.nota + "; " if h.nota else "") + "carga presente en el dato, sin orden al agente"
    else:
        lecturas_sensibles_sesion.extend(nuevas_lecturas)
    return acc.hallazgos
