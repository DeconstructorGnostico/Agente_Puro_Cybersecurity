"""Capas de lectura: el texto tal cual y sus versiones desofuscadas.

Los detectores no leen solo lo que se ve. Leen también:
- la versión sin caracteres de ancho cero, sin controles bidireccionales y sin homoglifos;
- la versión sin trucos de comillas de shell (r''m, r\\m, ${IFS});
- lo que hay dentro de bloques base64, hex (\\x..), URL-encoding y caracteres «tag» Unicode.

Cada truco encontrado queda como bandera: esconder algo ya es una señal.
"""
from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field
from urllib.parse import unquote

ANCHO_CERO = dict.fromkeys(map(ord, "\u200b\u200c\u200d\u2060\ufeff\u00ad\u180e\u2061\u2062\u2063\u2064"), None)
BIDI = dict.fromkeys(map(ord, "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069\u200e\u200f"), None)

HOMOGLIFOS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ѕ": "s", "ј": "j", "ԁ": "d", "һ": "h", "ӏ": "l", "ο": "o", "α": "a", "ν": "v",
    "τ": "t", "ı": "i", "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H",
    "О": "O", "Р": "P", "С": "C", "Т": "T", "Х": "X", "Ѕ": "S", "І": "I", "Ј": "J",
})

_B64 = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/=_-])")
_HEX = re.compile(r"(?:\\x[0-9a-fA-F]{2}){3,}")
_URL = re.compile(r"%[0-9a-fA-F]{2}")
_TAGS = re.compile("[\U000E0000-\U000E007F]+")


@dataclass
class Lectura:
    original: str
    capas: dict[str, str] = field(default_factory=dict)
    banderas: list[str] = field(default_factory=list)

    def textos(self) -> list[tuple[str, str]]:
        return list(self.capas.items())

    @property
    def plano(self) -> str:
        return self.capas.get("normalizado", self.original)


def _imprimible(s: str) -> bool:
    if not s:
        return False
    ok = sum(1 for c in s if c.isprintable() or c in "\n\t\r")
    return ok / len(s) >= 0.9 and sum(c.isalpha() for c in s) >= 3


def _desofuscar_shell(t: str) -> str:
    t = re.sub(r"\$\{IFS\}|\$IFS(\$\d)?", " ", t)
    # r''m, r""m → rm ; r\m → rm (solo entre letras, para no romper rutas ni regex)
    t = re.sub(r"(?<=\w)(''|\"\")(?=\w)", "", t)
    return t


def _sin_escapes(t: str) -> str:
    # r\m → rm. Va en una capa aparte para no romper rutas de Windows (HKLM\SAM).
    return re.sub(r"(?<=[A-Za-z])\\(?=[A-Za-z])", "", t)


def _decodificar_b64(t: str) -> list[str]:
    salidas = []
    for m in _B64.finditer(t):
        bloque = m.group(1)
        if bloque.isalpha() and (bloque.islower() or bloque.isupper()):
            continue  # una palabra larga no es base64
        for alt in (bloque, bloque.replace("-", "+").replace("_", "/")):
            try:
                raw = base64.b64decode(alt + "=" * (-len(alt) % 4), validate=True)
                txt = raw.decode("utf-8")
            except (binascii.Error, ValueError, UnicodeDecodeError):
                continue
            if _imprimible(txt):
                salidas.append(txt)
                break
    return salidas


def leer(texto: str) -> Lectura:
    texto = texto or ""
    lec = Lectura(original=texto)
    lec.capas["original"] = texto
    if any(ord(c) in ANCHO_CERO for c in texto):
        lec.banderas.append("ancho_cero")
    if any(ord(c) in BIDI for c in texto):
        lec.banderas.append("bidi")
    tags = _TAGS.findall(texto)
    if tags:
        lec.banderas.append("unicode_tags")
        oculto = "".join(chr(ord(c) - 0xE0000) for bloque in tags for c in bloque if 0x20 <= ord(c) - 0xE0000 < 0x7F)
        if oculto.strip():
            lec.capas["tags_ocultos"] = oculto
    t = unicodedata.normalize("NFKC", texto)
    t = _TAGS.sub("", t).translate(ANCHO_CERO).translate(BIDI)
    t2 = t.translate(HOMOGLIFOS)
    if t2 != t:
        lec.banderas.append("homoglifos")
    t3 = _desofuscar_shell(t2)
    if t3 != t2:
        lec.banderas.append("trucos_shell")
    lec.capas["normalizado"] = re.sub(r"[ \t]+", " ", t3)
    t4 = _sin_escapes(t3)
    if t4 != t3 and re.search(r"(?<![\w:])[a-z]+\\[a-z]", t3) and not re.search(r"[A-Za-z]:\\|HK(?:LM|CU)\\", t3):
        lec.capas["sin_escapes"] = t4
        lec.banderas.append("trucos_shell")
    # URL-encoding (hasta 3 vueltas, para el doble codificado %252e)
    if _URL.search(t3):
        dec = t3
        for _ in range(3):
            nuevo = unquote(dec)
            if nuevo == dec:
                break
            dec = nuevo
        if dec != t3:
            lec.capas["url"] = dec
            lec.banderas.append("url_encoding")
    if _HEX.search(t3):
        try:
            dec = _HEX.sub(lambda m: bytes.fromhex(m.group(0).replace("\\x", "")).decode("utf-8", "replace"), t3)
            lec.capas["hex"] = dec
            lec.banderas.append("hex")
        except ValueError:
            pass
    b64 = _decodificar_b64(t3)
    for i, txt in enumerate(b64[:4]):
        lec.capas[f"base64_{i}"] = _desofuscar_shell(unicodedata.normalize("NFKC", txt))
        # una vuelta más: base64 dentro de base64
        for j, txt2 in enumerate(_decodificar_b64(txt)[:2]):
            lec.capas[f"base64_{i}_{j}"] = txt2
    if b64:
        lec.banderas.append("base64")
    return lec
