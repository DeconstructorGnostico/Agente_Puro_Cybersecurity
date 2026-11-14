"""Memoria de sesión para detectar ataques partidos en varios pasos.

Se recuerda, por sesión:
- lecturas de recursos sensibles (aunque el paso haya quedado INDETERMINADO);
- variables definidas (A="rm -rf", B=" /") para expandirlas en pasos siguientes;
- descargas desde dominios no confiables, para ver si luego se ejecutan;
- tokens emitidos, para revocarlos si la sesión resulta hostil.

No es memoria verificada (no son hechos del mundo): son postulados de sesión,
igual que en CVA. Sirven para ver la cadena, no para «saber» nada.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import PurePosixPath

_ASIGNACION = re.compile(r"(?:^|[;&|\s])(?:export\s+|set\s+|local\s+)?([A-Za-z_]\w*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]+)")
_ASIGNACION_NATURAL = re.compile(
    r"\b(?:guarda|define|almacena|asigna|save|store|set|put)\s+[\"'“](.+?)[\"'”]\s+(?:como|en|a|as|in|into|to)\s+(?:la variable\s+|variable\s+|the variable\s+)?\$?([A-Za-z_]\w*)", re.I)
_CONCAT_NATURAL = re.compile(r"\b(?:concatena|une|junta|combina|join|concatenate|combine)\s+\$?([A-Za-z_]\w*)\s*(?:y|con|and|with|\+|,)\s*\$?([A-Za-z_]\w*)", re.I)
_DESCARGA = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest)\b[^\n;|]*?(https?://[^\s'\"]+)[^\n;|]*?(?:\s(?:-o|-O|--output|-outfile)\s+(\S+))?|"
    r"\b(?:curl|wget)\b[^\n;|]*?\s(?:-o|-O|--output)\s+(\S+)[^\n;|]*?(https?://[^\s'\"]+)", re.I)


@dataclass
class Sesion:
    id: str
    pasos: int = 0
    lecturas_sensibles: list = field(default_factory=list)
    variables: dict = field(default_factory=dict)
    descargas: dict = field(default_factory=dict)    # ruta → url
    tokens: list = field(default_factory=list)
    marcada: bool = False
    historial: list = field(default_factory=list)

    def registrar_variables(self, texto: str) -> None:
        for m in _ASIGNACION.finditer(texto):
            v = m.group(2)
            if v[:1] in "\"'" and v[-1:] == v[:1]:
                v = v[1:-1]
            self.variables[m.group(1)] = v
        for m in _ASIGNACION_NATURAL.finditer(texto):
            self.variables[m.group(2)] = m.group(1)

    def expandir(self, texto: str) -> str:
        """Sustituye $X, ${X} y %X% con lo recordado. Si no hay nada que expandir, devuelve igual."""
        if not self.variables:
            return texto
        out = texto
        for k, v in sorted(self.variables.items(), key=lambda kv: -len(kv[0])):
            out = re.sub(r"\$\{" + re.escape(k) + r"\}|\$" + re.escape(k) + r"\b|%" + re.escape(k) + "%", lambda _m: v, out)
        for m in _CONCAT_NATURAL.finditer(texto):
            a, b = m.group(1), m.group(2)
            if a in self.variables and b in self.variables:
                out += "\n" + self.variables[a] + self.variables[b]
                out += "\n" + self.variables[a] + " " + self.variables[b]
        return out

    def registrar_descargas(self, texto: str, es_confiable) -> None:
        for m in _DESCARGA.finditer(texto):
            url = m.group(1) or m.group(4)
            ruta = m.group(2) or m.group(3)
            if not url:
                continue
            host = re.sub(r"^https?://", "", url, flags=re.I).split("/")[0].split("@")[-1].split(":")[0]
            if es_confiable(host):
                continue
            if not ruta:
                ruta = PurePosixPath(url.split("?")[0]).name or "descarga"
            self.descargas[ruta.strip("'\"")] = url

    def ejecuta_descarga(self, texto: str) -> str | None:
        """¿Este paso da permisos o ejecuta algo descargado antes de un dominio no confiable?"""
        for ruta in self.descargas:
            nombre = PurePosixPath(ruta).name
            for cand in {ruta, nombre}:
                c = re.escape(cand)
                if re.search(r"\bchmod\s+(?:\+x|[0-7]*[1357][0-7]{0,2}|u\+x|a\+x)\s+\S*" + c, texto, re.I) or \
                   re.search(r"(?:^|[\s;&|])(?:sudo\s+)?(?:(?:ba|z)?sh|python[23]?|perl|ruby|node|source|\.)\s+\S*" + c + r"\b", texto, re.I) or \
                   re.search(r"(?:^|[\s;&|])\./" + re.escape(nombre) + r"\b", texto) or \
                   re.search(r"\b(?:ejecuta|corre|lanza|run|execute|instala|install|abre|open)\b[^\n]*" + c, texto, re.I):
                    return ruta
        return None


class Sesiones:
    def __init__(self):
        self._s: dict[str, Sesion] = {}

    def obtener(self, sid: str) -> Sesion:
        if sid not in self._s:
            self._s[sid] = Sesion(sid)
        return self._s[sid]
