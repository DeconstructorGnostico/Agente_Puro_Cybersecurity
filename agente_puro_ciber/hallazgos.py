"""Tipos de la especialidad: severidad, hallazgo, decisión."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from axiomas_gnostico.tipos import EstadoVerdad


class Severidad(int, Enum):
    NINGUNA = 0
    BAJA = 1
    MEDIA = 2
    ALTA = 3
    CRITICA = 4


class Decision(str, Enum):
    PERMITIR = "PERMITIR"
    BLOQUEAR = "BLOQUEAR"
    CUARENTENA = "CUARENTENA"
    INDETERMINADO = "INDETERMINADO"


CATEGORIAS = (
    "INYECCION_PROMPT", "ROBO_CREDENCIALES", "COMANDO_PELIGROSO", "EXFILTRACION",
    "ESCALADA_PRIVILEGIOS", "PERSISTENCIA", "SSRF", "PATH_TRAVERSAL", "INYECCION_SQL",
    "INYECCION_COMANDOS", "CADENA_ATAQUE", "SHELL_INVERSA", "EXPLOIT_CVE", "OFUSCACION",
    "POLITICA_CVA",
)


@dataclass
class Hallazgo:
    categoria: str
    tipo: str
    severidad: Severidad
    evidencia: str
    hecho_id: Optional[str] = None      # hecho verificado que lo respalda (conocimiento.py)
    canal: str = "INTENCION"            # INTENCION | DATO
    capa: str = "original"              # en qué capa de lectura apareció
    nota: str = ""

    def __post_init__(self):
        # Regla central: sin hecho verificado no se pasa de MEDIA («no lo sé» > «lo sé»).
        if self.hecho_id is None and self.severidad > Severidad.MEDIA:
            self.severidad = Severidad.MEDIA

    @property
    def verdad(self) -> EstadoVerdad:
        """«Esto es un ataque» solo es SUPPORTED si un hecho verificado lo respalda."""
        return EstadoVerdad.SUPPORTED if self.hecho_id else EstadoVerdad.UNDETERMINED

    def a_dict(self) -> dict:
        return {
            "categoria": self.categoria, "tipo": self.tipo, "severidad": self.severidad.name,
            "evidencia": self.evidencia[:160], "hecho_id": self.hecho_id, "canal": self.canal,
            "capa": self.capa, "verdad": self.verdad.value, "nota": self.nota,
        }


@dataclass
class ResultadoCiber:
    decision: Decision
    motivo: str
    severidad: Severidad
    hallazgos: list[Hallazgo] = field(default_factory=list)
    ordenes: list = field(default_factory=list)            # propuestas (Orden) pendientes de token
    respuestas: list[dict] = field(default_factory=list)   # acciones defensivas ya ejecutadas con token
    audit_hash: str = ""
    sesion: str = "default"
    banderas: list[str] = field(default_factory=list)
    cva: dict = field(default_factory=dict)
    pasos_sesion: int = 0

    def a_dict(self) -> dict:
        return {
            "decision": self.decision.value, "motivo": self.motivo,
            "severidad": self.severidad.name,
            "hallazgos": [h.a_dict() for h in self.hallazgos],
            "ordenes_propuestas": [o.a_dict() for o in self.ordenes],
            "respuestas_defensivas": list(self.respuestas),
            "audit_hash": self.audit_hash, "sesion": self.sesion,
            "banderas_ofuscacion": list(self.banderas), "cva": dict(self.cva),
        }
