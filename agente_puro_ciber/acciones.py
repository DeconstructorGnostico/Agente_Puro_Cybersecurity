"""Lista cerrada de acciones del Agente Puro Cybersecurity.

Operativas (necesitan que el iniciador autorice, y luego un token):
    LEER_RECURSO, REPORTAR, ENVIAR, COMANDO_SIMULADO, CONSULTAR_URL
Defensivas (el controlador las autoaprueba porque reducen capacidad, pero
igual llevan token de un solo uso y quedan auditadas):
    ESCANEAR, CUARENTENA_ARCHIVO, BLOQUEAR_ACCION, ALERTAR, REVOCAR_TOKEN

No existe una acción «ejecutar comando real» ni «hacer petición de red real».
COMANDO_SIMULADO y CONSULTAR_URL solo dejan constancia en la sandbox.
"""
from __future__ import annotations

from enum import Enum


class AccionCiber(str, Enum):
    LEER_RECURSO = "LEER_RECURSO"
    REPORTAR = "REPORTAR"
    ENVIAR = "ENVIAR"
    COMANDO_SIMULADO = "COMANDO_SIMULADO"
    CONSULTAR_URL = "CONSULTAR_URL"
    ESCANEAR = "ESCANEAR"
    CUARENTENA_ARCHIVO = "CUARENTENA_ARCHIVO"
    BLOQUEAR_ACCION = "BLOQUEAR_ACCION"
    ALERTAR = "ALERTAR"
    REVOCAR_TOKEN = "REVOCAR_TOKEN"


ESQUEMAS_CIBER: dict[AccionCiber, dict[str, type]] = {
    AccionCiber.LEER_RECURSO: {"recurso_id": str},
    AccionCiber.REPORTAR: {"resumen": str},
    AccionCiber.ENVIAR: {"destinatario": str, "cuerpo": str},
    AccionCiber.COMANDO_SIMULADO: {"comando": str},
    AccionCiber.CONSULTAR_URL: {"url": str},
    AccionCiber.ESCANEAR: {"objetivo": str},
    AccionCiber.CUARENTENA_ARCHIVO: {"ruta": str, "motivo": str, "contenido": str},
    AccionCiber.BLOQUEAR_ACCION: {"huella": str, "motivo": str},
    AccionCiber.ALERTAR: {"severidad": str, "mensaje": str},
    AccionCiber.REVOCAR_TOKEN: {"token_id": str},
}

DEFENSIVAS = frozenset({
    AccionCiber.ESCANEAR, AccionCiber.CUARENTENA_ARCHIVO, AccionCiber.BLOQUEAR_ACCION,
    AccionCiber.ALERTAR, AccionCiber.REVOCAR_TOKEN,
})
OPERATIVAS = frozenset(set(AccionCiber) - DEFENSIVAS)
