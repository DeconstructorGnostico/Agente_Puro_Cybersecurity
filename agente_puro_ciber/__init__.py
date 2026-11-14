"""Agente Puro Cybersecurity: especialidad de ciberseguridad del Cerebro Verificador de Agentes (CVA).

El intérprete propone; el ejecutor solo corre órdenes de una lista cerrada con un
token HMAC de un solo uso; la auditoría es una cadena SHA-256; «no lo sé»
(INDETERMINADO) es una respuesta válida y segura.
"""
from .agente import AgentePuroCiber
from .hallazgos import Decision, Hallazgo, ResultadoCiber, Severidad
from .acciones import AccionCiber

VERSION = "1.1.0"
__all__ = ["AgentePuroCiber", "Decision", "Hallazgo", "ResultadoCiber", "Severidad", "AccionCiber", "VERSION"]
