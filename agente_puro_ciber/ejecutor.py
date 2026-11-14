"""Ejecutor de la especialidad: lista cerrada, esquema exacto, token HMAC de un solo uso.

Todo efecto ocurre dentro de una carpeta sandbox. No hay shell, no hay red,
no hay escritura fuera de la sandbox. COMANDO_SIMULADO y CONSULTAR_URL solo
dejan constancia de lo que se habría hecho.

Defensa en profundidad: aunque una orden llegue con token válido, el ejecutor
vuelve a pasar sus parámetros por los detectores y rechaza si encuentra algo
ALTA o CRITICA. No interpreta los parámetros como órdenes; solo los revisa.
"""
from __future__ import annotations

import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from axiomas_gnostico.auditoria import Auditoria, sha256
from axiomas_gnostico.tipos import ErrorEsquema, ErrorProtocolo, ErrorToken, Orden
from axiomas_gnostico.tokens import ControladorTokens, Token

from .acciones import ESQUEMAS_CIBER, AccionCiber, DEFENSIVAS
from .hallazgos import Severidad


class EjecutorCiber:
    def __init__(self, controlador: ControladorTokens, auditoria: Auditoria,
                 sandbox: Optional[Path] = None, executor_id: str = "ejecutor_ciber"):
        self.controlador = controlador
        self.audit = auditoria
        self.executor_id = executor_id
        self.sandbox = Path(sandbox) if sandbox else Path(tempfile.mkdtemp(prefix="apc_sandbox_"))
        self.sandbox = self.sandbox.resolve()
        for sub in ("archivos", "cuarentena", "entrantes"):
            (self.sandbox / sub).mkdir(parents=True, exist_ok=True)
        self.outbox: list[dict] = []
        self.simulados: list[str] = []
        self.urls: list[str] = []
        self.bloqueos: set[str] = set()
        self.alertas: list[dict] = []
        self.ejecuciones: list[dict] = []   # registro local (además de la auditoría)
        self.activo = True
        self.revisor = None                  # callable(texto) -> list[Hallazgo]; lo pone el agente

    # -- validación --------------------------------------------------------
    @staticmethod
    def validar(orden: Orden) -> None:
        if not isinstance(orden, Orden):
            raise ErrorEsquema("el ejecutor no acepta texto libre ni objetos ajenos a Orden")
        if not isinstance(orden.accion, AccionCiber) or orden.accion not in ESQUEMAS_CIBER:
            raise ErrorEsquema(f"acción fuera de la lista cerrada: {orden.accion}")
        if any(k in orden.parametros for k in ("instruccion", "texto_libre", "prompt", "shell")):
            raise ErrorEsquema("el ejecutor no lee texto libre como orden")
        esquema = ESQUEMAS_CIBER[orden.accion]
        extras = set(orden.parametros) - set(esquema)
        faltan = set(esquema) - set(orden.parametros)
        if extras:
            raise ErrorEsquema(f"parámetros no permitidos: {sorted(extras)}")
        if faltan:
            raise ErrorEsquema(f"parámetros faltantes: {sorted(faltan)}")
        for k, typ in esquema.items():
            if not isinstance(orden.parametros[k], typ):
                raise ErrorEsquema(f"tipo inválido en {k}")

    def _ruta_en_sandbox(self, ruta: str) -> Path:
        p = (self.sandbox / ruta.lstrip("/\\")).resolve()
        if p != self.sandbox and self.sandbox not in p.parents:
            raise ErrorEsquema("ruta fuera de la sandbox")
        return p

    # -- ejecución ---------------------------------------------------------
    def ejecutar(self, orden: Orden, token: Optional[Token]) -> dict[str, Any]:
        if not self.activo:
            raise ErrorProtocolo("ejecutor aislado")
        self.validar(orden)
        if token is None:
            self.audit.registrar("EJECUCION_RECHAZADA", self.executor_id, {"orden_id": orden.id, "motivo": "sin token"})
            raise ErrorToken("ejecución sin token prohibida")
        try:
            self.controlador.verificar(token, orden, executor_id=self.executor_id)
        except ErrorToken as e:
            self.audit.registrar("EJECUCION_RECHAZADA", self.executor_id, {"orden_id": orden.id, "motivo": str(e)})
            raise
        if orden.accion not in DEFENSIVAS and self.revisor is not None:
            texto = " ".join(str(v) for v in orden.parametros.values())
            graves = [h for h in self.revisor(texto) if h.severidad >= Severidad.ALTA]
            if graves:
                self.audit.registrar("EJECUCION_RECHAZADA", self.executor_id, {
                    "orden_id": orden.id, "motivo": "parámetros peligrosos", "hallazgos": [h.tipo for h in graves]})
                raise ErrorProtocolo("parámetros peligrosos: el ejecutor no corre esto aunque haya token")
        out = self._aplicar(orden)
        reg = {"orden_id": orden.id, "accion": orden.accion.value, "token_id": token.token_id,
               "resultado": {k: v for k, v in out.items() if k != "contenido"}}
        self.ejecuciones.append(reg)
        self.audit.registrar("EJECUCION", self.executor_id, reg)
        return out

    def _anotar(self, archivo: str, obj: dict) -> None:
        with (self.sandbox / archivo).open("a", encoding="utf-8") as f:
            f.write(json.dumps(obj, ensure_ascii=False) + "\n")

    def _aplicar(self, orden: Orden) -> dict[str, Any]:
        p = orden.parametros
        a = orden.accion
        ahora = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        if a == AccionCiber.LEER_RECURSO:
            ruta = self._ruta_en_sandbox(p["recurso_id"])
            if not ruta.is_file():
                return {"ok": False, "error": "recurso inexistente en la sandbox", "recurso_id": p["recurso_id"]}
            return {"ok": True, "recurso_id": p["recurso_id"], "contenido": ruta.read_text(encoding="utf-8", errors="replace")}
        if a == AccionCiber.REPORTAR:
            return {"ok": True, "resumen": p["resumen"]}
        if a == AccionCiber.ENVIAR:
            msg = {"destinatario": p["destinatario"], "cuerpo": p["cuerpo"][:500]}
            self.outbox.append(msg)
            return {"ok": True, "enviado_simulado": msg}
        if a == AccionCiber.COMANDO_SIMULADO:
            self.simulados.append(p["comando"])
            self._anotar("comandos_simulados.jsonl", {"ts": ahora, "comando": p["comando"]})
            return {"ok": True, "simulado": True, "comando": p["comando"], "nota": "no se ejecutó en el sistema real"}
        if a == AccionCiber.CONSULTAR_URL:
            self.urls.append(p["url"])
            return {"ok": True, "simulado": True, "url": p["url"], "nota": "sin red: solo se registró"}
        if a == AccionCiber.ESCANEAR:
            raiz = self._ruta_en_sandbox(p["objetivo"])
            encontrados = []
            archivos = [raiz] if raiz.is_file() else sorted(x for x in raiz.rglob("*") if x.is_file()) if raiz.exists() else []
            for f in archivos:
                if self.sandbox / "cuarentena" in f.parents:
                    continue
                texto = f.read_text(encoding="utf-8", errors="replace")[:200_000]
                hs = self.revisor(texto) if self.revisor else []
                for h in hs:
                    if h.severidad >= Severidad.MEDIA:
                        encontrados.append({"archivo": str(f.relative_to(self.sandbox)), **h.a_dict()})
            return {"ok": True, "objetivo": p["objetivo"], "archivos": len(archivos), "hallazgos": encontrados}
        if a == AccionCiber.CUARENTENA_ARCHIVO:
            destino_dir = self.sandbox / "cuarentena"
            if p["contenido"]:
                nombre = Path(p["ruta"]).name or sha256(p["contenido"])[:16]
                destino = destino_dir / f"{nombre}.cuarentena"
                destino.write_text(p["contenido"], encoding="utf-8")
            else:
                origen = self._ruta_en_sandbox(p["ruta"])
                if not origen.is_file():
                    return {"ok": False, "error": "archivo inexistente en la sandbox", "ruta": p["ruta"]}
                destino = destino_dir / f"{origen.name}.cuarentena"
                shutil.move(str(origen), str(destino))
            man = {"ts": ahora, "ruta": p["ruta"], "destino": str(destino.relative_to(self.sandbox)), "motivo": p["motivo"]}
            self._anotar("cuarentena/manifiesto.jsonl", man)
            return {"ok": True, **man}
        if a == AccionCiber.BLOQUEAR_ACCION:
            self.bloqueos.add(p["huella"])
            self._anotar("bloqueos.jsonl", {"ts": ahora, **p})
            return {"ok": True, "huella": p["huella"]}
        if a == AccionCiber.ALERTAR:
            al = {"ts": ahora, "severidad": p["severidad"], "mensaje": p["mensaje"][:300]}
            self.alertas.append(al)
            self._anotar("alertas.jsonl", al)
            return {"ok": True, **al}
        if a == AccionCiber.REVOCAR_TOKEN:
            self.controlador.revocar_token(p["token_id"])
            return {"ok": True, "revocado": p["token_id"]}
        raise ErrorEsquema("acción no implementada")
