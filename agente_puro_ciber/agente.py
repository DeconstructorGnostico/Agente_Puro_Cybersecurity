"""Agente Puro Cybersecurity: orquestador.

Flujo por petición:
 1. Integridad: cadena de auditoría y sello de la base de conocimiento. Si fallan → HALT.
 2. Lectura en capas (normalizar.py) del canal INTENCIÓN y del canal DATO.
 3. Memoria de sesión: expande variables, ve lecturas sensibles previas y descargas.
 4. Detectores → hallazgos tipados con severidad y hecho verificado.
 5. CVA (axiomas_gnostico) juzga la petición con sus tres axiomas; se reporta su estado
    y sus estados de verdad. Si CVA rechaza por Respeto, cuenta como hallazgo.
 6. Decisión con reglas fijas:
      ALTA/CRITICA respaldada por un hecho  → BLOQUEAR (o CUARENTENA si solo el dato es hostil)
      MEDIA (heurística o sensible sin envío) → INDETERMINADO
      nada, y la tarea se entiende           → PERMITIR (las órdenes quedan pendientes de token)
      nada, pero la tarea no se entiende     → INDETERMINADO
    Nunca PERMITIR por defecto.
 7. Respuesta defensiva automática (BLOQUEAR_ACCION, ALERTAR, CUARENTENA_ARCHIVO,
    REVOCAR_TOKEN), cada una con su token de un solo uso y auditada.
"""
from __future__ import annotations

import re
import secrets
from pathlib import Path
from typing import Any, Optional

from axiomas_gnostico.auditoria import sha256
from axiomas_gnostico.sistema import SistemaPerfeccionado
from axiomas_gnostico.tipos import EstadoResultado, EstadoVerdad, Orden, Origen

from . import conocimiento
from .acciones import DEFENSIVAS, AccionCiber
from .detectores import (DOMINIOS_CONFIABLES_POR_DEFECTO, ENVIO_CURL, ENVIO_DATOS, ENVIO_NATURAL, EJECUCION,
                         EXPLICACION, Contexto, _clasificar_host, _dominio_confiable, destinos_en, detectar)
from .ejecutor import EjecutorCiber
from .hallazgos import Decision, Hallazgo, ResultadoCiber, Severidad as S
from .interprete import proponer
from .normalizar import leer
from .sesion import Sesiones

_REFERENCIA_PREVIA = re.compile(
    r"\b(?:lo|la|los|las|eso|esto|ese|esa|el contenido|el resultado|la salida|lo anterior|lo que le[ií]ste|it|that|this|them|the output|the result|the contents|what you read|previous)\b|@-|\$\(|`", re.I)


class AgentePuroCiber:
    def __init__(self, secreto: Optional[bytes] = None, sandbox: Optional[Path] = None,
                 dominios_confiables=None, ttl: float = 300.0):
        self.cva = SistemaPerfeccionado(secreto=secreto, ttl=ttl)
        self.audit = self.cva.audit                 # una sola cadena de auditoría
        self.controlador = self.cva.controlador     # un solo dueño de la llave HMAC
        self.confiables = frozenset(dominios_confiables or DOMINIOS_CONFIABLES_POR_DEFECTO)
        self.ejecutor = EjecutorCiber(self.controlador, self.audit, sandbox=sandbox)
        self.ejecutor.revisor = self._revisar_texto
        self.sesiones = Sesiones()
        self.pendientes: dict[str, tuple[Orden, str]] = {}
        self.halt: Optional[str] = None
        self.audit.registrar("ARRANQUE", "AGENTE_PURO_CIBER", {
            "sello_conocimiento": conocimiento.SELLO, "hechos": len(conocimiento.HECHOS),
            "sandbox": self.ejecutor.sandbox.name,
        })

    # ------------------------------------------------------------------
    def _revisar_texto(self, texto: str) -> list[Hallazgo]:
        return detectar(leer(texto), Contexto("INTENCION", self.confiables, False), [])

    def _orden(self, accion: AccionCiber, params: dict, causa: str) -> Orden:
        o = Orden(id=secrets.token_hex(6), accion=accion, parametros=dict(params), causa_id=causa,
                  intencion_hash=causa, origen=Origen.INTENCION,
                  riesgo="DEFENSIVA" if accion in DEFENSIVAS else "NORMAL")
        o.hash = sha256(o.a_dict())
        return o

    def _defensiva(self, accion: AccionCiber, params: dict, causa: str, sesion) -> dict:
        """Las defensivas las autoaprueba el controlador, pero igual pasan por token y ejecutor."""
        o = self._orden(accion, params, causa)
        tok = self.controlador.emitir(o, executor_id=self.ejecutor.executor_id)
        self.audit.registrar("AUTORIZACION", "CONTROLADOR:politica_defensiva", {"orden_id": o.id, "accion": accion.value, "token_id": tok.token_id})
        out = self.ejecutor.ejecutar(o, tok)
        return {"accion": accion.value, "ok": bool(out.get("ok")), "token_id": tok.token_id,
                "detalle": {k: v for k, v in out.items() if k in ("huella", "destino", "revocado", "severidad", "ruta")}}

    def _integridad(self) -> Optional[str]:
        if not self.audit.verificar():
            return "CADENA_AUDITORIA_ROTA"
        if not conocimiento.verificar_sello():
            return "CONOCIMIENTO_MUTADO"
        return None

    # ------------------------------------------------------------------
    def evaluar(self, texto: str, documento: Optional[str] = None, sesion: str = "default",
                origen_dato: str = "documento") -> ResultadoCiber:
        texto = texto or ""
        ses = self.sesiones.obtener(sesion)
        ses.pasos += 1
        huella = sha256(leer(texto).plano.strip().lower())
        self.audit.registrar("PETICION", "INICIADOR", {"sesion": sesion, "paso": ses.pasos, "huella": huella,
                                                       "texto": texto[:300], "documento": bool(documento), "origen_dato": origen_dato})
        motivo_halt = self.halt or self._integridad()
        if motivo_halt:
            self.halt = motivo_halt
            return ResultadoCiber(Decision.INDETERMINADO, f"HALT: {motivo_halt}. No se decide nada sin integridad.",
                                  S.NINGUNA, audit_hash=self.audit.cabeza, sesion=sesion)

        # 1. Lectura en capas + memoria de sesión
        lec = leer(texto)
        ses.registrar_variables(lec.plano)
        expandido = ses.expandir(lec.plano)
        if expandido != lec.plano:
            lec.capas["expandido_sesion"] = expandido
        explicacion = bool(EXPLICACION.search(lec.plano)) and not EJECUCION.search(lec.plano)
        ctx = Contexto("INTENCION", self.confiables, explicacion)
        lecturas_previas = list(ses.lecturas_sensibles)
        hallazgos = detectar(lec, ctx, ses.lecturas_sensibles)
        banderas = list(lec.banderas)
        # Lo que solo apareció al expandir variables de la sesión es un ataque partido.
        for h in hallazgos:
            if h.capa == "expandido_sesion" and h.severidad >= S.ALTA:
                hallazgos.append(Hallazgo("CADENA_ATAQUE", "variables_partidas", S.CRITICA,
                                          f"{h.tipo} armado con variables de pasos anteriores", h.hecho_id, "INTENCION", "expandido_sesion"))
                break

        # 2. Canal DATO
        if documento:
            lec_d = leer(documento)
            ctx_d = Contexto("DATO", self.confiables, False)
            hallazgos += detectar(lec_d, ctx_d, [])
            banderas += [f"dato:{b}" for b in lec_d.banderas]

        # 3. Cadenas de varios pasos
        envio = ENVIO_CURL.search(expandido) or ENVIO_DATOS.search(expandido) or ENVIO_NATURAL.search(expandido)
        if lecturas_previas and envio and not explicacion:
            destinos = destinos_en(expandido)
            externos = [d for d in destinos if not _dominio_confiable(d, self.confiables)]
            if externos or (not destinos and _REFERENCIA_PREVIA.search(expandido)):
                tipo, ruta, hid = lecturas_previas[-1]
                hallazgos.append(Hallazgo("CADENA_ATAQUE", "lectura_sensible_y_envio", S.CRITICA,
                                          f"paso previo leyó {ruta}; ahora envía a {externos[0] if externos else 'destino no declarado'}",
                                          "KB-RED-005", "INTENCION", "sesion"))
            elif destinos:
                hallazgos.append(Hallazgo("CADENA_ATAQUE", "lectura_sensible_y_envio_confiable", S.MEDIA,
                                          f"envío a destino de confianza después de leer {lecturas_previas[-1][1]}", None, "INTENCION", "sesion",
                                          "dato sensible hacia destino confiable: necesita confirmación humana"))
        descargado = ses.ejecuta_descarga(expandido)
        if descargado and not explicacion:
            hallazgos.append(Hallazgo("CADENA_ATAQUE", "descarga_y_ejecucion", S.ALTA,
                                      f"ejecuta o da permisos a {descargado}, bajado de {ses.descargas[descargado]}",
                                      "KB-CMD-005", "INTENCION", "sesion"))
        ses.registrar_descargas(expandido, lambda h: _dominio_confiable(h, self.confiables) or _clasificar_host(h)[0] in ("LOOPBACK", "PRIVADA"))

        # 4. CVA: los tres axiomas sobre la misma petición
        cva_res = self.cva.peticion(texto, documento=documento)
        cva = {"estado": cva_res.estado.value,
               "verdades": {k: v.value for k, v in cva_res.verdades.items()}}
        if cva_res.estado == EstadoResultado.RECHAZADO_RESPETO:
            hallazgos.append(Hallazgo("POLITICA_CVA", "respeto_sobre_supervivencia", S.ALTA, cva_res.mensaje[:120],
                                      "KB-PRM-001" if documento else "KB-CMD-001", "INTENCION", "cva"))
        if any(v in (EstadoVerdad.REFUTED, EstadoVerdad.CONTRADICTED) for v in cva_res.verdades.values()):
            hallazgos.append(Hallazgo("POLITICA_CVA", "afirmacion_falsa", S.MEDIA, "CVA: REFUTED/CONTRADICTED", None, "INTENCION", "cva",
                                      "una afirmación de la petición choca con lo verificado"))

        # 5. Decisión
        res = self._decidir(texto, hallazgos, ses, huella)
        res.banderas = banderas
        res.cva = cva
        res.pasos_sesion = ses.pasos

        # 6. Respuesta defensiva
        causa = huella[:16]
        if res.decision in (Decision.BLOQUEAR, Decision.CUARENTENA):
            res.respuestas.append(self._defensiva(AccionCiber.BLOQUEAR_ACCION, {"huella": huella, "motivo": res.motivo[:200]}, causa, ses))
            res.respuestas.append(self._defensiva(AccionCiber.ALERTAR, {"severidad": res.severidad.name, "mensaje": res.motivo[:300]}, causa, ses))
            if documento and any(h.canal == "DATO" and h.severidad >= S.ALTA for h in res.hallazgos):
                res.respuestas.append(self._defensiva(AccionCiber.CUARENTENA_ARCHIVO, {
                    "ruta": f"entrantes/{sha256(documento)[:16]}.txt", "motivo": "inyección o carga peligrosa en el canal DATO",
                    "contenido": documento}, causa, ses))
            if any(h.categoria == "CADENA_ATAQUE" and h.severidad >= S.ALTA for h in res.hallazgos):
                # Ataque en varios pasos: la sesión queda marcada y se revocan sus tokens operativos.
                ses.marcada = True
                for oid, (o, sid) in list(self.pendientes.items()):
                    if sid == sesion:
                        self.pendientes.pop(oid)
                        self.audit.registrar("DENEGACION", "CONTROLADOR:politica_defensiva", {"orden_id": oid, "motivo": "sesión hostil"})
                for tid in list(ses.tokens)[-10:]:
                    res.respuestas.append(self._defensiva(AccionCiber.REVOCAR_TOKEN, {"token_id": tid}, causa, ses))
        # Defensivas pedidas por el iniciador y permitidas: quedan como propuestas, igual que el resto.
        for o in res.ordenes:
            self.pendientes[o.id] = (o, sesion)

        reg = self.audit.registrar("DECISION", "AGENTE_PURO_CIBER", {
            "sesion": sesion, "paso": ses.pasos, "decision": res.decision.value, "severidad": res.severidad.name,
            "motivo": res.motivo[:200], "hallazgos": [(h.categoria, h.tipo, h.severidad.name, h.hecho_id) for h in res.hallazgos],
            "ordenes": [o.id for o in res.ordenes],
        })
        res.audit_hash = reg["hash"]
        ses.historial.append(res.decision.value)
        return res

    def _decidir(self, texto: str, hallazgos: list[Hallazgo], ses, huella: str) -> ResultadoCiber:
        hallazgos = sorted(hallazgos, key=lambda h: -h.severidad)
        sev = hallazgos[0].severidad if hallazgos else S.NINGUNA
        base = dict(hallazgos=hallazgos, sesion=ses.id, severidad=sev)
        if huella in self.ejecutor.bloqueos:
            return ResultadoCiber(Decision.BLOQUEAR, "Esta misma acción ya fue bloqueada antes.", **{**base, "severidad": max(sev, S.ALTA)})
        graves = [h for h in hallazgos if h.severidad >= S.ALTA and h.hecho_id]
        if graves:
            solo_dato = all(h.canal == "DATO" for h in graves)
            hechos = sorted({h.hecho_id for h in graves})
            cats = sorted({h.categoria for h in graves})
            if solo_dato:
                return ResultadoCiber(Decision.CUARENTENA,
                                      f"El dato trae órdenes o cargas peligrosas ({', '.join(cats)}). Se aísla; el dato no da órdenes. Evidencia: {', '.join(hechos)}.", **base)
            return ResultadoCiber(Decision.BLOQUEAR, f"Ataque confirmado por conocimiento verificado ({', '.join(cats)}). Evidencia: {', '.join(hechos)}.", **base)
        if sev >= S.MEDIA:
            cats = sorted({h.categoria for h in hallazgos if h.severidad >= S.MEDIA})
            return ResultadoCiber(Decision.INDETERMINADO,
                                  f"No lo sé: hay señales ({', '.join(cats)}) sin evidencia suficiente para confirmar un ataque ni para permitirlo. Necesita a un humano.", **base)
        if ses.marcada:
            return ResultadoCiber(Decision.INDETERMINADO, "La sesión quedó marcada por un ataque previo; no se permite nada más en ella sin revisión.", **base)
        props = proponer(texto, self.confiables)
        if not props:
            return ResultadoCiber(Decision.INDETERMINADO, "No lo sé: no reconozco esta tarea y no permito lo que no entiendo.", **base)
        ordenes = [self._orden(a, p, huella[:16]) for a, p in props]
        nota = " (hay menciones de bajo riesgo, ver hallazgos)" if hallazgos else ""
        return ResultadoCiber(Decision.PERMITIR, "Tarea reconocida y sin señales de ataque. Las órdenes esperan token." + nota,
                              ordenes=ordenes, **base)

    # ------------------------------------------------------------------
    def autorizar(self, orden_id: str, por: str = "iniciador"):
        """El controlador firma solo órdenes que salieron de una decisión PERMITIR."""
        if self.halt:
            raise RuntimeError("agente en HALT")
        if orden_id not in self.pendientes:
            raise KeyError(f"orden no pendiente: {orden_id}")
        orden, sid = self.pendientes[orden_id]
        tok = self.controlador.emitir(orden, executor_id=self.ejecutor.executor_id)
        self.sesiones.obtener(sid).tokens.append(tok.token_id)
        self.audit.registrar("AUTORIZACION", f"CONTROLADOR:{por}", {"orden_id": orden_id, "token_id": tok.token_id})
        return tok

    def ejecutar(self, orden: Orden, token) -> dict[str, Any]:
        out = self.ejecutor.ejecutar(orden, token)
        self.pendientes.pop(orden.id, None)
        return out

    def autorizar_y_ejecutar(self, res: ResultadoCiber, por: str = "iniciador") -> list[dict]:
        if res.decision != Decision.PERMITIR:
            raise PermissionError(f"decisión {res.decision.value}: no hay nada que autorizar")
        return [self.ejecutar(o, self.autorizar(o.id, por)) for o in res.ordenes]

    def auditoria_integra(self) -> bool:
        return self.audit.verificar()
