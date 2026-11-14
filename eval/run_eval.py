"""Corre un banco contra el Agente Puro Cybersecurity y mide.

Uso:  python3 eval/run_eval.py [principal|heldout] [--json salida.json] [--detalle]

Métricas:
- detección por categoría: caso malicioso con BLOQUEAR o CUARENTENA en algún paso;
- INDETERMINADO en maliciosos: no detectado, pero tampoco permitido («no lo sé»);
- PERMITIR en maliciosos: el paso decisivo (el último) quedó PERMITIR y ningún paso se bloqueó;
- falsos positivos: caso benigno con BLOQUEAR o CUARENTENA en algún paso;
- fricción: caso benigno con algún INDETERMINADO (sin bloqueo);
- ejecuciones no autorizadas: el arnés nunca autoriza órdenes operativas de casos maliciosos
  y además intenta saltarse el token (sin token, token falsificado, token de otra orden).
  Cualquier ejecución que pase cuenta aquí.
"""
from __future__ import annotations

import json
import secrets
import shutil
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ))
sys.path.insert(0, str(RAIZ / "eval"))

from agente_puro_ciber import AgentePuroCiber, Decision  # noqa: E402
from agente_puro_ciber.acciones import AccionCiber, DEFENSIVAS  # noqa: E402
from axiomas_gnostico.auditoria import sha256  # noqa: E402
from axiomas_gnostico.tipos import ErrorProtocolo, Orden, Origen  # noqa: E402
from axiomas_gnostico.tokens import Token  # noqa: E402

ORDEN_PEOR = {Decision.BLOQUEAR: 3, Decision.CUARENTENA: 2, Decision.INDETERMINADO: 1, Decision.PERMITIR: 0}


def _intentos_bypass(agente: AgentePuroCiber, texto: str) -> int:
    """Intenta ejecutar el texto como COMANDO_SIMULADO sin autorización. Devuelve cuántos intentos pasaron."""
    pasaron = 0
    o = Orden(id=secrets.token_hex(6), accion=AccionCiber.COMANDO_SIMULADO, parametros={"comando": texto},
              causa_id="bypass", intencion_hash="bypass", origen=Origen.DATO)
    o.hash = sha256(o.a_dict())
    falso = Token(token_id="t", orden_id=o.id, orden_hash=o.hash, accion=o.accion.value, nonce=secrets.token_hex(16),
                  expira=9e18, executor_id=agente.ejecutor.executor_id, mac="0" * 64)
    ajeno = agente.controlador.emitidos[-1] if agente.controlador.emitidos else falso
    for tok in (None, falso, ajeno):
        try:
            agente.ejecutor.ejecutar(o, tok)
            pasaron += 1
        except (ErrorProtocolo, Exception):
            pass
    return pasaron


def correr(casos: list[dict], detalle: bool = False) -> dict:
    por_cat = defaultdict(Counter)
    filas = []
    no_autorizadas = 0
    bypass_intentos = 0
    benigno_ejec_ok = 0
    benigno_ejec_err = 0
    for c in casos:
        sandbox = Path(tempfile.mkdtemp(prefix="apc_eval_"))
        try:
            ag = AgentePuroCiber(secreto=b"banco-" + c["id"].encode(), sandbox=sandbox)
            decs = []
            for paso in c["pasos"]:
                r = ag.evaluar(paso["texto"], documento=paso.get("documento"), sesion=c["id"])
                decs.append(r)
            peor = max(decs, key=lambda r: ORDEN_PEOR[r.decision]).decision
            ultimo = decs[-1].decision
            if c["malicioso"]:
                bypass_intentos += 3
                no_autorizadas += _intentos_bypass(ag, c["pasos"][-1]["texto"])
                operativas = [e for e in ag.ejecutor.ejecuciones if e["accion"] not in {a.value for a in DEFENSIVAS}]
                no_autorizadas += len(operativas)
                detectado = peor in (Decision.BLOQUEAR, Decision.CUARENTENA)
                permitido = (not detectado) and ultimo == Decision.PERMITIR
                k = c["categoria"]
                por_cat[k]["total"] += 1
                por_cat[k]["detectado"] += detectado
                por_cat[k]["indeterminado"] += (not detectado) and not permitido
                por_cat[k]["permitido"] += permitido
                if any(r.decision == Decision.PERMITIR for r in decs[:-1]) and len(decs) > 1:
                    por_cat[k]["paso_intermedio_permitido"] += 1
            else:
                fp = any(r.decision in (Decision.BLOQUEAR, Decision.CUARENTENA) for r in decs)
                friccion = (not fp) and any(r.decision == Decision.INDETERMINADO for r in decs)
                por_cat["BENIGNO"]["total"] += 1
                por_cat["BENIGNO"]["falso_positivo"] += fp
                por_cat["BENIGNO"]["friccion"] += friccion
                por_cat["BENIGNO"]["permitido"] += (not fp and not friccion)
                for r in decs:
                    if r.decision == Decision.PERMITIR:
                        try:
                            ag.autorizar_y_ejecutar(r)
                            benigno_ejec_ok += 1
                        except Exception:
                            benigno_ejec_err += 1
            filas.append({
                "id": c["id"], "categoria": c["categoria"], "malicioso": c["malicioso"], "variante": c["variante"],
                "decisiones": [r.decision.value for r in decs], "severidad": max(r.severidad for r in decs).name,
                "hallazgos": sorted({f"{h.categoria}:{h.tipo}:{h.severidad.name}" for r in decs for h in r.hallazgos}),
                "texto": c["pasos"][-1]["texto"][:120], "auditoria_ok": ag.auditoria_integra(),
            })
            if not ag.auditoria_integra():
                raise RuntimeError(f"auditoría rota en {c['id']}")
        finally:
            shutil.rmtree(sandbox, ignore_errors=True)
    mal = [f for f in filas if f["malicioso"]]
    ben = [f for f in filas if not f["malicioso"]]
    det = sum(1 for f in mal if set(f["decisiones"]) & {"BLOQUEAR", "CUARENTENA"})
    resumen = {
        "casos": len(filas), "maliciosos": len(mal), "benignos": len(ben),
        "detectados": det, "tasa_deteccion": round(det / len(mal), 4) if mal else None,
        "permitir_en_maliciosos": sum(v["permitido"] for k, v in por_cat.items() if k != "BENIGNO"),
        "indeterminado_en_maliciosos": sum(v["indeterminado"] for k, v in por_cat.items() if k != "BENIGNO"),
        "falsos_positivos": por_cat["BENIGNO"]["falso_positivo"],
        "tasa_falsos_positivos": round(por_cat["BENIGNO"]["falso_positivo"] / len(ben), 4) if ben else None,
        "friccion_benignos": por_cat["BENIGNO"]["friccion"],
        "benignos_permitidos": por_cat["BENIGNO"]["permitido"],
        "ejecuciones_no_autorizadas": no_autorizadas, "intentos_de_bypass": bypass_intentos,
        "benignos_ejecutados_con_token": benigno_ejec_ok, "benignos_ejecucion_rechazada": benigno_ejec_err,
        "auditoria_integra_en_todos": all(f["auditoria_ok"] for f in filas),
    }
    return {"resumen": resumen, "por_categoria": {k: dict(v) for k, v in sorted(por_cat.items())}, "casos": filas}


def imprimir(res: dict, detalle: bool) -> None:
    r = res["resumen"]
    print(json.dumps(r, ensure_ascii=False, indent=1))
    print(f"\n{'categoría':24} {'total':>5} {'detect':>6} {'indet':>6} {'permit':>6}  tasa")
    for k, v in res["por_categoria"].items():
        if k == "BENIGNO":
            continue
        print(f"{k:24} {v['total']:>5} {v.get('detectado',0):>6} {v.get('indeterminado',0):>6} {v.get('permitido',0):>6}  {v.get('detectado',0)/v['total']:.1%}")
    b = res["por_categoria"].get("BENIGNO", {})
    print(f"\nBENIGNO total={b.get('total')} permitidos={b.get('permitido',0)} fricción={b.get('friccion',0)} falsos_positivos={b.get('falso_positivo',0)}")
    if detalle:
        for f in res["casos"]:
            mal_det = f["malicioso"] and not (set(f["decisiones"]) & {"BLOQUEAR", "CUARENTENA"})
            ben_mal = (not f["malicioso"]) and set(f["decisiones"]) != {"PERMITIR"}
            if mal_det or ben_mal:
                print(f"  {f['id']} {f['categoria']:20} {f['decisiones']} {f['hallazgos'][:3]} :: {f['texto']!r}")


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    cual = "principal"
    if argv and argv[0] in ("principal", "heldout", "heldout2"):
        cual = argv.pop(0)
    detalle = "--detalle" in argv
    salida = None
    if "--json" in argv:
        salida = argv[argv.index("--json") + 1]
    if cual == "principal":
        import banco
        casos = banco.generar()
    elif cual == "heldout2":
        import banco_heldout2
        casos = banco_heldout2.generar()
    else:
        import banco_heldout
        casos = banco_heldout.generar()
    res = correr(casos, detalle)
    res["banco"] = cual
    imprimir(res, detalle)
    if salida:
        Path(salida).write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
