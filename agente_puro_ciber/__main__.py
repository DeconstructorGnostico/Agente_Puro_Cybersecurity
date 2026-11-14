"""CLI: python3 -m agente_puro_ciber "texto o comando" [--documento "..."] [--json] | --demo"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from .agente import AgentePuroCiber


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="agente_puro_ciber",
                                description="Agente Puro Cybersecurity: decide PERMITIR, BLOQUEAR, CUARENTENA o INDETERMINADO")
    p.add_argument("texto", nargs="*", help="petición o comando a evaluar (canal INTENCIÓN)")
    p.add_argument("--documento", "--dato", dest="documento", default=None,
                   help="documento, resultado de herramienta o página web (canal DATO: no da órdenes)")
    p.add_argument("--origen", default="documento", help="origen del dato: documento | herramienta | web")
    p.add_argument("--json", action="store_true", help="salida en JSON")
    p.add_argument("--demo", action="store_true", help="corre los 8 escenarios de demostración")
    argv = list(sys.argv[1:] if argv is None else argv)
    if any(a in ("-h", "--help") for a in argv):
        p.print_help()
        return 0
    # Todo lo que no sea una opción nuestra es texto, en su orden original
    # (así «rm -rf /» funciona aun sin comillas).
    propias, texto, i = [], [], 0
    while i < len(argv):
        a = argv[i]
        if a in ("--json", "--demo"):
            propias.append(a)
        elif a in ("--documento", "--dato", "--origen") and i + 1 < len(argv):
            propias += [a, argv[i + 1]]
            i += 1
        else:
            texto.append(a)
        i += 1
    args = p.parse_args(propias)
    args.texto = texto
    if args.demo:
        from .demo import correr
        log = correr()
        return 0 if all(x["ok"] for x in log) else 1
    texto = " ".join(args.texto).strip()
    if not texto:
        p.print_help()
        return 2
    with tempfile.TemporaryDirectory(prefix="apc_cli_") as tmp:
        ag = AgentePuroCiber(sandbox=Path(tmp))
        r = ag.evaluar(texto, documento=args.documento, origen_dato=args.origen)
    return _imprimir(r, args.json)


def _imprimir(r, como_json: bool) -> int:
    if como_json:
        print(json.dumps(r.a_dict(), ensure_ascii=False, indent=2))
        return 0
    print(f"decisión:  {r.decision.value}")
    print(f"severidad: {r.severidad.name}")
    print(f"motivo:    {r.motivo}")
    for h in r.hallazgos:
        print(f"  - {h.categoria}/{h.tipo} {h.severidad.name} verdad={h.verdad.value}"
              + (f" evidencia={h.hecho_id}" if h.hecho_id else "") + f" :: {h.evidencia[:80]!r}" + (f" ({h.nota})" if h.nota else ""))
    if r.ordenes:
        print("órdenes propuestas (esperan token; no se ejecutan desde la CLI):")
        for o in r.ordenes:
            print(f"  - {o.accion.value} {o.parametros}")
    if r.respuestas:
        print("respuesta defensiva (simulada en sandbox, con token):")
        for x in r.respuestas:
            print(f"  - {x['accion']} ok={x['ok']}")
    if r.banderas:
        print(f"ofuscación detectada: {r.banderas}")
    print(f"CVA: {r.cva.get('estado')}  ·  auditoría: {r.audit_hash}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
