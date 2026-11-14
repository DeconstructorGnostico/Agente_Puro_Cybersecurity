"""Calcula métricas, tablas (RESULTADOS_tablas.md), resultados.json y comparativa.png desde predicciones.json."""
from __future__ import annotations
import json
from collections import defaultdict
from pathlib import Path
AQUI = Path(__file__).resolve().parent
P = json.loads((AQUI / "predicciones.json").read_text())["datasets"]

HERR = {
    "APC v1.1.0": lambda f: (f["apc"]["detectado"], f["apc"]["ms"]),
    "LLM Guard PromptInjection": lambda f: (f["llmguard"]["PromptInjection"]["flag"], f["llmguard"]["PromptInjection"]["ms"]),
    "LLM Guard suite": lambda f: (any(v["flag"] for v in f["llmguard"].values()), sum(v["ms"] for v in f["llmguard"].values())),
    "ProtectAI deberta-v2 (0.5)": lambda f: (f["deberta"]["detectado"], f["deberta"]["ms"]),
}
HERR_EXT = dict(HERR)
HERR_EXT["APC (texto como documento)"] = lambda f: (f["apc_doc"]["detectado"], f["apc_doc"]["ms"])

def metr(filas, fn):
    tp = fn_ = fp = tn = 0; ms = 0.0
    for f in filas:
        d, t = fn(f); ms += t
        if f["malicioso"]:
            tp += d; fn_ += not d
        else:
            fp += d; tn += not d
    rec = tp / (tp + fn_) if tp + fn_ else None
    fpr = fp / (fp + tn) if fp + tn else None
    prec = tp / (tp + fp) if tp + fp else None
    f1 = 2 * prec * rec / (prec + rec) if prec and rec else (0.0 if rec is not None and prec is not None else None)
    return dict(n=len(filas), maliciosos=tp + fn_, benignos=fp + tn, tp=tp, fn=fn_, fp=fp, tn=tn,
                deteccion=rec, tasa_fp=fpr, precision=prec, f1=f1, latencia_ms=ms / len(filas) if filas else None)

def apc_extra(filas, clave="apc"):
    m = [f for f in filas if f["malicioso"]]; b = [f for f in filas if not f["malicioso"]]
    return {"maliciosos_indeterminado": sum(f[clave]["decision"] == "INDETERMINADO" for f in m),
            "maliciosos_permitir": sum(f[clave]["decision"] == "PERMITIR" for f in m),
            "benignos_indeterminado_friccion": sum(f[clave]["decision"] == "INDETERMINADO" for f in b)}

pct = lambda x: "—" if x is None else f"{x*100:.1f}%"
num = lambda x: "—" if x is None else f"{x:.3f}"

res = {}; md = []
NOMBRES = {"principal": "Banco principal (banco.py, usado para ajustar al agente)",
           "heldout": "Banco held-out 1 (banco_heldout.py)",
           "heldout2": "Banco held-out 2 limpio (banco_heldout2.py)",
           "ext_deepset": "Externo: deepset/prompt-injections (train+test, 662)",
           "ext_safeguard": "Externo: xTRam1/safe-guard-prompt-injection (test, 2060)"}
for ds, filas in P.items():
    herr = HERR_EXT if ds.startswith("ext_") else HERR
    r = {"todas": {h: metr(filas, fn) for h, fn in herr.items()}}
    r["apc_detalle"] = apc_extra(filas)
    if ds.startswith("ext_"):
        r["apc_doc_detalle"] = apc_extra(filas, "apc_doc")
    md.append(f"\n### {NOMBRES[ds]}\n")
    md.append(f"Casos: {len(filas)} ({sum(f['malicioso'] for f in filas)} maliciosos, {sum(not f['malicioso'] for f in filas)} benignos)\n")
    def tabla(rr):
        out = ["| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |", "|---|---|---|---|---|---|"]
        for h, m in rr.items():
            out.append(f"| {h} | {pct(m['deteccion'])} ({m['tp']}/{m['maliciosos']}) | {pct(m['tasa_fp'])} ({m['fp']}/{m['benignos']}) | {num(m['precision'])} | {num(m['f1'])} | {m['latencia_ms']:.1f} ms |")
        return out
    md.append("**Todas las categorías**\n"); md += tabla(r["todas"])
    e = r["apc_detalle"]
    md.append(f"\nAPC en maliciosos no detectados: {e['maliciosos_indeterminado']} INDETERMINADO («no lo sé») y {e['maliciosos_permitir']} PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): {e['benignos_indeterminado_friccion']}.")
    if ds.startswith("ext_"):
        e = r["apc_doc_detalle"]
        md.append(f"APC con el texto como documento: {e['maliciosos_indeterminado']} INDETERMINADO y {e['maliciosos_permitir']} PERMITIR en maliciosos; fricción en benignos: {e['benignos_indeterminado_friccion']}.")
    if not ds.startswith("ext_"):
        sub = [f for f in filas if (not f["malicioso"]) or f["categoria"] == "INYECCION_PROMPT"]
        r["solo_inyeccion_prompt"] = {h: metr(sub, fn) for h, fn in herr.items()}
        md.append("\n**Solo inyección de prompt (maliciosos INYECCION_PROMPT + todos los benignos)**\n"); md += tabla(r["solo_inyeccion_prompt"])
        sub2 = [f for f in filas if (not f["malicioso"]) or f["categoria"] != "INYECCION_PROMPT"]
        r["sin_inyeccion_prompt"] = {h: metr(sub2, fn) for h, fn in herr.items()}
        md.append("\n**Fuera del alcance de los competidores (todas menos INYECCION_PROMPT + todos los benignos)**\n"); md += tabla(r["sin_inyeccion_prompt"])
        cats = sorted({f["categoria"] for f in filas if f["malicioso"]})
        r["por_categoria"] = {}
        md.append("\n**Detección por categoría**\n")
        md.append("| Categoría | n | " + " | ".join(herr) + " |"); md.append("|---|---|" + "---|" * len(herr))
        for c in cats:
            fc = [f for f in filas if f["categoria"] == c]
            r["por_categoria"][c] = {h: sum(fn(f)[0] for f in fc) for h, fn in herr.items()}
            md.append(f"| {c} | {len(fc)} | " + " | ".join(f"{r['por_categoria'][c][h]} ({r['por_categoria'][c][h]/len(fc)*100:.0f}%)" for h in herr) + " |")
        # qué escáner de la suite disparó
    disparos = defaultdict(lambda: [0, 0])
    for f in filas:
        for s, v in f["llmguard"].items():
            disparos[s][0 if f["malicioso"] else 1] += v["flag"]
    r["llmguard_por_escaner"] = {s: {"maliciosos_marcados": a, "benignos_marcados": b} for s, (a, b) in disparos.items()}
    md.append("\nEscáneres de LLM Guard que dispararon (maliciosos / benignos): " + ", ".join(f"{s} {a}/{b}" for s, (a, b) in disparos.items()) + ".")
    res[ds] = r

(AQUI / "resultados.json").write_text(json.dumps(res, ensure_ascii=False, indent=1), encoding="utf-8")
(AQUI / "RESULTADOS_tablas.md").write_text("\n".join(md) + "\n", encoding="utf-8")

import matplotlib; matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
paneles = [("heldout2", "Held-out 2 limpio (325)"), ("ext_deepset", "deepset/prompt-injections (662)"), ("ext_safeguard", "safe-guard-prompt-injection test (2060)")]
fig, axs = plt.subplots(1, 3, figsize=(18, 6), sharey=True)
for ax, (ds, tit) in zip(axs, paneles):
    rr = res[ds]["todas"]; hs = list(rr); x = np.arange(len(hs))
    det = [rr[h]["deteccion"] * 100 for h in hs]; fp = [rr[h]["tasa_fp"] * 100 for h in hs]
    b1 = ax.bar(x - 0.2, det, 0.4, label="Detección (%)", color="#2e7d32")
    b2 = ax.bar(x + 0.2, fp, 0.4, label="Falsos positivos (%)", color="#c62828")
    ax.bar_label(b1, fmt="%.1f", fontsize=8); ax.bar_label(b2, fmt="%.1f", fontsize=8)
    ax.set_xticks(x); ax.set_xticklabels([h.replace(" (", "\n(").replace("LLM Guard ", "LLM Guard\n") for h in hs], fontsize=8)
    ax.set_title(tit); ax.set_ylim(0, 110); ax.grid(axis="y", alpha=.3)
axs[0].set_ylabel("%"); axs[0].legend(loc="upper right")
fig.suptitle("Agente Puro Cybersecurity v1.1.0 vs detectores open source: detección vs falsos positivos")
fig.tight_layout(); fig.savefig(AQUI / "comparativa.png", dpi=130)
print((AQUI / "RESULTADOS_tablas.md").read_text())
