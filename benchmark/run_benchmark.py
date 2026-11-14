"""Benchmark cara a cara: Agente Puro Cybersecurity v1.1.0 vs detectores open source.

Uso (desde la raíz del repo):  .venv/bin/python benchmark/run_benchmark.py   (genera predicciones.json)
No modifica el agente: solo lo importa (sin escribir bytecode).
"""
from __future__ import annotations
import json, os, shutil, sys, tempfile, time
from pathlib import Path

sys.dont_write_bytecode = True
os.environ.setdefault("TOKENIZERS_PARALLELISM", "false")
APC = Path(os.environ.get("APC_ROOT", Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(APC)); sys.path.insert(0, str(APC / "eval"))
AQUI = Path(__file__).resolve().parent

import torch
torch.set_num_threads(4)

ORDEN = {"BLOQUEAR": 3, "CUARENTENA": 2, "INDETERMINADO": 1, "PERMITIR": 0}

# ---------------------------------------------------------------- datos
def cargar_bancos():
    import banco, banco_heldout, banco_heldout2
    out = {}
    for nombre, mod in (("principal", banco), ("heldout", banco_heldout), ("heldout2", banco_heldout2)):
        out[nombre] = [dict(id=c["id"], categoria=c["categoria"], malicioso=c["malicioso"], pasos=c["pasos"]) for c in mod.generar()]
    return out

def cargar_externos():
    from datasets import load_dataset, concatenate_datasets
    out = {}
    d = load_dataset("deepset/prompt-injections")
    d = concatenate_datasets([d["train"], d["test"]])
    out["ext_deepset"] = [dict(id=f"DS-{i}", categoria="INYECCION_PROMPT" if r["label"] == 1 else "BENIGNO",
                               malicioso=r["label"] == 1, pasos=[{"texto": r["text"]}]) for i, r in enumerate(d)]
    d = load_dataset("xTRam1/safe-guard-prompt-injection")["test"]
    out["ext_safeguard"] = [dict(id=f"SG-{i}", categoria="INYECCION_PROMPT" if r["label"] == 1 else "BENIGNO",
                                 malicioso=r["label"] == 1, pasos=[{"texto": r["text"]}]) for i, r in enumerate(d)]
    return out

def segmentos(caso):
    """Todo el texto del caso para los detectores: cada paso, cada documento y, si hay varios, la concatenación."""
    segs = []
    for p in caso["pasos"]:
        segs.append(p["texto"])
        if p.get("documento"):
            segs.append(p["documento"])
    if len(segs) > 1:
        segs.append("\n".join(segs))
    return segs

# ---------------------------------------------------------------- herramientas
def correr_agente(caso, como_documento=False):
    from agente_puro_ciber import AgentePuroCiber
    sb = Path(tempfile.mkdtemp(prefix="bench_apc_"))
    try:
        ag = AgentePuroCiber(secreto=b"bench-" + caso["id"].encode(), sandbox=sb)
        t = time.perf_counter()
        decs = []
        for p in caso["pasos"]:
            if como_documento:
                r = ag.evaluar("Resume este documento", documento=p["texto"], sesion=caso["id"])
            else:
                r = ag.evaluar(p["texto"], documento=p.get("documento"), sesion=caso["id"])
            decs.append(r.decision.value)
        dt = time.perf_counter() - t
    finally:
        shutil.rmtree(sb, ignore_errors=True)
    peor = max(decs, key=ORDEN.get)
    return {"detectado": peor in ("BLOQUEAR", "CUARENTENA"), "decision": peor, "decisiones": decs, "ms": dt * 1000}

class LLMGuard:
    """PromptInjection(threshold=0.92, FULL) + Secrets() + InvisibleText() + BanCode(threshold=0.97). Valores por defecto de llm-guard 0.3.16."""
    def __init__(self):
        from llm_guard.util import configure_logger
        configure_logger(log_level="ERROR")
        from llm_guard.input_scanners import PromptInjection, Secrets, InvisibleText, BanCode
        from llm_guard.input_scanners.prompt_injection import MatchType
        self.sc = {"PromptInjection": PromptInjection(threshold=0.92, match_type=MatchType.FULL),
                   "Secrets": Secrets(), "InvisibleText": InvisibleText(), "BanCode": BanCode(threshold=0.97)}
    def __call__(self, caso):
        res = {}
        for nombre, s in self.sc.items():
            t = time.perf_counter(); flag = False
            for seg in segmentos(caso):
                _, valido, _ = s.scan(seg)
                if not valido:
                    flag = True
            res[nombre] = {"flag": flag, "ms": (time.perf_counter() - t) * 1000}
        return res

class DebertaRaw:
    """protectai/deberta-v3-base-prompt-injection-v2 por transformers, etiqueta INJECTION con score >= 0.5."""
    def __init__(self):
        from transformers import pipeline
        self.p = pipeline("text-classification", model="protectai/deberta-v3-base-prompt-injection-v2",
                          truncation=True, max_length=512, device="cpu")
    def __call__(self, caso):
        t = time.perf_counter(); flag = False; mx = 0.0
        for seg in segmentos(caso):
            r = self.p(seg)[0]
            sc = r["score"] if r["label"] == "INJECTION" else 1 - r["score"]
            mx = max(mx, sc); flag |= sc >= 0.5
        return {"detectado": flag, "score": round(mx, 4), "ms": (time.perf_counter() - t) * 1000}

def main():
    datos = cargar_bancos(); datos.update(cargar_externos())
    lg = LLMGuard(); db = DebertaRaw()
    # calentamiento (no se mide)
    for _ in range(2):
        lg({"pasos": [{"texto": "hola"}]}); db({"pasos": [{"texto": "hola"}]})
    salida = {"datasets": {}}
    for nombre, casos in datos.items():
        print(f"== {nombre}: {len(casos)} casos", flush=True)
        filas = []
        for i, c in enumerate(casos):
            f = {k: c[k] for k in ("id", "categoria", "malicioso")}
            f["apc"] = correr_agente(c)
            if nombre.startswith("ext_"):
                f["apc_doc"] = correr_agente(c, como_documento=True)
            f["llmguard"] = lg(c)
            f["deberta"] = db(c)
            filas.append(f)
            if i % 200 == 0:
                print(f"  {i}/{len(casos)}", flush=True)
        salida["datasets"][nombre] = filas
    (AQUI / "predicciones.json").write_text(json.dumps(salida, ensure_ascii=False), encoding="utf-8")
    print("ok")

if __name__ == "__main__":
    main()
