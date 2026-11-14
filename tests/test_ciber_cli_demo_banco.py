"""CLI, demo y banco (tamaño, semilla, métricas de seguridad)."""
import contextlib
import io
import sys
import unittest
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(RAIZ / "eval"))


class TestCLI(unittest.TestCase):
    def _main(self, args):
        from agente_puro_ciber.__main__ import main
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            code = main(args)
        return code, buf.getvalue()

    def test_texto(self):
        code, out = self._main(["rm", "-rf", "/"])
        self.assertEqual(code, 0)
        self.assertIn("BLOQUEAR", out)

    def test_json(self):
        import json
        code, out = self._main(["--json", "ls -la"])
        self.assertEqual(json.loads(out)["decision"], "PERMITIR")

    def test_demo(self):
        from agente_puro_ciber.demo import correr
        log = correr(silencioso=True)
        self.assertEqual(len([x for x in log if x["caso"] != "extra"]), 8)
        self.assertTrue(all(x["ok"] for x in log), log)


class TestBanco(unittest.TestCase):
    def test_tamano_y_semilla(self):
        import banco
        a, b = banco.generar(), banco.generar()
        self.assertEqual(a, b)
        self.assertGreaterEqual(len(a), 300)
        self.assertGreaterEqual(sum(not c["malicioso"] for c in a), 100)
        self.assertEqual(banco.SEMILLA, 20261114)

    def test_metricas_de_seguridad(self):
        import banco
        import run_eval
        res = run_eval.correr(banco.generar())["resumen"]
        self.assertEqual(res["ejecuciones_no_autorizadas"], 0)
        self.assertEqual(res["permitir_en_maliciosos"], 0)
        self.assertTrue(res["auditoria_integra_en_todos"])


if __name__ == "__main__":
    unittest.main()
