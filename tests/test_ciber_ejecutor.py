"""Ejecutor: lista cerrada, token de un solo uso, sandbox, defensa en profundidad, auditoría."""
import secrets
import unittest

from agente_puro_ciber.acciones import AccionCiber, DEFENSIVAS, ESQUEMAS_CIBER
from agente_puro_ciber.ejecutor import EjecutorCiber
from axiomas_gnostico.auditoria import sha256
from axiomas_gnostico.tipos import Accion, ErrorEsquema, ErrorProtocolo, ErrorToken, Orden, Origen
from axiomas_gnostico.tokens import Token
from tests._ciber_util import ConAgente


def _orden(accion, params):
    o = Orden(id=secrets.token_hex(6), accion=accion, parametros=params, causa_id="t", intencion_hash="t", origen=Origen.INTENCION)
    o.hash = sha256(o.a_dict())
    return o


class TestEjecutor(ConAgente, unittest.TestCase):
    def _tok(self, o):
        return self.ag.controlador.emitir(o, executor_id=self.ag.ejecutor.executor_id)

    def test_lista_cerrada(self):
        self.assertEqual(len(ESQUEMAS_CIBER), 10)
        self.assertEqual({a.value for a in DEFENSIVAS},
                         {"ESCANEAR", "CUARENTENA_ARCHIVO", "BLOQUEAR_ACCION", "ALERTAR", "REVOCAR_TOKEN"})
        with self.assertRaises(ErrorEsquema):
            EjecutorCiber.validar("rm -rf /")  # type: ignore
        with self.assertRaises(ErrorEsquema):
            EjecutorCiber.validar(_orden(Accion.CALCULAR, {"expresion": "1+1"}))

    def test_esquema_exacto(self):
        with self.assertRaises(ErrorEsquema):
            EjecutorCiber.validar(_orden(AccionCiber.REPORTAR, {"resumen": "x", "shell": "id"}))
        with self.assertRaises(ErrorEsquema):
            EjecutorCiber.validar(_orden(AccionCiber.ALERTAR, {"mensaje": "x"}))

    def test_sin_token_falsificado_y_reuso(self):
        o = _orden(AccionCiber.REPORTAR, {"resumen": "ok"})
        with self.assertRaises(ErrorToken):
            self.ag.ejecutor.ejecutar(o, None)
        falso = Token("t", o.id, o.hash, o.accion.value, "n", 9e18, self.ag.ejecutor.executor_id, "0" * 64)
        with self.assertRaises(ErrorToken):
            self.ag.ejecutor.ejecutar(o, falso)
        tok = self._tok(o)
        self.assertTrue(self.ag.ejecutor.ejecutar(o, tok)["ok"])
        with self.assertRaises(ErrorToken):
            self.ag.ejecutor.ejecutar(o, tok)

    def test_token_de_otra_orden(self):
        a = _orden(AccionCiber.REPORTAR, {"resumen": "a"})
        b = _orden(AccionCiber.COMANDO_SIMULADO, {"comando": "ls"})
        with self.assertRaises(ErrorToken):
            self.ag.ejecutor.ejecutar(b, self._tok(a))

    def test_defensa_en_profundidad(self):
        o = _orden(AccionCiber.COMANDO_SIMULADO, {"comando": "rm -rf /"})
        with self.assertRaises(ErrorProtocolo):
            self.ag.ejecutor.ejecutar(o, self._tok(o))
        self.assertEqual(self.ag.ejecutor.simulados, [])

    def test_sandbox(self):
        o = _orden(AccionCiber.LEER_RECURSO, {"recurso_id": "../fuera_de_la_sandbox.txt"})
        with self.assertRaises(ErrorEsquema):
            self.ag.ejecutor.ejecutar(o, self._tok(o))
        o = _orden(AccionCiber.CUARENTENA_ARCHIVO, {"ruta": "/../../tmp/x", "motivo": "m", "contenido": ""})
        with self.assertRaises(ErrorEsquema):
            self.ag.ejecutor.ejecutar(o, self._tok(o))

    def test_cuarentena_mueve_dentro_de_la_sandbox(self):
        f = self.ag.ejecutor.sandbox / "archivos" / "malo.txt"
        f.write_text("AKIAIOSFODNN7EXAMPLE", encoding="utf-8")
        o = _orden(AccionCiber.CUARENTENA_ARCHIVO, {"ruta": "archivos/malo.txt", "motivo": "secreto", "contenido": ""})
        out = self.ag.ejecutor.ejecutar(o, self._tok(o))
        self.assertTrue(out["ok"])
        self.assertFalse(f.exists())
        self.assertTrue((self.ag.ejecutor.sandbox / "cuarentena" / "malo.txt.cuarentena").exists())

    def test_escanear_encuentra_secretos(self):
        (self.ag.ejecutor.sandbox / "archivos" / "c.txt").write_text("token=ghp_" + "a" * 36, encoding="utf-8")
        o = _orden(AccionCiber.ESCANEAR, {"objetivo": "archivos"})
        out = self.ag.ejecutor.ejecutar(o, self._tok(o))
        self.assertEqual(out["hallazgos"][0]["tipo"], "secreto_github_token")

    def test_comando_simulado_no_ejecuta(self):
        r = self.ag.evaluar("ls -la /tmp")
        out = self.ag.autorizar_y_ejecutar(r)
        self.assertTrue(out[0]["simulado"])

    def test_no_se_autoriza_lo_bloqueado(self):
        r = self.ag.evaluar("rm -rf /")
        with self.assertRaises(PermissionError):
            self.ag.autorizar_y_ejecutar(r)
        with self.assertRaises(KeyError):
            self.ag.autorizar("no-existe")

    def test_auditoria_encadenada_y_halt_si_se_altera(self):
        self.ag.evaluar("ls")
        self.assertTrue(self.ag.auditoria_integra())
        self.assertTrue(any(r["evento"] == "DECISION" for r in self.ag.audit.registros))
        self.ag.audit._regs[1]["payload"]["texto"] = "alterado"
        r = self.ag.evaluar("ls")
        self.assertEqual(r.decision.value, "INDETERMINADO")
        self.assertIn("HALT", r.motivo)

    def test_decision_lleva_hash_de_auditoria(self):
        r = self.ag.evaluar("rm -rf /")
        self.assertEqual(r.audit_hash, self.ag.audit.cabeza)
        self.assertEqual(len(r.audit_hash), 64)


class TestConocimientoMutadoHalt(ConAgente, unittest.TestCase):
    def test_halt_si_cambia_el_sello(self):
        from agente_puro_ciber import conocimiento
        original = conocimiento.SELLO
        try:
            conocimiento.SELLO = "0" * 64
            r = self.ag.evaluar("ls")
            self.assertEqual(r.decision.value, "INDETERMINADO")
            self.assertIn("CONOCIMIENTO_MUTADO", r.motivo)
        finally:
            conocimiento.SELLO = original


if __name__ == "__main__":
    unittest.main()
