"""Utilidades compartidas por las pruebas de la especialidad."""
import shutil
import tempfile
from pathlib import Path

from agente_puro_ciber import AgentePuroCiber


class ConAgente:
    def setUp(self):
        self._tmp = Path(tempfile.mkdtemp(prefix="apc_test_"))
        self.ag = AgentePuroCiber(secreto=b"pruebas", sandbox=self._tmp)

    def tearDown(self):
        shutil.rmtree(self._tmp, ignore_errors=True)

    def dec(self, texto, documento=None, sesion=None):
        return self.ag.evaluar(texto, documento=documento, sesion=sesion or texto[:20]).decision.value
