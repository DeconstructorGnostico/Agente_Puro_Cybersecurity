"""Base de conocimiento verificado: sello, CVE y la regla «sin hecho no hay ALTA»."""
import unittest
from types import MappingProxyType

from agente_puro_ciber import conocimiento
from agente_puro_ciber.hallazgos import Hallazgo, Severidad
from axiomas_gnostico.tipos import EstadoVerdad


class TestConocimiento(unittest.TestCase):
    def test_sello_integro(self):
        self.assertTrue(conocimiento.verificar_sello())
        self.assertEqual(len(conocimiento.SELLO), 64)

    def test_mutacion_rompe_sello(self):
        falsa = dict(conocimiento.HECHOS)
        falsa.pop("KB-CMD-001")
        self.assertFalse(conocimiento.verificar_sello(MappingProxyType(falsa)))

    def test_base_inmutable(self):
        with self.assertRaises(TypeError):
            conocimiento.HECHOS["KB-X"] = None  # type: ignore

    def test_cve_conocidos(self):
        hs = conocimiento.buscar_cve("¿Me afecta CVE-2021-44228 o CVE-2014-6271?")
        self.assertEqual({h.id for h in hs}, {"KB-CVE-2021-44228", "KB-CVE-2014-6271"})

    def test_cve_desconocido_no_se_inventa(self):
        self.assertEqual(conocimiento.buscar_cve("CVE-2031-99999"), [])

    def test_sin_hecho_no_pasa_de_media(self):
        h = Hallazgo("X", "y", Severidad.CRITICA, "ev", hecho_id=None)
        self.assertEqual(h.severidad, Severidad.MEDIA)
        self.assertEqual(h.verdad, EstadoVerdad.UNDETERMINED)

    def test_con_hecho_es_supported(self):
        h = Hallazgo("X", "y", Severidad.CRITICA, "ev", hecho_id="KB-CMD-001")
        self.assertEqual(h.severidad, Severidad.CRITICA)
        self.assertEqual(h.verdad, EstadoVerdad.SUPPORTED)

    def test_todo_hecho_tiene_categoria_y_severidad_valida(self):
        for h in conocimiento.HECHOS.values():
            self.assertIn(h.severidad, {"BAJA", "MEDIA", "ALTA", "CRITICA"})
            self.assertTrue(h.afirmacion)


if __name__ == "__main__":
    unittest.main()
