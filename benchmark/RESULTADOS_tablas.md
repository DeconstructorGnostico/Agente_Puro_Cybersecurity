
### Banco principal (banco.py, usado para ajustar al agente)

Casos: 354 (219 maliciosos, 135 benignos)

**Todas las categorías**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 100.0% (219/219) | 0.0% (0/135) | 1.000 | 1.000 | 2.3 ms |
| LLM Guard PromptInjection | 36.1% (79/219) | 23.0% (31/135) | 0.718 | 0.480 | 56.5 ms |
| LLM Guard suite | 87.2% (191/219) | 51.1% (69/135) | 0.735 | 0.797 | 65.4 ms |
| ProtectAI deberta-v2 (0.5) | 43.8% (96/219) | 25.2% (34/135) | 0.738 | 0.550 | 56.1 ms |

APC en maliciosos no detectados: 0 INDETERMINADO («no lo sé») y 0 PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): 0.

**Solo inyección de prompt (maliciosos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 100.0% (16/16) | 0.0% (0/135) | 1.000 | 1.000 | 2.0 ms |
| LLM Guard PromptInjection | 93.8% (15/16) | 23.0% (31/135) | 0.326 | 0.484 | 58.0 ms |
| LLM Guard suite | 100.0% (16/16) | 51.1% (69/135) | 0.188 | 0.317 | 66.7 ms |
| ProtectAI deberta-v2 (0.5) | 93.8% (15/16) | 25.2% (34/135) | 0.306 | 0.462 | 57.5 ms |

**Fuera del alcance de los competidores (todas menos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 100.0% (203/203) | 0.0% (0/135) | 1.000 | 1.000 | 2.3 ms |
| LLM Guard PromptInjection | 31.5% (64/203) | 23.0% (31/135) | 0.674 | 0.430 | 53.6 ms |
| LLM Guard suite | 86.2% (175/203) | 51.1% (69/135) | 0.717 | 0.783 | 62.1 ms |
| ProtectAI deberta-v2 (0.5) | 39.9% (81/203) | 25.2% (34/135) | 0.704 | 0.509 | 53.1 ms |

**Detección por categoría**

| Categoría | n | APC v1.1.0 | LLM Guard PromptInjection | LLM Guard suite | ProtectAI deberta-v2 (0.5) |
|---|---|---|---|---|---|
| CADENA_ATAQUE | 14 | 14 (100%) | 6 (43%) | 14 (100%) | 7 (50%) |
| COMANDO_PELIGROSO | 26 | 26 (100%) | 3 (12%) | 14 (54%) | 4 (15%) |
| ESCALADA_PRIVILEGIOS | 19 | 19 (100%) | 4 (21%) | 14 (74%) | 6 (32%) |
| EXFILTRACION | 18 | 18 (100%) | 4 (22%) | 18 (100%) | 4 (22%) |
| EXPLOIT_CVE | 13 | 13 (100%) | 7 (54%) | 10 (77%) | 9 (69%) |
| INYECCION_COMANDOS | 15 | 15 (100%) | 6 (40%) | 15 (100%) | 6 (40%) |
| INYECCION_PROMPT | 16 | 16 (100%) | 15 (94%) | 16 (100%) | 15 (94%) |
| INYECCION_SQL | 16 | 16 (100%) | 11 (69%) | 16 (100%) | 13 (81%) |
| PATH_TRAVERSAL | 15 | 15 (100%) | 3 (20%) | 14 (93%) | 6 (40%) |
| PERSISTENCIA | 17 | 17 (100%) | 7 (41%) | 17 (100%) | 11 (65%) |
| ROBO_CREDENCIALES | 19 | 19 (100%) | 5 (26%) | 17 (89%) | 6 (32%) |
| SHELL_INVERSA | 14 | 14 (100%) | 2 (14%) | 9 (64%) | 3 (21%) |
| SSRF | 17 | 17 (100%) | 6 (35%) | 17 (100%) | 6 (35%) |

Escáneres de LLM Guard que dispararon (maliciosos / benignos): PromptInjection 79/31, Secrets 1/0, InvisibleText 7/0, BanCode 174/56.

### Banco held-out 1 (banco_heldout.py)

Casos: 316 (187 maliciosos, 129 benignos)

**Todas las categorías**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 97.3% (182/187) | 0.0% (0/129) | 1.000 | 0.986 | 2.4 ms |
| LLM Guard PromptInjection | 42.2% (79/187) | 34.1% (44/129) | 0.642 | 0.510 | 60.9 ms |
| LLM Guard suite | 85.0% (159/187) | 58.1% (75/129) | 0.679 | 0.755 | 70.2 ms |
| ProtectAI deberta-v2 (0.5) | 49.2% (92/187) | 35.7% (46/129) | 0.667 | 0.566 | 60.4 ms |

APC en maliciosos no detectados: 5 INDETERMINADO («no lo sé») y 0 PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): 0.

**Solo inyección de prompt (maliciosos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 100.0% (12/12) | 0.0% (0/129) | 1.000 | 1.000 | 2.3 ms |
| LLM Guard PromptInjection | 100.0% (12/12) | 34.1% (44/129) | 0.214 | 0.353 | 64.0 ms |
| LLM Guard suite | 100.0% (12/12) | 58.1% (75/129) | 0.138 | 0.242 | 73.7 ms |
| ProtectAI deberta-v2 (0.5) | 100.0% (12/12) | 35.7% (46/129) | 0.207 | 0.343 | 63.7 ms |

**Fuera del alcance de los competidores (todas menos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 97.1% (170/175) | 0.0% (0/129) | 1.000 | 0.986 | 2.4 ms |
| LLM Guard PromptInjection | 38.3% (67/175) | 34.1% (44/129) | 0.604 | 0.469 | 57.3 ms |
| LLM Guard suite | 84.0% (147/175) | 58.1% (75/129) | 0.662 | 0.741 | 66.1 ms |
| ProtectAI deberta-v2 (0.5) | 45.7% (80/175) | 35.7% (46/129) | 0.635 | 0.532 | 56.8 ms |

**Detección por categoría**

| Categoría | n | APC v1.1.0 | LLM Guard PromptInjection | LLM Guard suite | ProtectAI deberta-v2 (0.5) |
|---|---|---|---|---|---|
| CADENA_ATAQUE | 12 | 10 (83%) | 7 (58%) | 12 (100%) | 7 (58%) |
| COMANDO_PELIGROSO | 25 | 25 (100%) | 2 (8%) | 11 (44%) | 3 (12%) |
| ESCALADA_PRIVILEGIOS | 17 | 16 (94%) | 8 (47%) | 16 (94%) | 9 (53%) |
| EXFILTRACION | 17 | 17 (100%) | 6 (35%) | 14 (82%) | 6 (35%) |
| EXPLOIT_CVE | 10 | 10 (100%) | 5 (50%) | 7 (70%) | 6 (60%) |
| INYECCION_COMANDOS | 12 | 12 (100%) | 5 (42%) | 12 (100%) | 7 (58%) |
| INYECCION_PROMPT | 12 | 12 (100%) | 12 (100%) | 12 (100%) | 12 (100%) |
| INYECCION_SQL | 12 | 12 (100%) | 6 (50%) | 12 (100%) | 10 (83%) |
| PATH_TRAVERSAL | 12 | 12 (100%) | 6 (50%) | 12 (100%) | 6 (50%) |
| PERSISTENCIA | 16 | 16 (100%) | 9 (56%) | 16 (100%) | 10 (62%) |
| ROBO_CREDENCIALES | 17 | 16 (94%) | 4 (24%) | 12 (71%) | 4 (24%) |
| SHELL_INVERSA | 12 | 12 (100%) | 3 (25%) | 10 (83%) | 4 (33%) |
| SSRF | 13 | 12 (92%) | 6 (46%) | 13 (100%) | 8 (62%) |

Escáneres de LLM Guard que dispararon (maliciosos / benignos): PromptInjection 79/44, Secrets 3/0, InvisibleText 3/0, BanCode 138/44.

### Banco held-out 2 limpio (banco_heldout2.py)

Casos: 325 (192 maliciosos, 133 benignos)

**Todas las categorías**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 77.6% (149/192) | 0.0% (0/133) | 1.000 | 0.874 | 2.3 ms |
| LLM Guard PromptInjection | 40.1% (77/192) | 21.8% (29/133) | 0.726 | 0.517 | 55.7 ms |
| LLM Guard suite | 83.9% (161/192) | 50.4% (67/133) | 0.706 | 0.767 | 64.4 ms |
| ProtectAI deberta-v2 (0.5) | 49.0% (94/192) | 25.6% (34/133) | 0.734 | 0.588 | 58.3 ms |

APC en maliciosos no detectados: 37 INDETERMINADO («no lo sé») y 6 PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): 2.

**Solo inyección de prompt (maliciosos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 91.7% (11/12) | 0.0% (0/133) | 1.000 | 0.957 | 2.0 ms |
| LLM Guard PromptInjection | 91.7% (11/12) | 21.8% (29/133) | 0.275 | 0.423 | 58.5 ms |
| LLM Guard suite | 100.0% (12/12) | 50.4% (67/133) | 0.152 | 0.264 | 67.1 ms |
| ProtectAI deberta-v2 (0.5) | 91.7% (11/12) | 25.6% (34/133) | 0.244 | 0.386 | 64.8 ms |

**Fuera del alcance de los competidores (todas menos INYECCION_PROMPT + todos los benignos)**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 76.7% (138/180) | 0.0% (0/133) | 1.000 | 0.868 | 2.2 ms |
| LLM Guard PromptInjection | 36.7% (66/180) | 21.8% (29/133) | 0.695 | 0.480 | 52.6 ms |
| LLM Guard suite | 82.8% (149/180) | 50.4% (67/133) | 0.690 | 0.753 | 60.9 ms |
| ProtectAI deberta-v2 (0.5) | 46.1% (83/180) | 25.6% (34/133) | 0.709 | 0.559 | 55.4 ms |

**Detección por categoría**

| Categoría | n | APC v1.1.0 | LLM Guard PromptInjection | LLM Guard suite | ProtectAI deberta-v2 (0.5) |
|---|---|---|---|---|---|
| CADENA_ATAQUE | 12 | 11 (92%) | 6 (50%) | 12 (100%) | 8 (67%) |
| COMANDO_PELIGROSO | 25 | 14 (56%) | 3 (12%) | 13 (52%) | 6 (24%) |
| ESCALADA_PRIVILEGIOS | 17 | 11 (65%) | 6 (35%) | 10 (59%) | 6 (35%) |
| EXFILTRACION | 17 | 14 (82%) | 6 (35%) | 15 (88%) | 6 (35%) |
| EXPLOIT_CVE | 13 | 9 (69%) | 5 (38%) | 10 (77%) | 9 (69%) |
| INYECCION_COMANDOS | 15 | 13 (87%) | 5 (33%) | 15 (100%) | 8 (53%) |
| INYECCION_PROMPT | 12 | 11 (92%) | 11 (92%) | 12 (100%) | 11 (92%) |
| INYECCION_SQL | 15 | 14 (93%) | 9 (60%) | 15 (100%) | 9 (60%) |
| PATH_TRAVERSAL | 12 | 12 (100%) | 3 (25%) | 12 (100%) | 7 (58%) |
| PERSISTENCIA | 15 | 11 (73%) | 8 (53%) | 14 (93%) | 8 (53%) |
| ROBO_CREDENCIALES | 15 | 11 (73%) | 3 (20%) | 12 (80%) | 4 (27%) |
| SHELL_INVERSA | 12 | 7 (58%) | 4 (33%) | 9 (75%) | 4 (33%) |
| SSRF | 12 | 11 (92%) | 8 (67%) | 12 (100%) | 8 (67%) |

Escáneres de LLM Guard que dispararon (maliciosos / benignos): PromptInjection 77/29, Secrets 10/0, InvisibleText 5/0, BanCode 144/48.

### Externo: deepset/prompt-injections (train+test, 662)

Casos: 662 (263 maliciosos, 399 benignos)

**Todas las categorías**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 12.2% (32/263) | 0.0% (0/399) | 1.000 | 0.217 | 2.8 ms |
| LLM Guard PromptInjection | 38.4% (101/263) | 0.8% (3/399) | 0.971 | 0.550 | 51.7 ms |
| LLM Guard suite | 54.0% (142/263) | 13.3% (53/399) | 0.728 | 0.620 | 60.2 ms |
| ProtectAI deberta-v2 (0.5) | 41.4% (109/263) | 1.0% (4/399) | 0.965 | 0.580 | 50.9 ms |
| APC (texto como documento) | 14.4% (38/263) | 0.0% (0/399) | 1.000 | 0.252 | 2.6 ms |

APC en maliciosos no detectados: 102 INDETERMINADO («no lo sé») y 129 PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): 115.
APC con el texto como documento: 3 INDETERMINADO y 222 PERMITIR en maliciosos; fricción en benignos: 2.

Escáneres de LLM Guard que dispararon (maliciosos / benignos): PromptInjection 101/3, Secrets 0/0, InvisibleText 1/2, BanCode 63/48.

### Externo: xTRam1/safe-guard-prompt-injection (test, 2060)

Casos: 2060 (650 maliciosos, 1410 benignos)

**Todas las categorías**

| Herramienta | Detección | Falsos positivos | Precisión | F1 | Latencia media |
|---|---|---|---|---|---|
| APC v1.1.0 | 24.5% (159/650) | 0.4% (6/1410) | 0.964 | 0.390 | 6.5 ms |
| LLM Guard PromptInjection | 80.6% (524/650) | 0.1% (2/1410) | 0.996 | 0.891 | 73.8 ms |
| LLM Guard suite | 81.2% (528/650) | 13.0% (184/1410) | 0.742 | 0.775 | 85.0 ms |
| ProtectAI deberta-v2 (0.5) | 84.2% (547/650) | 0.1% (2/1410) | 0.996 | 0.912 | 72.4 ms |
| APC (texto como documento) | 24.9% (162/650) | 0.3% (4/1410) | 0.976 | 0.397 | 7.1 ms |

APC en maliciosos no detectados: 293 INDETERMINADO («no lo sé») y 198 PERMITIR. Benignos con INDETERMINADO (fricción, no cuenta como falso positivo): 544.
APC con el texto como documento: 7 INDETERMINADO y 481 PERMITIR en maliciosos; fricción en benignos: 75.

Escáneres de LLM Guard que dispararon (maliciosos / benignos): PromptInjection 524/2, Secrets 1/0, InvisibleText 0/0, BanCode 7/183.
