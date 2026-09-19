#!/usr/bin/env python3
"""
Techo de recompensa POR ASSET en YesWeHack.

El problema que resuelve: `max_bounty` es una propiedad del PROGRAMA —lo que
paga por un crítico en su asset más valioso— y el informe habla de un asset
concreto. Enseñar el máximo del programa junto a un asset de valor bajo hace
leer como techo de ese asset una cifra que nunca cobrará por él. Caso real que
lo destapó (2026-08-18): el informe de Telenor Sweden anunciaba `*.telenorcdn.net`
con «Bounty máx. 6000», cuando ese asset es de valor LOW y su crítico paga 3000.

El feed de `bounty-targets-data` no trae esta información: de YesWeHack solo
llegan `target` y `type`. Pero su API pública SÍ la publica, sin credenciales:

    GET https://api.yeswehack.com/programs/<handle>
      scopes[]            → { scope, scope_type, asset_value }
      reward_grid_<nivel> → { bounty_low, bounty_medium, bounty_high, bounty_critical }

`asset_value` toma los valores LOW / MEDIUM / HIGH / CRITICAL (y VERY_LOW, que
tiene rejilla propia aunque no se haya observado en uso). El techo del asset es
el `bounty_critical` de la rejilla de SU nivel.

Se consulta solo al generar un informe —un evento, no cada barrido—, así que el
gasto es de una petición por evento de YesWeHack.

Las otras plataformas no entran aquí: HackerOne y Federacy no publican importe
ninguno, y Bugcrowd e Intigriti no exponen un valor por asset en su feed. Si
algún día lo hicieran, este módulo es el sitio donde añadirlo.
"""

import json
import logging
import urllib.request

log = logging.getLogger(__name__)

API = "https://api.yeswehack.com/programs/{handle}"
TIMEOUT = 15

# Niveles que YesWeHack asigna a un asset, de menos a más valioso. El orden
# importa para presentarlos, no para calcular.
NIVELES = ["VERY_LOW", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _techo_de_rejilla(datos, nivel):
    """
    Lo que paga un crítico en la rejilla de ese nivel.

    Una rejilla puede venir entera a `None` (el programa no usa ese nivel);
    entonces se cae a la rejilla por defecto, que es la que el programa aplica
    a lo que no ha clasificado. Si tampoco hay, se devuelve `None`: preferimos
    no decir nada a inventar una cifra.
    """
    for clave in (f"reward_grid_{nivel.lower()}", "reward_grid_default"):
        rejilla = datos.get(clave) or {}
        techo = rejilla.get("bounty_critical")
        if techo:
            return techo
    return None


def techos(handle, assets):
    """
    `{asset: {"valor": "LOW", "techo": 3000}}` para los assets que se encuentren.

    Nunca lanza: si la API falla, cambia de forma o el programa no está, se
    devuelve lo que se haya podido resolver (posiblemente nada) y el informe
    sale sin este dato, como salía antes.
    """
    if not handle or not assets:
        return {}

    try:
        req = urllib.request.Request(
            API.format(handle=handle), headers={"accept": "application/json"}
        )
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            datos = json.load(r)
    except Exception as e:
        log.warning(f"[yeswehack] no se pudo consultar el valor de los assets "
                    f"de {handle}: {e}")
        return {}

    # El scope de la API se compara con el del feed por su texto exacto: ambos
    # son el patrón tal cual lo publica el programa (`*.telenorcdn.net`).
    por_scope = {}
    for s in datos.get("scopes") or []:
        nombre = (s.get("scope") or "").strip()
        valor = (s.get("asset_value") or "").strip().upper()
        if nombre and valor:
            por_scope[nombre] = valor

    salida = {}
    for asset in assets:
        valor = por_scope.get(str(asset).strip())
        if not valor:
            continue
        salida[asset] = {"valor": valor, "techo": _techo_de_rejilla(datos, valor)}
    return salida


if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)
    if len(sys.argv) < 3:
        print("uso: python3 valor_assets.py <handle> <asset> [asset...]")
        sys.exit(1)
    print(json.dumps(techos(sys.argv[1], sys.argv[2:]), ensure_ascii=False, indent=2))
