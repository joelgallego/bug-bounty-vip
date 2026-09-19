#!/usr/bin/env python3
"""
Enriquecimiento de programas: detección de GraphQL.
Uso: python3 enrich.py <id_inicio> <id_fin>
Ejemplo: python3 enrich.py 1 10

Lógica de valores:
  1   = GraphQL confirmado
  0   = testado exhaustivamente, no encontrado
  NULL = no se pudo comprobar (timeout, sin dominios URL, etc.)
"""

import json
import logging
import sqlite3
import sys
import urllib.request
import urllib.error
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.parse import urlparse

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH  = str(BASE / "programas.db")
LOG_PATH = BASE / "logs" / "enrich.log"

GRAPHQL_PATHS = [
    "/graphql",
    "/api/graphql",
    "/graphql/v1",
    "/v1/graphql",
    "/v2/graphql",
    "/query",
    "/graphiql",
    "/playground",
    "/api/v1/graphql",
    "/api/v2/graphql",
]

# Query de introspección mínima
INTROSPECTION = json.dumps({"query": "{__schema{queryType{name}}}"}).encode()

# Firmas en la respuesta que confirman GraphQL
GRAPHQL_FIRMAS = [b"__schema", b"queryType", b"__typename"]

# Errores GraphQL típicos cuando la query es inválida pero el endpoint existe
GRAPHQL_ERRORES = [b"Cannot query field", b"Did you mean", b"syntax error"]

TIMEOUT = 6  # segundos por request

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_PATH),
        logging.StreamHandler(),
    ],
)
log = logging.getLogger(__name__)


def extraer_dominios(scope_raw_in):
    """Extrae bases de URL testables del scope, descartando wildcards e IPs."""
    if not scope_raw_in:
        return []

    try:
        items = json.loads(scope_raw_in)
    except Exception:
        return []

    dominios = set()
    for item in items:
        endpoint = (
            item.get("asset_identifier")  # HackerOne
            or item.get("endpoint")       # Intigriti
            or item.get("target")         # YesWeHack
            or ""
        ).strip()

        tipo = (
            item.get("asset_type") or item.get("type") or ""
        ).lower()

        # Saltar tipos que no son URL/dominio
        if tipo in ("google_play_app_id", "apple_store_app_id", "android", "ios",
                    "cidr", "other", "executable", "hardware"):
            continue

        # Saltar wildcards
        if endpoint.startswith("*"):
            continue

        # Saltar si no parece URL ni dominio
        if not endpoint or " " in endpoint:
            continue

        # Normalizar a URL con esquema
        if not endpoint.startswith("http"):
            endpoint = "https://" + endpoint

        try:
            parsed = urlparse(endpoint)
            base = f"{parsed.scheme}://{parsed.netloc}"
            if parsed.netloc:
                dominios.add(base)
        except Exception:
            continue

    return list(dominios)


def probar_graphql_endpoint(base, path):
    """
    Envía introspección a base+path.
    Devuelve True si la respuesta indica GraphQL, False si no, None si error de red.
    """
    url = base.rstrip("/") + path
    req = urllib.request.Request(
        url,
        data=INTROSPECTION,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Mozilla/5.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
            body = r.read(4096)
            if any(f in body for f in GRAPHQL_FIRMAS + GRAPHQL_ERRORES):
                return True
            return False
    except urllib.error.HTTPError as e:
        # Algunos endpoints GraphQL devuelven 400/405 con body GraphQL
        try:
            body = e.read(4096)
            if any(f in body for f in GRAPHQL_FIRMAS + GRAPHQL_ERRORES):
                return True
        except Exception:
            pass
        return False
    except Exception:
        # Timeout, conexión rechazada, etc.
        return None


def detectar_graphql(dominios):
    """
    Prueba todos los paths en todos los dominios en paralelo.
    Devuelve: 1 encontrado, 0 no encontrado, None no comprobable.
    """
    if not dominios:
        return None

    tareas = [(base, path) for base in dominios for path in GRAPHQL_PATHS]
    hubo_respuesta = False

    with ThreadPoolExecutor(max_workers=10) as pool:
        futuros = {pool.submit(probar_graphql_endpoint, base, path): (base, path)
                   for base, path in tareas}
        for futuro in as_completed(futuros):
            resultado = futuro.result()
            if resultado is True:
                pool.shutdown(wait=False, cancel_futures=True)
                return 1
            if resultado is False:
                hubo_respuesta = True

    return None


def procesar_rango(id_inicio, id_fin):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        "SELECT id, plataforma, handle, scope_raw_in FROM programas WHERE id BETWEEN ? AND ? AND offers_bounties = 1",
        (id_inicio, id_fin),
    )
    programas = cur.fetchall()

    if not programas:
        log.info(f"No hay programas entre id {id_inicio} y {id_fin}")
        con.close()
        return

    log.info(f"Procesando {len(programas)} programas (id {id_inicio}-{id_fin})")

    for prog_id, plataforma, handle, scope_raw_in in programas:
        dominios = extraer_dominios(scope_raw_in)

        if not dominios:
            log.info(f"  [{prog_id}] {handle} ({plataforma}) — sin dominios URL, omitido")
            continue

        log.info(f"  [{prog_id}] {handle} ({plataforma}) — probando {len(dominios)} dominio(s)...")
        resultado = detectar_graphql(dominios)

        etiqueta = {1: "ENCONTRADO", 0: "no encontrado", None: "sin respuesta"}.get(resultado, "?")
        log.info(f"  [{prog_id}] {handle} → GraphQL: {etiqueta}")

        cur.execute(
            "UPDATE programas SET tiene_graphql=? WHERE id=?",
            (resultado, prog_id),
        )

    con.commit()
    con.close()
    log.info("Listo.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 enrich.py <id_inicio> <id_fin>")
        sys.exit(1)

    try:
        id_inicio = int(sys.argv[1])
        id_fin    = int(sys.argv[2])
    except ValueError:
        print("Los IDs deben ser números enteros")
        sys.exit(1)

    procesar_rango(id_inicio, id_fin)
