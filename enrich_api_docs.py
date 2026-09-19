#!/usr/bin/env python3
"""
Enriquecimiento: detección de API docs públicas (Swagger/OpenAPI/ReDoc) via nuclei.
Actualiza: tiene_api_docs, tiene_api.

Uso: python3 enrich_api_docs.py <id_inicio> <id_fin>

Lógica de valores:
  1   = confirmado por nuclei
  0   = nuclei escaneó y no encontró nada
  NULL = sin dominios URL o dominios inaccesibles
"""

import json
import logging
import os
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path
from urllib.parse import urlparse

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH      = str(BASE / "programas.db")
LOG_PATH     = BASE / "logs" / "enrich_api_docs.log"
NUCLEI_BIN   = "nuclei"
TEMPLATES    = [
    "~/nuclei-templates/http/exposures/apis/swagger-api.yaml",
    "~/nuclei-templates/http/exposures/apis/openapi.yaml",
    "~/nuclei-templates/http/exposures/apis/redoc-api-docs.yaml",
]

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
    if not scope_raw_in:
        return []
    try:
        items = json.loads(scope_raw_in)
    except Exception:
        return []

    dominios = set()
    for item in items:
        endpoint = (
            item.get("asset_identifier")
            or item.get("endpoint")
            or item.get("target")
            or ""
        ).strip()
        tipo = (item.get("asset_type") or item.get("type") or "").lower()

        if tipo in ("google_play_app_id", "apple_store_app_id", "android", "ios",
                    "cidr", "other", "executable", "hardware"):
            continue
        if endpoint.startswith("*") or not endpoint or " " in endpoint:
            continue
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


def cargar_programas(cur, id_inicio, id_fin):
    cur.execute(
        """SELECT id, plataforma, handle, scope_raw_in
           FROM programas
           WHERE id BETWEEN ? AND ? AND offers_bounties = 1""",
        (id_inicio, id_fin),
    )
    return cur.fetchall()


def construir_mapa_dominios(programas):
    """Devuelve (dominios_unicos, mapa dominio→[prog_id])."""
    mapa = {}
    for prog_id, _, _, scope_raw_in in programas:
        for dominio in extraer_dominios(scope_raw_in):
            mapa.setdefault(dominio, []).append(prog_id)
    return list(mapa.keys()), mapa


def lanzar_nuclei(dominios, fichero_targets, fichero_output):
    """Escribe targets, lanza nuclei, devuelve True si ok."""
    Path(fichero_targets).write_text("\n".join(dominios))
    log.info(f"Lanzando nuclei sobre {len(dominios)} dominios...")

    templates = " ".join(f"-t {t}" for t in TEMPLATES)
    cmd = (
        f"{NUCLEI_BIN} -l {fichero_targets} "
        f"{templates} "
        f"-j -o {fichero_output} "
        f"-silent -rate-limit 15"
    )

    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if result.returncode != 0 and not Path(fichero_output).exists():
        log.error(f"nuclei error: {result.stderr[:500]}")
        return False
    return True


def procesar_output(fichero_output, mapa):
    """
    Lee el JSON de nuclei línea a línea.
    Devuelve set de prog_ids con api_docs confirmado.
    """
    encontrados = set()
    if not Path(fichero_output).exists():
        return encontrados

    with open(fichero_output) as f:
        for linea in f:
            linea = linea.strip()
            if not linea:
                continue
            try:
                resultado = json.loads(linea)
            except Exception:
                continue

            host = resultado.get("host", "")
            template_id = resultado.get("template-id", "")

            if template_id in ("swagger-api", "openapi", "redoc-api-docs"):
                # Normalizar host a base URL
                if not host.startswith("http"):
                    host = "https://" + host
                parsed = urlparse(host)
                base = f"{parsed.scheme}://{parsed.netloc}"

                for prog_id in mapa.get(base, []):
                    log.info(f"  → [{prog_id}] {base} — {template_id} ENCONTRADO")
                    encontrados.add(prog_id)

    return encontrados


def actualizar_bd(cur, todos_ids, ids_con_docs, ids_sin_dominios):
    for prog_id in ids_con_docs:
        cur.execute(
            "UPDATE programas SET tiene_api_docs=1, tiene_api=1 WHERE id=?",
            (prog_id,),
        )


def procesar_rango(id_inicio, id_fin):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    programas = cargar_programas(cur, id_inicio, id_fin)
    if not programas:
        log.info(f"No hay programas con bounty entre id {id_inicio} y {id_fin}")
        con.close()
        return

    log.info(f"Procesando {len(programas)} programas (id {id_inicio}-{id_fin})")

    dominios, mapa = construir_mapa_dominios(programas)

    # Programas sin ningún dominio URL
    ids_con_dominios = {prog_id for prog_id in (mapa[d][0] for d in mapa)}
    todos_ids        = {p[0] for p in programas}
    ids_sin_dominios = todos_ids - ids_con_dominios

    if ids_sin_dominios:
        log.info(f"  {len(ids_sin_dominios)} programas sin dominios URL — quedarán NULL")

    if not dominios:
        log.info("Sin dominios que escanear.")
        con.close()
        return

    # Ficheros temporales en un dir neutral (antes usaba el scratchpad de Claude Code)
    scratchpad = Path(os.environ.get(
        "API_DOCS_SCRATCHPAD",
        f"/tmp/{Path(__file__).stem}_{os.getuid()}"
    ))
    scratchpad.mkdir(parents=True, exist_ok=True)
    fichero_targets = str(scratchpad / f"nuclei_targets_{id_inicio}_{id_fin}.txt")
    fichero_output  = str(scratchpad / f"nuclei_output_{id_inicio}_{id_fin}.json")

    ok = lanzar_nuclei(dominios, fichero_targets, fichero_output)
    if not ok:
        log.error("nuclei falló, abortando.")
        con.close()
        return

    ids_con_docs = procesar_output(fichero_output, mapa)
    log.info(f"Encontrados: {len(ids_con_docs)} programas con API docs")

    actualizar_bd(cur, todos_ids, ids_con_docs, ids_sin_dominios)
    con.commit()
    con.close()

    # Limpiar temporales
    for f in [fichero_targets, fichero_output]:
        try:
            Path(f).unlink()
        except Exception:
            pass

    log.info("Listo.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 enrich_api_docs.py <id_inicio> <id_fin>")
        sys.exit(1)

    try:
        id_inicio = int(sys.argv[1])
        id_fin    = int(sys.argv[2])
    except ValueError:
        print("Los IDs deben ser números enteros")
        sys.exit(1)

    procesar_rango(id_inicio, id_fin)
