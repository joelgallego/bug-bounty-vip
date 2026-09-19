#!/usr/bin/env python3
"""
Enriquecimiento: detección de OAuth2/OIDC via nuclei.
Actualiza: tiene_oauth.

Uso: python3 enrich_oauth.py <id_inicio> <id_fin>

Lógica de valores:
  1   = OAuth2 u OIDC confirmado por nuclei
  NULL = sin dominios URL, dominios inaccesibles o no detectado
  (nunca se escribe 0)
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

DB_PATH    = str(BASE / "programas.db")
LOG_PATH   = BASE / "logs" / "enrich_oauth.log"
NUCLEI_BIN = "nuclei"
TEMPLATES  = [
    "~/nuclei-templates/http/technologies/oauth2-detect.yaml",
    "~/nuclei-templates/http/technologies/oidc-detect.yaml",
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


def construir_mapa_dominios(programas):
    mapa = {}
    for prog_id, _, _, scope_raw_in in programas:
        for dominio in extraer_dominios(scope_raw_in):
            mapa.setdefault(dominio, []).append(prog_id)
    return list(mapa.keys()), mapa


def lanzar_nuclei(dominios, fichero_targets, fichero_output):
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

            if template_id in ("oauth2-detect", "oidc-detect"):
                if not host.startswith("http"):
                    host = "https://" + host
                try:
                    parsed = urlparse(host)
                    base = f"{parsed.scheme}://{parsed.netloc}"
                except Exception:
                    continue

                for prog_id in mapa.get(base, []):
                    log.info(f"  → [{prog_id}] {base} — {template_id} ENCONTRADO")
                    encontrados.add(prog_id)

    return encontrados


def procesar_rango(id_inicio, id_fin):
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()

    cur.execute(
        """SELECT id, plataforma, handle, scope_raw_in
           FROM programas
           WHERE id BETWEEN ? AND ? AND offers_bounties = 1""",
        (id_inicio, id_fin),
    )
    programas = cur.fetchall()

    if not programas:
        log.info(f"No hay programas con bounty entre id {id_inicio} y {id_fin}")
        con.close()
        return

    log.info(f"Procesando {len(programas)} programas (id {id_inicio}-{id_fin})")

    dominios, mapa = construir_mapa_dominios(programas)

    ids_sin_dominios = {p[0] for p in programas} - {pid for pids in mapa.values() for pid in pids}
    if ids_sin_dominios:
        log.info(f"  {len(ids_sin_dominios)} programas sin dominios URL — quedarán NULL")

    if not dominios:
        log.info("Sin dominios que escanear.")
        con.close()
        return

    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        fichero_targets = f.name
    fichero_output = fichero_targets.replace(".txt", "_out.json")

    ok = lanzar_nuclei(dominios, fichero_targets, fichero_output)

    if not ok:
        log.error("nuclei falló, abortando.")
        for f in [fichero_targets, fichero_output]:
            Path(f).unlink(missing_ok=True)
        con.close()
        return

    ids_con_oauth = procesar_output(fichero_output, mapa)

    for f in [fichero_targets, fichero_output]:
        try:
            Path(f).unlink(missing_ok=True)
        except Exception:
            pass
    log.info(f"Encontrados: {len(ids_con_oauth)} programas con OAuth/OIDC")

    for prog_id in ids_con_oauth:
        cur.execute("UPDATE programas SET tiene_oauth=1 WHERE id=?", (prog_id,))

    con.commit()
    con.close()
    log.info("Listo.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 enrich_oauth.py <id_inicio> <id_fin>")
        sys.exit(1)

    try:
        id_inicio = int(sys.argv[1])
        id_fin    = int(sys.argv[2])
    except ValueError:
        print("Los IDs deben ser números enteros")
        sys.exit(1)

    procesar_rango(id_inicio, id_fin)
