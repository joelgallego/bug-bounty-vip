#!/usr/bin/env python3
"""
Enriquecimiento: detección de pasarelas de pago via webanalyze.
Actualiza: tiene_pagos, pago_detectado.

Uso: python3 enrich_pagos.py <id_inicio> <id_fin>

Lógica de valores:
  1   = pasarela de pago detectada (Stripe, PayPal, Adyen, Klarna, etc.)
  NULL = sin dominios URL, dominios inaccesibles o no detectado
  (nunca se escribe 0)
"""

import json
import logging
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
LOG_PATH   = BASE / "logs" / "enrich_pagos.log"
APPS_PATH  = str(BASE / "technologies.json")
WEBANALYZE = "webanalyze"
WORKERS    = 10

PAYMENT_CATEGORY = "41"

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


def cargar_payment_apps():
    """Devuelve set de nombres de apps de la categoría payment."""
    with open(APPS_PATH) as f:
        data = json.load(f)
    apps = set()
    for name, tech in data.get("technologies", {}).items():
        cats = [str(c) for c in (tech.get("cats") or [])]
        if PAYMENT_CATEGORY in cats:
            apps.add(name)
    return apps


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


def lanzar_webanalyze(dominios, fichero_targets):
    Path(fichero_targets).write_text("\n".join(dominios))
    log.info(f"Lanzando webanalyze sobre {len(dominios)} dominios ({WORKERS} workers)...")

    cmd = [
        WEBANALYZE,
        "-hosts", fichero_targets,
        "-apps", APPS_PATH,
        "-output", "json",
        "-worker", str(WORKERS),
        "-redirect",
        "-silent",
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0 and not result.stdout.strip():
        log.error(f"webanalyze error: {result.stderr[:500]}")
        return None
    return result.stdout


def procesar_output(output_json, mapa, payment_apps):
    """Devuelve dict prog_id → pasarela detectada."""
    encontrados = {}

    for linea in output_json.splitlines():
        linea = linea.strip()
        if not linea:
            continue
        try:
            resultado = json.loads(linea)
        except Exception:
            continue

        hostname = resultado.get("hostname", "")
        matches = resultado.get("matches", [])
        if not hostname or not matches:
            continue

        if not hostname.startswith("http"):
            hostname = "https://" + hostname
        try:
            parsed = urlparse(hostname)
            base = f"{parsed.scheme}://{parsed.netloc}"
        except Exception:
            continue

        for match in matches:
            app_name = match.get("app_name", "")
            if app_name in payment_apps:
                for prog_id in mapa.get(base, []):
                    if prog_id not in encontrados:
                        log.info(f"  → [{prog_id}] {base} — {app_name} detectado")
                        encontrados[prog_id] = app_name

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

    payment_apps = cargar_payment_apps()
    log.info(f"Categoría payment: {len(payment_apps)} tecnologías cargadas")

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

    output = lanzar_webanalyze(dominios, fichero_targets)
    Path(fichero_targets).unlink(missing_ok=True)

    if output is None:
        log.error("webanalyze falló, abortando.")
        con.close()
        return

    encontrados = procesar_output(output, mapa, payment_apps)
    log.info(f"Encontrados: {len(encontrados)} programas con pagos")

    for prog_id, pasarela in encontrados.items():
        cur.execute(
            "UPDATE programas SET tiene_pagos=1, pago_detectado=? WHERE id=?",
            (pasarela, prog_id),
        )

    con.commit()
    con.close()
    log.info("Listo.")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python3 enrich_pagos.py <id_inicio> <id_fin>")
        sys.exit(1)

    try:
        id_inicio = int(sys.argv[1])
        id_fin    = int(sys.argv[2])
    except ValueError:
        print("Los IDs deben ser números enteros")
        sys.exit(1)

    procesar_rango(id_inicio, id_fin)
