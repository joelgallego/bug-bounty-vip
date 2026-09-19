#!/usr/bin/env python3
"""
enrich_bounty_h1.py — rellena `max_bounty`, `min_bounty` y `moneda` de HackerOne.

El feed de bounty-targets-data no publica importes de HackerOne, así que esos
campos quedaban a NULL en toda la plataforma mientras las otras cinco los tenían
al 100%. Los datos salen del GraphQL público vía `bounty_hackerone.rb` (mismo
cliente anónimo que los logos): 226 programas caben en 3 peticiones.

`hide_bounty_amounts` NO se usa para descartar: comprobado que los programas con
ese flag muestran igualmente su tabla de recompensas en su página pública, con el
mismo techo que da la API (ver cabecera de `bounty_hackerone.rb`). Un programa sin
importe en la API se deja a NULL, no a 0: NULL es "no publicado" y 0 sería "no paga".

Uso:
  python3 enrich_bounty_h1.py [--solo-vacios] [--simular]
"""

import argparse
import json
import logging
import sqlite3
import subprocess
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "programas.db"
RUBY = BASE / "bounty_hackerone.rb"

log = logging.getLogger(__name__)


def conectar():
    con = sqlite3.connect(DB, timeout=60)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    return con


def handles(con, solo_vacios):
    sql = ("SELECT plataforma_id, id FROM programas "
           "WHERE plataforma='hackerone' AND activo=1")
    if solo_vacios:
        sql += " AND max_bounty IS NULL"
    return {h: i for h, i in con.execute(sql) if h}


def consultar(lista):
    """Invoca el cliente Ruby. Devuelve {handle: {max, min, moneda, oculta}}."""
    r = subprocess.run(
        ["ruby", str(RUBY)], input="\n".join(lista),
        capture_output=True, text=True, timeout=600,
    )
    if r.returncode != 0:
        raise RuntimeError(f"bounty_hackerone.rb falló: {r.stderr.strip()[:300]}")
    return json.loads(r.stdout)


def actualizar(solo_vacios=False, aplicar=True):
    con = conectar()
    mapa_ids = handles(con, solo_vacios)
    if not mapa_ids:
        log.info("hackerone: nada que consultar")
        return {}

    datos = consultar(sorted(mapa_ids))
    con_dato = sin_importe = sin_respuesta = 0

    for handle, pid in mapa_ids.items():
        d = datos.get(handle)
        if d is None:
            sin_respuesta += 1
            continue
        if d["max"] is None:
            sin_importe += 1
            continue
        con_dato += 1
        if aplicar:
            con.execute(
                "UPDATE programas SET max_bounty=?, min_bounty=?, moneda=? WHERE id=?",
                (d["max"], d["min"], d.get("moneda"), pid),
            )
    if aplicar:
        con.commit()

    resumen = {"consultados": len(mapa_ids), "con_dato": con_dato,
               "sin_importe": sin_importe, "sin_respuesta": sin_respuesta}
    log.info("hackerone bounty: %s", resumen)
    return resumen


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--solo-vacios", action="store_true",
                    help="solo los que aún no tienen max_bounty")
    ap.add_argument("--simular", action="store_true", help="no escribe en la BD")
    args = ap.parse_args()
    print(json.dumps(actualizar(args.solo_vacios, not args.simular),
                     ensure_ascii=False))
