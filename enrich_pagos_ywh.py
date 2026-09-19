#!/usr/bin/env python3
"""
Enriquecimiento del campo `pagos` para YesWeHack.

Basado EXCLUSIVAMENTE en stats.average_reward de la API pública
https://api.yeswehack.com/programs/<slug> (valor en céntimos → EUR).

Bandas (EUR); el borde cae en la banda inferior:
  0 o null (datos ocultos) -> 0   (procesado, pero el programa oculta el dato)
  0  < avg <= 200          -> 1
  200 < avg <= 400         -> 2
  400 < avg <= 600         -> 3
  600 < avg <= 1000        -> 4
  avg > 1000               -> 5

Semántica del NULL en la BD:
  - pagos = 0    -> procesado; programa oculta/no paga media
  - pagos = 1..5 -> procesado; media conocida
  - pagos = NULL -> AÚN NO PROCESADO (programas nuevos hasta que se corra esto)

Programas inaccesibles (404/privado/error) se dejan NULL y se loguean.

Uso:
  python3 enrich_pagos_ywh.py            # todos los YWH
  python3 enrich_pagos_ywh.py 600 660    # rango de IDs
"""

import sqlite3
import sys
import time
import json
import urllib.request
import urllib.error
from pathlib import Path

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB  = str(BASE / "programas.db")
UA  = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/150.0.0.0 Safari/537.36"
API = "https://api.yeswehack.com/programs/"
PAUSE = 1.0  # segundos entre programas (cortesía / evitar rate limit)


def band(avg_eur):
    if avg_eur is None or avg_eur <= 0:
        return 0
    if avg_eur <= 200:
        return 1
    if avg_eur <= 400:
        return 2
    if avg_eur <= 600:
        return 3
    if avg_eur <= 1000:
        return 4
    return 5


def slug_from(url, handle):
    if url and "/programs/" in url:
        return url.rstrip("/").split("/programs/", 1)[1].split("/")[0]
    return handle


def fetch(slug):
    req = urllib.request.Request(
        API + slug,
        headers={
            "User-Agent": UA,
            "Origin": "https://yeswehack.com",
            "Referer": "https://yeswehack.com/",
            "Accept": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=15) as r:
        return json.load(r)


def main():
    con = sqlite3.connect(DB)
    cur = con.cursor()
    if len(sys.argv) == 3:
        cur.execute(
            "SELECT id, handle, url FROM programas WHERE plataforma='yeswehack' "
            "AND id BETWEEN ? AND ? ORDER BY id",
            (int(sys.argv[1]), int(sys.argv[2])),
        )
    else:
        cur.execute(
            "SELECT id, handle, url FROM programas WHERE plataforma='yeswehack' ORDER BY id"
        )
    rows = cur.fetchall()
    print(f"{len(rows)} programas YesWeHack a procesar\n")

    ok = fail = 0
    dist = {}
    for pid, handle, url in rows:
        slug = slug_from(url, handle)
        try:
            d = fetch(slug)
        except urllib.error.HTTPError as e:
            print(f"[{pid:3}] {slug:48} HTTP {e.code} -> NULL (sin procesar)")
            fail += 1
            time.sleep(PAUSE)
            continue
        except Exception as e:
            print(f"[{pid:3}] {slug:48} ERROR {e} -> NULL")
            fail += 1
            time.sleep(PAUSE)
            continue

        avg_cent = (d.get("stats") or {}).get("average_reward")
        avg_eur = None if avg_cent is None else avg_cent / 100.0
        p = band(avg_eur)
        cur.execute("UPDATE programas SET pagos=? WHERE id=?", (p, pid))
        con.commit()
        dist[p] = dist.get(p, 0) + 1
        ok += 1
        print(f"[{pid:3}] {slug:48} avg={avg_eur if avg_eur is not None else 'oculto'} -> pagos={p}")
        time.sleep(PAUSE)

    con.close()
    print(f"\nProcesados: {ok}  |  Fallidos (NULL): {fail}")
    print("Distribución pagos:", dict(sorted(dist.items())))


if __name__ == "__main__":
    main()
