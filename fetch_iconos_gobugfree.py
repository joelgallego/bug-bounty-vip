#!/usr/bin/env python3
"""
fetch_iconos_gobugfree.py — baja el logo oficial de cada programa de GObugfree.

A diferencia de los otros cuatro fetchers, este **no consulta la plataforma para
averiguar qué logo toca**: la URL ya viene en `feeds_gobugfree/gobugfree_data.json`,
que `fetch_gobugfree.py` genera cada 2 h y donde guarda el `logo_url` de cada
ficha (lo recoge del HTML que ya tenía descargado). Aquí solo se baja la imagen.
Así estrenar los iconos no cuesta un segundo barrido de las 24 páginas.

El cruce es por IDENTIFICADOR (`slug` del feed = `plataforma_id` en la BD), no
por parecido de nombre, igual que en Bugcrowd e Intigriti.

Verificado el 2026-08-16: 23 de los 24 programas publican logo —el que falta,
`univote-vdp`, no paga, así que ni entra en la BD— y **los 8 que pagan lo
tienen**. Formatos: png, svg y jpeg.

Uso:
    python3 fetch_iconos_gobugfree.py                        # simulación
    python3 fetch_iconos_gobugfree.py --aplicar              # descarga y escribe
    python3 fetch_iconos_gobugfree.py --aplicar --solo-vacios
"""
import argparse
import json
import sqlite3
import sys
import time
from pathlib import Path

import requests

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE = Path(__file__).resolve().parent

FEED    = BASE / "feeds_gobugfree" / "gobugfree_data.json"
DESTINO = BASE.parent / "web" / "iconos"
DB_PATH = str(BASE / "programas.db")

UA = "bug-bounty.vip feed collector (+https://www.bug-bounty.vip)"
PAUSA = 1.0        # cortesía: un logo por segundo

# Extensión por tipo de contenido. El feed trae la extensión en la URL, pero un
# CDN puede servir otra cosa; manda lo que diga el servidor.
EXT_POR_TIPO = {
    "image/png": "png", "image/jpeg": "jpg", "image/jpg": "jpg",
    "image/svg+xml": "svg", "image/webp": "webp", "image/gif": "gif",
}


def logos_del_feed():
    """{slug: logo_url} de lo que haya en el feed local."""
    try:
        datos = json.loads(FEED.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        sys.exit(f"no se pudo leer el feed ({e}); genera antes con fetch_gobugfree.py")
    return {p["slug"]: p.get("logo_url") for p in datos if p.get("logo_url")}


def main():
    ap = argparse.ArgumentParser(description="Logos de los programas de GObugfree")
    ap.add_argument("--aplicar", action="store_true",
                    help="descarga las imágenes y escribe en la BD")
    ap.add_argument("--solo-vacios", action="store_true",
                    help="saltar los programas que ya tienen icono")
    args = ap.parse_args()

    mapa = logos_del_feed()
    con = sqlite3.connect(DB_PATH)
    filas = con.execute(
        "SELECT id, plataforma_id, nombre, icono FROM programas "
        "WHERE plataforma='gobugfree' AND activo=1"
    ).fetchall()

    pendientes, sin_logo = [], []
    for pid, plataforma_id, nombre, icono in filas:
        if args.solo_vacios and icono:
            continue
        url = mapa.get(plataforma_id)
        if not url:
            sin_logo.append(nombre or plataforma_id)
            continue
        pendientes.append((pid, plataforma_id, nombre, url))

    print(f"programas: {len(filas)}  |  a descargar: {len(pendientes)}  "
          f"|  sin logo publicado: {len(sin_logo)}")
    for n in sin_logo:
        print(f"  (sin logo) {n}")

    if not args.aplicar:
        for pid, plataforma_id, nombre, url in pendientes:
            print(f"  [simulación] {plataforma_id:22s} <- {url[:80]}")
        print("\n(simulación: usa --aplicar para descargar)")
        con.close()
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    ok = fallos = 0
    for i, (pid, plataforma_id, nombre, url) in enumerate(pendientes):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=30)
            r.raise_for_status()
            tipo = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
            ext = EXT_POR_TIPO.get(tipo) or url.rsplit(".", 1)[-1].lower()[:4] or "png"
            fichero = f"{pid}.{ext}"
            # Un cambio de formato dejaría el fichero viejo huérfano sirviéndose.
            for viejo in DESTINO.glob(f"{pid}.*"):
                viejo.unlink()
            (DESTINO / fichero).write_bytes(r.content)
            con.execute("UPDATE programas SET icono=? WHERE id=?", (fichero, pid))
            con.commit()
            print(f"  ✓ {plataforma_id:22s} -> {fichero} ({len(r.content)} B)")
            ok += 1
        except Exception as e:
            print(f"  ✗ {plataforma_id:22s} {e}")
            fallos += 1
        if i < len(pendientes) - 1:
            time.sleep(PAUSA)

    con.close()
    print(f"\nDescargados: {ok}   fallos: {fallos}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
