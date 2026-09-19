#!/usr/bin/env python3
"""
fetch_iconos_yeswehack.py — baja el logo de cada programa de YesWeHack.

Como Intigriti y a diferencia de HackerOne, aquí no hace falta sesión: la API
pública lista los programas con su miniatura, y el `slug` que devuelve es el
mismo valor que la BD guarda en `plataforma_id`, así que el cruce es por
identificador y no por parecido de nombres.

    GET https://api.yeswehack.com/programs?page=N   -> items[].slug + thumbnail.url

Cada programa trae dos imágenes: `thumbnail` (la del programa) y
`business_unit.logo` (la de la empresa, compartida por sus programas). Se
prefiere la primera y se cae a la segunda si falta.

Uso:
    python3 fetch_iconos_yeswehack.py             # simulación
    python3 fetch_iconos_yeswehack.py --aplicar
    python3 fetch_iconos_yeswehack.py --aplicar --solo-vacios
"""
import argparse
import hashlib
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

LISTADO = "https://api.yeswehack.com/programs"
# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE = Path(__file__).resolve().parent

DESTINO = BASE.parent / "web" / "iconos"
DB_PATH = str(BASE / "programas.db")
PAUSA = 1.0

EXT_POR_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}


def listar_programas(pausa):
    """Recorre la paginación de la API y devuelve {slug: url_logo}."""
    urls, pagina, total_paginas = {}, 1, 1
    while pagina <= total_paginas:
        r = requests.get(LISTADO, params={"page": pagina, "resultsPerPage": 100},
                         timeout=30)
        r.raise_for_status()
        j = r.json()
        total_paginas = j.get("pagination", {}).get("nb_pages", 1)
        for p in j.get("items", []):
            thumb = (p.get("thumbnail") or {}).get("url")
            if not thumb:
                bu = p.get("business_unit") or {}
                logo = bu.get("logo") or {}
                thumb = logo.get("url")
            if p.get("slug") and thumb:
                urls[p["slug"]] = thumb
        print(f"  página {pagina}/{total_paginas}: {len(urls)} logos acumulados")
        pagina += 1
        if pagina <= total_paginas:
            time.sleep(pausa)
    return urls


def main():
    ap = argparse.ArgumentParser(description="Baja los logos de YesWeHack")
    ap.add_argument("--aplicar", action="store_true")
    ap.add_argument("--solo-vacios", action="store_true")
    ap.add_argument("--pausa", type=float, default=PAUSA)
    args = ap.parse_args()

    print("Recorriendo la API pública de YesWeHack...")
    urls = listar_programas(args.pausa)
    print(f"  {len(urls)} programas con logo")

    con = sqlite3.connect(DB_PATH)
    filas = con.execute(
        "SELECT id, plataforma_id, nombre, icono FROM programas WHERE plataforma='yeswehack'"
    ).fetchall()

    pendientes, sin_url = [], []
    for pid, slug, nombre, icono in filas:
        url = urls.get(slug)
        if not url:
            sin_url.append((pid, slug, nombre))
            continue
        if args.solo_vacios and icono:
            continue
        pendientes.append((pid, nombre, url))

    print(f"BD yeswehack: {len(filas)}   a descargar: {len(pendientes)}"
          f"   sin logo en la API: {len(sin_url)}")
    for pid, slug, nombre in sin_url:
        print(f"    sin logo: {pid:4} {slug:45} {nombre}")

    if not args.aplicar:
        print("\n(simulación: no se ha descargado nada. Repetir con --aplicar)")
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    ok = fallos = 0
    por_hash = defaultdict(list)
    for i, (pid, nombre, url) in enumerate(pendientes, 1):
        try:
            resp = requests.get(url, timeout=30)
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "").split(";")[0].strip()
            ext = EXT_POR_MIME.get(mime)
            if ext is None:
                print(f"  [{i}/{len(pendientes)}] {pid} {nombre}: tipo inesperado {mime!r}")
                fallos += 1
                continue
            for viejo in DESTINO.glob(f"{pid}.*"):
                if viejo.suffix != ext:
                    viejo.unlink()
            fichero = f"{pid}{ext}"
            (DESTINO / fichero).write_bytes(resp.content)
            con.execute("UPDATE programas SET icono=? WHERE id=?", (fichero, pid))
            con.commit()
            por_hash[hashlib.md5(resp.content).hexdigest()].append((pid, nombre))
            ok += 1
            print(f"  [{i}/{len(pendientes)}] {pid:4} {nombre[:45]:45} -> {fichero}")
        except requests.RequestException as e:
            print(f"  [{i}/{len(pendientes)}] {pid} {nombre}: ERROR {e}")
            fallos += 1
        time.sleep(args.pausa)

    print(f"\nDescargados: {ok}   fallos: {fallos}")
    repetidos = {h: v for h, v in por_hash.items() if len(v) > 1}
    if repetidos:
        print("\nImágenes idénticas compartidas por varios programas "
              "(logo de empresa o imagen por defecto):")
        for h, v in sorted(repetidos.items(), key=lambda kv: -len(kv[1])):
            print(f"  {h[:12]}  x{len(v)}: " + ", ".join(n for _, n in v[:6])
                  + (" ..." if len(v) > 6 else ""))
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
