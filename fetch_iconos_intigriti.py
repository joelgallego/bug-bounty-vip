#!/usr/bin/env python3
"""
fetch_iconos_intigriti.py — baja el logo oficial de cada programa de Intigriti.

Por qué así y no casando nombres de fichero: el listado público de Intigriti
trae `programId`, que es exactamente el `plataforma_id` que guarda la BD. El
cruce es por identificador, no por parecido de nombre — que es lo que había
fallado antes (varias empresas tienen varios programas: bajo "dpgm" hay 11,
y el logo de cada uno es distinto).

Dos endpoints, ambos públicos (no hacen falta cookies ni navegador):
    GET /api/core/public/programs          -> listado con programId + logoId
    GET /api/file/api/file/<logoId>        -> el PNG

Uso:
    python3 fetch_iconos_intigriti.py             # simulación
    python3 fetch_iconos_intigriti.py --aplicar   # descarga y escribe en BD
    python3 fetch_iconos_intigriti.py --aplicar --solo-vacios   # no re-baja
"""
import argparse
import sqlite3
import sys
import time
from pathlib import Path

import requests

LISTADO = "https://app.intigriti.com/api/core/public/programs"
FICHERO = "https://app.intigriti.com/api/file/api/file/{}"
# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE = Path(__file__).resolve().parent

DESTINO = BASE.parent / "web" / "iconos"
DB_PATH = str(BASE / "programas.db")

# Cortesía con el servidor: un logo por segundo, no somos un scraper.
PAUSA = 1.0

EXT_POR_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}


def main():
    ap = argparse.ArgumentParser(description="Baja los logos de Intigriti")
    ap.add_argument("--aplicar", action="store_true", help="descargar y escribir en la BD")
    ap.add_argument("--solo-vacios", action="store_true",
                    help="saltar los programas que ya tienen icono")
    ap.add_argument("--pausa", type=float, default=PAUSA, help="segundos entre descargas")
    args = ap.parse_args()

    print("Descargando el listado público de programas...")
    r = requests.get(LISTADO, headers={"accept": "application/json"}, timeout=30)
    r.raise_for_status()
    api = {p["programId"]: p for p in r.json() if p.get("programId")}
    print(f"  {len(api)} programas en Intigriti")

    con = sqlite3.connect(DB_PATH)
    filas = con.execute(
        "SELECT id, plataforma_id, nombre, icono FROM programas WHERE plataforma='intigriti'"
    ).fetchall()

    pendientes, sin_logo, huerfanos = [], [], []
    for pid, plataforma_id, nombre, icono in filas:
        p = api.get(plataforma_id)
        if p is None:
            huerfanos.append((pid, nombre))
            continue
        if not p.get("logoId"):
            sin_logo.append((pid, nombre))
            continue
        if args.solo_vacios and icono:
            continue
        pendientes.append((pid, nombre, p["logoId"]))

    print(f"  a descargar: {len(pendientes)}   ya no están en el listado: {len(huerfanos)}"
          f"   sin logo: {len(sin_logo)}")

    if not args.aplicar:
        for pid, nombre, _ in pendientes[:5]:
            print(f"    {pid:4} {nombre}")
        if len(pendientes) > 5:
            print(f"    ... y {len(pendientes)-5} más")
        print("\n(simulación: no se ha descargado nada. Repetir con --aplicar)")
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    ok = fallos = 0
    for i, (pid, nombre, logo_id) in enumerate(pendientes, 1):
        try:
            resp = requests.get(FICHERO.format(logo_id), timeout=30)
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "").split(";")[0].strip()
            ext = EXT_POR_MIME.get(mime)
            if ext is None:
                print(f"  [{i}/{len(pendientes)}] {pid} {nombre}: tipo inesperado {mime!r}")
                fallos += 1
                continue
            # Un id, un fichero: si antes tenía otra extensión, se retira.
            for viejo in DESTINO.glob(f"{pid}.*"):
                if viejo.suffix != ext:
                    viejo.unlink()
            nombre_fichero = f"{pid}{ext}"
            (DESTINO / nombre_fichero).write_bytes(resp.content)
            con.execute("UPDATE programas SET icono=? WHERE id=?", (nombre_fichero, pid))
            con.commit()
            ok += 1
            print(f"  [{i}/{len(pendientes)}] {pid:4} {nombre[:45]:45} -> {nombre_fichero}")
        except requests.RequestException as e:
            print(f"  [{i}/{len(pendientes)}] {pid} {nombre}: ERROR {e}")
            fallos += 1
        time.sleep(args.pausa)

    print(f"\nDescargados: {ok}   fallos: {fallos}")
    if huerfanos:
        print(f"\nEn la BD pero ya no en el listado de Intigriti ({len(huerfanos)}):")
        for pid, nombre in huerfanos:
            print(f"  {pid:4} {nombre}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
