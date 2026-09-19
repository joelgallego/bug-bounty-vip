#!/usr/bin/env python3
"""
fetch_iconos_bugcrowd.py — baja el logo oficial de cada programa de Bugcrowd.

Como en Intigriti, el cruce es por IDENTIFICADOR, no por parecido de nombre:
el listado trae `briefUrl` (https://bugcrowd.com/engagements/<slug>) y ese slug
es exactamente el `plataforma_id` que guarda la BD (ver `sync.slug_bugcrowd`).
Verificado el 2026-08-10: los 239 programas de la BD casan por slug, 0 huérfanos.

Dos endpoints, ambos públicos (no hacen falta cookies ni navegador, pero sí un
User-Agent de navegador: con el de urllib/requests la respuesta es 403):
    GET /engagements.json?page=N      -> listado paginado (24 por página)
    GET <logoUrl>                     -> la imagen, en logos.bugcrowdusercontent.com

Uso:
    python3 fetch_iconos_bugcrowd.py             # simulación
    python3 fetch_iconos_bugcrowd.py --aplicar   # descarga y escribe en BD
    python3 fetch_iconos_bugcrowd.py --aplicar --solo-vacios   # no re-baja
"""
import argparse
import sqlite3
import sys
import time
from pathlib import Path

import requests

LISTADO = "https://bugcrowd.com/engagements.json"
# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE = Path(__file__).resolve().parent

DESTINO = BASE.parent / "web" / "iconos"
DB_PATH = str(BASE / "programas.db")

# Bugcrowd responde 403 al User-Agent por defecto de requests. No es una
# barrera de autenticación: con el de un navegador el mismo JSON es público.
UA = ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")

# Cortesía con el servidor: un logo por segundo, no somos un scraper.
PAUSA = 1.0
MAX_PAGINAS = 40          # tope de seguridad por si la paginación no termina

EXT_POR_MIME = {
    "image/png": ".png",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/svg+xml": ".svg",
    "image/webp": ".webp",
    "image/gif": ".gif",
}


def slug_de(brief_url):
    """El slug del engagement, que es el `plataforma_id` de la BD."""
    if not brief_url:
        return None
    return brief_url.rstrip("/").rsplit("/", 1)[-1] or None


def descargar_listado(ses, pausa):
    """Recorre la paginación entera y devuelve {slug: engagement}."""
    api, pagina, total = {}, 1, None
    while pagina <= MAX_PAGINAS:
        r = ses.get(LISTADO, params={"page": pagina}, timeout=30)
        r.raise_for_status()
        datos = r.json()
        lote = datos.get("engagements") or []
        if not lote:
            break
        for e in lote:
            if (s := slug_de(e.get("briefUrl"))):
                api[s] = e
        total = (datos.get("paginationMeta") or {}).get("totalCount")
        if total is not None and len(api) >= total:
            break
        pagina += 1
        time.sleep(pausa)
    return api, total


def main():
    ap = argparse.ArgumentParser(description="Baja los logos de Bugcrowd")
    ap.add_argument("--aplicar", action="store_true", help="descargar y escribir en la BD")
    ap.add_argument("--solo-vacios", action="store_true",
                    help="saltar los programas que ya tienen icono")
    ap.add_argument("--pausa", type=float, default=PAUSA, help="segundos entre descargas")
    args = ap.parse_args()

    ses = requests.Session()
    ses.headers.update({"user-agent": UA, "accept": "application/json"})

    print("Descargando el listado público de engagements...")
    api, total = descargar_listado(ses, args.pausa)
    print(f"  {len(api)} engagements recogidos"
          + (f" (la fuente dice {total})" if total is not None else ""))

    con = sqlite3.connect(DB_PATH)
    filas = con.execute(
        "SELECT id, plataforma_id, nombre, icono FROM programas WHERE plataforma='bugcrowd'"
    ).fetchall()

    pendientes, sin_logo, huerfanos = [], [], []
    for pid, plataforma_id, nombre, icono in filas:
        e = api.get(plataforma_id)
        if e is None:
            huerfanos.append((pid, nombre))
            continue
        if not e.get("logoUrl"):
            sin_logo.append((pid, nombre))
            continue
        if args.solo_vacios and icono:
            continue
        pendientes.append((pid, nombre, e["logoUrl"]))

    print(f"  a descargar: {len(pendientes)}   ya no están en el listado: {len(huerfanos)}"
          f"   sin logo: {len(sin_logo)}")

    if not args.aplicar:
        for pid, nombre, url in pendientes[:5]:
            print(f"    {pid:4} {nombre[:40]:40} {url}")
        if len(pendientes) > 5:
            print(f"    ... y {len(pendientes)-5} más")
        print("\n(simulación: no se ha descargado nada. Repetir con --aplicar)")
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    ok = fallos = 0
    for i, (pid, nombre, url) in enumerate(pendientes, 1):
        try:
            resp = ses.get(url, timeout=30)
            resp.raise_for_status()
            mime = resp.headers.get("content-type", "").split(";")[0].strip().lower()
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
    if sin_logo:
        print(f"\nSin logo en el listado ({len(sin_logo)}):")
        for pid, nombre in sin_logo:
            print(f"  {pid:4} {nombre}")
    if huerfanos:
        print(f"\nEn la BD pero ya no en el listado de Bugcrowd ({len(huerfanos)}):")
        for pid, nombre in huerfanos:
            print(f"  {pid:4} {nombre}")
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
