#!/usr/bin/env python3
"""
fetch_iconos_hackerone.py — baja el logo de cada programa de HackerOne.

A diferencia de Intigriti, HackerOne no tiene un listado público de logos: la
URL del logo se pide por GraphQL. Este script NO habla con GraphQL: recibe ya
hecho el mapa handle -> URL y se limita a descargar (las imágenes son públicas,
salen de profile-photos.hackerone-user-content.com y de S3, sin cookies).

CORRECCIÓN (2026-08-16). Aquí se afirmaba que ese GraphQL "exige el CSRF de una
sesión con login" y que por eso el mapa había que generarlo a mano desde la
consola del navegador. **Es falso, y comprobado**: basta el token que sirve la
propia página pública del directorio, sin ninguna sesión. Es el mismo truco con
el que el crawler de bounty-targets lee los scopes sin credenciales. Verificado
con `security`, `gitlab` y `coinbase`: devuelve sus tres URLs sin login.

Así que el mapa ya NO se hace a mano:

    ruby logos_hackerone.rb <handle> [handle...]   > mapa.json

y de eso se encarga `iconos.py`, que además lo lanza solo cuando entra un
programa nuevo. Este script sigue siendo el que descarga, sin cambios.

`xtralarge` es el mayor de los tres tamaños (128x128; large=110, medium=82).
Ojo: no se pueden pedir más de 3 alias de profile_picture por selection set.

Uso (normalmente no hace falta invocarlo a mano, lo hace `iconos.py`):
    python3 fetch_iconos_hackerone.py --json mapa.json
    python3 fetch_iconos_hackerone.py --json mapa.json --aplicar
"""
import argparse
import hashlib
import json
import sqlite3
import sys
import time
from collections import defaultdict
from pathlib import Path

import requests

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


def main():
    ap = argparse.ArgumentParser(description="Baja los logos de HackerOne")
    ap.add_argument("--json", required=True,
                    help="fichero con {handle: {profile_picture: url}} o lista de nodos")
    ap.add_argument("--aplicar", action="store_true")
    ap.add_argument("--solo-vacios", action="store_true")
    ap.add_argument("--pausa", type=float, default=PAUSA)
    args = ap.parse_args()

    datos = json.loads(Path(args.json).read_text())
    if isinstance(datos, list):
        datos = {n["handle"]: n for n in datos}
    urls = {h: n.get("profile_picture") for h, n in datos.items()}

    con = sqlite3.connect(DB_PATH)
    filas = con.execute(
        "SELECT id, plataforma_id, nombre, icono FROM programas WHERE plataforma='hackerone'"
    ).fetchall()

    pendientes, sin_url = [], []
    for pid, handle, nombre, icono in filas:
        url = urls.get(handle)
        if not url:
            sin_url.append((pid, handle, nombre))
            continue
        if args.solo_vacios and icono:
            continue
        pendientes.append((pid, nombre, url))

    print(f"BD hackerone: {len(filas)}   a descargar: {len(pendientes)}"
          f"   sin URL de logo: {len(sin_url)}")
    if sin_url:
        for pid, handle, nombre in sin_url:
            print(f"    sin logo: {pid:4} {handle:30} {nombre}")

    if not args.aplicar:
        print("\n(simulación: no se ha descargado nada. Repetir con --aplicar)")
        return 0

    DESTINO.mkdir(parents=True, exist_ok=True)
    ok = fallos = 0
    por_hash = defaultdict(list)   # para detectar el avatar por defecto
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
            if i % 25 == 0 or i == len(pendientes):
                print(f"  [{i}/{len(pendientes)}] ...")
        except requests.RequestException as e:
            print(f"  [{i}/{len(pendientes)}] {pid} {nombre}: ERROR {e}")
            fallos += 1
        time.sleep(args.pausa)

    print(f"\nDescargados: {ok}   fallos: {fallos}")

    # Varios programas con el MISMO fichero byte a byte = avatar genérico de
    # HackerOne, no el logo de la empresa. No sirve para la web.
    repetidos = {h: v for h, v in por_hash.items() if len(v) > 1}
    if repetidos:
        print("\nImágenes idénticas compartidas por varios programas "
              "(probable avatar por defecto):")
        for h, v in sorted(repetidos.items(), key=lambda kv: -len(kv[1])):
            print(f"  {h[:12]}  x{len(v)}: " + ", ".join(n for _, n in v[:6])
                  + (" ..." if len(v) > 6 else ""))
    con.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
