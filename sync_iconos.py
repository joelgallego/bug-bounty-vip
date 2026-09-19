#!/usr/bin/env python3
"""
sync_iconos.py — casa los iconos descargados con los programas de la BD.

La carpeta de origen tiene nombres de marca ("digitalocean.png"), que es como
se descargan. La web los sirve por id de programa ("489.png"), porque es lo
único estable: el nombre comercial cambia y no siempre coincide con el de la
plataforma.

Se COPIA, no se mueve: la carpeta de origen sigue siendo la fuente, y ahí
esperan también los iconos de programas que hoy no están en la BD (los feeds
solo traen los que pagan bounty) por si entran más adelante.

Uso:
    python3 sync_iconos.py            # muestra lo que haría, no toca nada
    python3 sync_iconos.py --aplicar  # copia y actualiza la columna `icono`
"""
import argparse
import re
import shutil
import sqlite3
import sys
import unicodedata
from pathlib import Path

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE = Path(__file__).resolve().parent

ORIGEN  = Path.home() / "Imágenes" / "programas"
DESTINO = BASE.parent / "web" / "iconos"
DB_PATH = str(BASE / "programas.db")

EXTENSIONES = {".png", ".jpg", ".jpeg", ".svg", ".webp"}

# Coletillas que la plataforma añade al nombre del programa y que nadie pone
# al guardar el icono ("Aikido Security: Bug Bounty Program" -> "Aikido").
RUIDO = re.compile(
    r"(bugbounty|bounty|program|programme|public|private|blackbox|vdp"
    r"|responsibledisclosure|opensource)"
)

# Iconos cuyo nombre no se parece al del programa y hubo que resolver mirando:
# nombre de fichero normalizado -> id de programa.
ALIAS = {
    "axelspringer":            467,  # Axel Springer National Media & Tech
    "digitaloceancloudways":   479,  # Cloudways by DigitalOcean
    "dpgmediahetlaatstenieuws": 502,  # Het Laatste Nieuws
    "dstnygroup":              494,  # Dstny
}


def norm(s):
    """Nombre comparable: sin acentos, sin signos, en minúsculas."""
    if not s:
        return ""
    s = unicodedata.normalize("NFKD", s).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", s.lower())


def indice_programas(con):
    """Devuelve (clave normalizada -> [programa], id -> programa)."""
    idx, por_id = {}, {}
    for pid, plat, nombre, handle in con.execute(
        "SELECT id, plataforma, nombre, handle FROM programas"
    ):
        por_id[pid] = (pid, plat, nombre)
        claves = {norm(nombre), RUIDO.sub("", norm(nombre)), norm(handle)}
        for c in claves:
            if c:
                idx.setdefault(c, []).append((pid, plat, nombre))
    return idx, por_id


def casar(fichero, idx, por_id):
    """
    Programas que corresponden a este icono.

    Varias coincidencias con la MISMA clave son la misma marca en distintas
    plataformas (Wolt está en Intigriti y en HackerOne): el logo vale para
    todas, así que se copia a cada id. No es una ambigüedad.
    """
    k = norm(fichero.stem)
    if k in ALIAS:
        p = por_id.get(ALIAS[k])
        return [p] if p else []
    encontrados = idx.get(k) or idx.get(RUIDO.sub("", k)) or []
    return list({p[0]: p for p in encontrados}.values())


def main():
    ap = argparse.ArgumentParser(description="Casa iconos descargados con programas")
    ap.add_argument("--aplicar", action="store_true",
                    help="copiar los ficheros y escribir la columna `icono`")
    args = ap.parse_args()

    if not ORIGEN.is_dir():
        print(f"No existe la carpeta de origen: {ORIGEN}")
        return 1

    con = sqlite3.connect(DB_PATH)
    idx, por_id = indice_programas(con)

    copiados, sin_casar = [], []
    for f in sorted(ORIGEN.iterdir()):
        if f.suffix.lower() not in EXTENSIONES:
            continue
        programas = casar(f, idx, por_id)
        if not programas:
            sin_casar.append(f.name)
            continue
        for pid, plat, nombre in programas:
            copiados.append((f, f"{pid}{f.suffix.lower()}", pid, plat, nombre))

    if args.aplicar:
        DESTINO.mkdir(parents=True, exist_ok=True)
        for origen, destino_nombre, pid, _, _ in copiados:
            shutil.copy2(origen, DESTINO / destino_nombre)
            con.execute("UPDATE programas SET icono=? WHERE id=?", (destino_nombre, pid))
        con.commit()

    print(f"{'COPIADOS' if args.aplicar else 'SE COPIARÍAN'}: {len(copiados)}")
    for origen, destino_nombre, pid, plat, nombre in copiados:
        print(f"  {origen.name:32} -> {destino_nombre:10} {plat:10} {nombre}")

    print(f"\nSIN CASAR: {len(sin_casar)}  (siguen en {ORIGEN}, no se ha tocado nada)")
    for n in sin_casar:
        print(f"  {n}")

    con.close()
    if not args.aplicar:
        print("\n(simulación: nada copiado. Repetir con --aplicar)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
