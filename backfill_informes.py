#!/usr/bin/env python3
"""
backfill_informes.py — crea informes a partir de cambios de scope ya detectados.

`sync.py` lleva desde julio guardando en `programas` el scope anterior de cada
programa (`scope_raw_in_antiguo`) y la fecha en que cambió (`fecha_cambio_scope`),
pero la tabla `informes` es más nueva, así que esos eventos nunca llegaron al
feed. Este script los recupera.

No inventa nada: la fecha es la que registró el sync y los assets salen de
comparar el scope actual con el anterior, ambos ya en la BD. Los informes se
marcan con `origen='backfill'` para poder distinguirlos de los que nacen en
vivo, y **no llevan `ts_barrido_anterior`**: de un evento pasado no sabemos
cuál fue la ventana de detección, y preferimos no dar una antigüedad que no
podemos sostener.

Limitación: solo se guarda el estado anterior *inmediato*, así que de cada
programa sale como mucho un informe (su último cambio).

Uso:
    python3 backfill_informes.py --limite 10 [--aplicar]
"""
import argparse
import json
import sqlite3
import sys
from datetime import datetime, timezone
from pathlib import Path

import sync

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH = str(BASE / "programas.db")


def candidatos(con, limite):
    """Programas con assets nuevos reales, del más reciente al más antiguo."""
    filas = con.execute(
        """SELECT id, nombre, handle, plataforma, url, max_bounty,
                  fecha_cambio_scope, scope_raw_in, scope_raw_in_antiguo
           FROM programas
           WHERE fecha_cambio_scope IS NOT NULL
             AND scope_raw_in_antiguo IS NOT NULL
           ORDER BY fecha_cambio_scope DESC"""
    ).fetchall()

    out = []
    for pid, nombre, handle, plat, url, maxb, fecha, ahora_, antes in filas:
        nuevos = sync.ids_scope(ahora_) - sync.ids_scope(antes)
        if not nuevos:
            continue
        # Mismo criterio que las alertas en vivo: solo cuentan los que pagan.
        bounty = sync.ids_scope(ahora_, solo_bounty=True)
        elegibles = sorted(a for a in nuevos if a in bounty)
        if not elegibles:
            continue
        out.append({
            "programa_id": pid,
            "nombre": nombre or handle,
            "plataforma": plat,
            "url": url or "",
            "max_bounty": maxb,
            "fecha": fecha,
            "assets": elegibles,
            "omitidos": len(nuevos) - len(elegibles),
        })
        if len(out) >= limite:
            break
    return out


def ya_existe(con, programa_id, fecha):
    return con.execute(
        "SELECT 1 FROM informes WHERE programa_id=? AND timestamp=? AND tipo='scope_ampliado'",
        (programa_id, fecha),
    ).fetchone() is not None


def refrescar(con, aplicar):
    """
    Recalcula el contexto (tecnologías + perfil del programa) de los informes
    ya creados, sin tocar sus assets ni lo que haya aportado el recon.

    Sirve cuando cambia qué se publica de cada programa: los informes viejos
    se ponen al día en vez de quedarse con el formato anterior.
    """
    filas = con.execute("SELECT id, programa_id, datos_json FROM informes").fetchall()
    for informe_id, programa_id, datos_raw in filas:
        datos = json.loads(datos_raw) if datos_raw else {}
        datos.pop("omitidos_sin_bounty", None)   # todos los assets pagan por construcción
        datos.pop("bounty_max", None)            # ahora vive dentro de `programa`
        datos.update(sync.contexto_programa(con, programa_id))
        tecs = datos.get("tecnologias", [])
        print(f"  informe {informe_id:>3}: {len(tecs)} tecnología(s) "
              f"{'· ' + ', '.join(tecs[:5]) if tecs else '(ninguna detectada)'}")
        if aplicar:
            con.execute("UPDATE informes SET datos_json=? WHERE id=?",
                        (json.dumps(datos, ensure_ascii=False), informe_id))
    if aplicar:
        con.commit()
    return len(filas)


def main():
    ap = argparse.ArgumentParser(description="Backfill de informes desde cambios ya detectados")
    ap.add_argument("--limite", type=int, default=10)
    ap.add_argument("--aplicar", action="store_true", help="sin esto solo muestra qué haría")
    ap.add_argument("--refrescar", action="store_true",
                    help="recalcular tecnologías y perfil de los informes ya creados")
    args = ap.parse_args()

    con = sqlite3.connect(DB_PATH)
    if args.refrescar:
        try:
            print(f"{'APLICANDO' if args.aplicar else 'SIMULACIÓN'} — refresco de contexto:\n")
            n = refrescar(con, args.aplicar)
            print(f"\n{n} informe(s) {'actualizados' if args.aplicar else 'sin tocar (simulación)'}.")
            return 0
        finally:
            con.close()
    try:
        elegidos = candidatos(con, args.limite)
        if not elegidos:
            print("No hay cambios de scope reconstruibles.")
            return 1

        print(f"{'APLICANDO' if args.aplicar else 'SIMULACIÓN'} — {len(elegidos)} informes:\n")
        creados = 0
        for c in elegidos:
            marca = "ya existe" if ya_existe(con, c["programa_id"], c["fecha"]) else "nuevo"
            print(f"  {c['fecha'][:16]}  {c['plataforma']:10} {c['nombre'][:34]:34} "
                  f"+{len(c['assets'])} assets  [{marca}]")
            for a in c["assets"][:3]:
                print(f"       · {a}")
            if len(c["assets"]) > 3:
                print(f"       · … y {len(c['assets']) - 3} más")

            if not args.aplicar or marca == "ya existe":
                continue

            datos = {
                "assets": c["assets"][:50],
                "assets_total": len(c["assets"]),
                "omitidos_sin_bounty": c["omitidos"],
                "bounty_max": c["max_bounty"],
            }
            con.execute(
                """INSERT INTO informes
                   (timestamp, plataforma, programa_id, programa_nombre, tipo, titulo,
                    datos_json, url_programa, relevancia, es_rareza, publicado, origen)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    c["fecha"], c["plataforma"], c["programa_id"], c["nombre"],
                    "scope_ampliado",
                    sync.TITULOS["scope_ampliado"].format(nombre=c["nombre"], n=len(c["assets"])),
                    json.dumps(datos, ensure_ascii=False),
                    c["url"], 0, 0, 1, "backfill",
                ),
            )
            creados += 1

        if args.aplicar:
            con.commit()
            print(f"\n{creados} informe(s) creados.")
        else:
            print("\nNada escrito. Repite con --aplicar para crearlos.")
        return 0
    finally:
        con.close()


if __name__ == "__main__":
    sys.exit(main())
