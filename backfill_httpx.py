#!/usr/bin/env python3
"""
backfill_httpx.py — rellena la caracterización web de servicios ya descubiertos.

POR QUÉ EXISTE
    La tabla `servicios` se llena por dos vías: httpx (capa 2), que trae código
    HTTP, título, tecnologías y WAF; y nmap (capa 3), que solo sabe decir qué
    puerto está abierto y qué protocolo cree que corre ahí. Hasta el
    2026-08-07 httpx NO corría en el pase profundo, así que todo lo que
    descubrió naabu quedó sin caracterizar; y aun después, httpx sondea HOSTS
    (puertos por defecto), no los puertos raros que encuentra naabu.

    Resultado medido el 2026-08-19: de 2790 servicios en la BD, **1298 no
    tenían `status`**, y 1172 de ellos son claramente web (80/443/8080/8443).
    Informes enteros —Exodus (4 y 12), 100 servicios cada uno— salían en la web
    con la columna «Respuesta» vacía de arriba abajo.

    Esto NO amplía el alcance de lo que tocamos: sondea servicios que ya
    estaban en la tabla, es decir, hosts que el recon ya visitó en su día. Solo
    completa el dato que faltaba.

QUÉ MARCA
    `ts_sondeo` se escribe en TODOS los objetivos enviados, respondan o no. Es
    lo que permite distinguir en la web "no lo hemos mirado" (`ts_sondeo` NULL)
    de "lo miramos y no contestó" (`ts_sondeo` con fecha y `status` NULL), que
    hasta ahora eran el mismo guion. Caso real que lo motivó:
    `vfo03.vodafone.om` (Vodafone Oman) es intermitente —2 de 3 sondeos dan 503
    y uno no contesta—, y su fila se leía igual que un servicio sin sondear.

Uso:
    python3 backfill_httpx.py                 # todo lo pendiente
    python3 backfill_httpx.py --limite 50     # una cata
    python3 backfill_httpx.py --programa 143  # solo un programa
    python3 backfill_httpx.py --simular       # qué haría, sin tocar nada ni red
"""
import argparse
import json
import subprocess
import sqlite3
import sys
import tempfile
from pathlib import Path

from recon_pipeline import BIN, HTTPX_RATE, HTTPX_THREADS, ahora

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH = str(BASE / "programas.db")

# Puertos que se sondean aunque nmap no haya sabido decir qué corre ahí. El
# criterio real es el `servicio` (cualquier cosa con "http" dentro); esta lista
# es el respaldo para las filas que nmap dejó como `tcpwrapped` o vacías.
PUERTOS_WEB = (80, 443, 8080, 8443, 8000, 8888, 4443, 9443, 8081)

LOTE = 400          # objetivos por invocación de httpx


def conectar():
    con = sqlite3.connect(DB_PATH, timeout=60)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


def pendientes(con, programa_id=None, limite=None):
    """Servicios web ya descubiertos a los que les falta la caracterización."""
    sql = """
        SELECT sv.id, s.subdominio, sv.puerto
          FROM servicios sv
          JOIN subdominios s ON s.id = sv.subdominio_id
         WHERE sv.status IS NULL AND sv.ts_sondeo IS NULL
           AND (sv.servicio LIKE '%http%' OR sv.puerto IN {puertos})
    """.format(puertos=str(PUERTOS_WEB))
    params = []
    if programa_id:
        sql += """ AND sv.subdominio_id IN (
                     SELECT subdominio_id FROM programa_subdominio WHERE programa_id = ?)"""
        params.append(programa_id)
    sql += " ORDER BY sv.id"
    if limite:
        sql += f" LIMIT {int(limite)}"
    return con.execute(sql, params).fetchall()


def sondear(objetivos):
    """
    httpx sobre `host:puerto`, con los MISMOS flags que la capa 2 del pipeline
    para que el dato que entra por aquí sea indistinguible del que entra por
    allí. Devuelve {"host:puerto": registro}.
    """
    with tempfile.TemporaryDirectory() as tmp:
        entrada = Path(tmp) / "in.txt"
        entrada.write_text("\n".join(objetivos) + "\n")
        r = subprocess.run(
            [BIN["httpx"], "-l", str(entrada), "-json", "-silent",
             "-sc", "-title", "-td", "-server", "-fr", "-cdn",
             "-rl", str(HTTPX_RATE), "-threads", str(HTTPX_THREADS)],
            capture_output=True, text=True, timeout=1800,
        )
    out = {}
    for linea in r.stdout.splitlines():
        try:
            d = json.loads(linea)
        except json.JSONDecodeError:
            continue
        clave = (d.get("input") or "").strip().lower()
        if clave:
            out[clave] = d
    return out


def cdn_de(d):
    if d.get("cdn") and d.get("cdn_name"):
        return f"{d['cdn_name']}/{d.get('cdn_type') or 'cdn'}"
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--programa", type=int, help="limitar a un programa")
    ap.add_argument("--limite", type=int, help="máximo de servicios a sondear")
    ap.add_argument("--simular", action="store_true", help="no toca red ni BD")
    args = ap.parse_args()

    con = conectar()
    filas = pendientes(con, args.programa, args.limite)
    if not filas:
        print("Nada pendiente: todos los servicios web tienen status o ya se sondearon.")
        return 0

    print(f"{len(filas)} servicios pendientes de caracterizar.")
    if args.simular:
        for sid, host, puerto in filas[:20]:
            print(f"  [{sid}] {host}:{puerto}")
        if len(filas) > 20:
            print(f"  … y {len(filas) - 20} más")
        return 0

    objetivos = {f"{host.lower()}:{puerto}": sid for sid, host, puerto in filas}
    claves = list(objetivos)
    ts = ahora()
    con_dato = sin_respuesta = 0

    for i in range(0, len(claves), LOTE):
        lote = claves[i:i + LOTE]
        print(f"  httpx {i + 1}-{i + len(lote)} de {len(claves)}…", flush=True)
        try:
            resp = sondear(lote)
        except subprocess.TimeoutExpired:
            # El lote se pierde, pero NO se marca: sin marca se reintenta en la
            # pasada siguiente, que es justo lo que se quiere de un timeout.
            print("    ⚠️ httpx agotó el plazo en este lote: se deja pendiente")
            continue

        for clave in lote:
            sid = objetivos[clave]
            d = resp.get(clave)
            if not d:
                # Sondeado y sin respuesta: se marca la fecha y `status` sigue
                # NULL. La web lo pinta distinto de "no sondeado".
                con.execute("UPDATE servicios SET ts_sondeo=? WHERE id=?", (ts, sid))
                sin_respuesta += 1
                continue
            con.execute(
                """UPDATE servicios
                      SET status = COALESCE(?, status),
                          title  = COALESCE(?, title),
                          tech   = COALESCE(?, tech),
                          server = COALESCE(?, server),
                          cdn    = COALESCE(?, cdn),
                          ts_sondeo = ?, fecha_analisis = ?
                    WHERE id = ?""",
                (d.get("status_code"), d.get("title"),
                 ",".join(d.get("tech") or []) or None,
                 d.get("webserver"), cdn_de(d), ts, ts, sid),
            )
            con_dato += 1
        con.commit()

    print(f"Hecho: {con_dato} caracterizados, {sin_respuesta} sondeados sin respuesta.")
    print("Recuerda publicar: python3 export_json.py --deploy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
