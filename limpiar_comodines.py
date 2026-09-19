#!/usr/bin/env python3
"""
limpiar_comodines.py — retira de la BD los subdominios que solo existen porque
el dominio tiene comodín DNS.

Un dominio con comodín responde que SÍ a cualquier nombre inventado. Hasta el
2026-08-19 la resolución de lo pasivo (dnsx) no lo filtraba —solo el bruteforce,
vía puredns—, así que entraron como superficie viva miles de hosts que no
existen, se sondearon con httpx y se publicaron. Casos medidos: `emarketer.com`
respondía a todo con 8.8.8.8 (el DNS público de Google) y dejó 499 hosts falsos
en el informe de Axel Springer; `*.yellow-fellow.moonpay.com`, 4.437 en MoonPay.

El pipeline ya no los deja entrar (`resolver()` → `_comodines()`). Esto repara
lo que quedó guardado antes de ese arreglo, con el MISMO criterio: se pregunta
por nombres inventados de cada rama y solo se descarta lo que resuelva a las IPs
con las que contesta el comodín.

NO se usa `dnsx -auto-wildcard`: decide por frecuencia de respuestas iguales, así
que un objetivo con cientos de subdominios tras el mismo CDN se le parece a un
comodín. Aquí se sondea con nombres inventados y se exige que la IP coincida.

Qué hace con lo que detecta:
  - el subdominio se marca `vivo=0` y NO se borra: un nombre bajo comodín no
    resuelve de verdad, y conservar la fila permite ver el día que cambie.
  - sus `servicios` sí se borran: describen al servidor del comodín (Google, un
    balanceador), no al programa, así que son datos falsos sobre un tercero.

Uso:
  python3 limpiar_comodines.py [--raiz DOMINIO] [--minimo N] [--simular]
"""

import argparse
import collections
import json
import logging
import random
import sqlite3
import subprocess
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB = BASE / "programas.db"
DNSX = Path.home() / "go/bin/dnsx"
HILOS = 25

log = logging.getLogger(__name__)


def conectar():
    con = sqlite3.connect(DB, timeout=60)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    return con


def raices(con, minimo, solo=None):
    """Raíces con suficientes vivos como para que un comodín se note."""
    if solo:
        return [solo]
    return [r for (r,) in con.execute(
        "SELECT raiz FROM subdominios WHERE vivo=1 AND raiz IS NOT NULL "
        "GROUP BY raiz HAVING COUNT(*) >= ? ORDER BY COUNT(*) DESC", (minimo,))]


def _rama(host):
    partes = host.split(".", 1)
    return partes[1] if len(partes) == 2 else host


def comodines_de(hosts):
    """
    Ramas con comodín entre las de estos hosts → {rama: {ips del comodín}}.

    Dos nombres inventados por rama con al menos tres hijos. Si contestan, esa
    rama responde a cualquier cosa y sus IPs son las que no valen.
    """
    ramas = collections.Counter(_rama(h) for h in hosts)
    sondas = {}
    for r, n in ramas.items():
        if n >= 3:
            for i in range(2):
                sondas[f"zzq{random.randrange(10**8, 10**9)}x{i}.{r}"] = r
    if not sondas:
        return {}

    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False) as f:
        f.write("\n".join(sondas) + "\n")
        entrada = f.name
    try:
        r = subprocess.run(
            [str(DNSX), "-l", entrada, "-a", "-json", "-silent", "-t", str(HILOS)],
            capture_output=True, text=True, timeout=900,
        )
    finally:
        Path(entrada).unlink(missing_ok=True)

    fuera = {}
    for l in r.stdout.splitlines():
        try:
            d = json.loads(l)
        except json.JSONDecodeError:
            continue
        rama = sondas.get((d.get("host") or "").lower())
        if rama:
            fuera.setdefault(rama, set()).update(d.get("a") or [])
    return fuera


def limpiar(minimo=5, solo=None, aplicar=True):
    con = conectar()
    total_falsos = total_srv = 0
    afectadas = []

    for raiz in raices(con, minimo, solo):
        filas = con.execute(
            "SELECT id, subdominio, ip FROM subdominios WHERE raiz=? AND vivo=1",
            (raiz,)).fetchall()
        if not filas:
            continue
        comodines = comodines_de([s.lower() for _, s, _ in filas])
        falsos = [i for i, s, ip in filas
                  if ip and ip in comodines.get(_rama(s.lower()), ())]
        if not falsos:
            log.info("%-28s %4d vivos, 0 bajo comodín", raiz, len(filas))
            continue

        marcas = ",".join("?" * len(falsos))
        srv = con.execute(
            f"SELECT COUNT(*) FROM servicios WHERE subdominio_id IN ({marcas})",
            falsos).fetchone()[0]
        log.warning("%-28s %4d vivos → %4d bajo comodín (%d servicios falsos)",
                    raiz, len(filas), len(falsos), srv)
        afectadas.append({"raiz": raiz, "vivos": len(filas),
                          "comodin": len(falsos), "servicios": srv})
        total_falsos += len(falsos)
        total_srv += srv
        if aplicar:
            con.execute(
                f"DELETE FROM servicios WHERE subdominio_id IN ({marcas})", falsos)
            con.execute(
                f"UPDATE subdominios SET vivo=0 WHERE id IN ({marcas})", falsos)
            con.commit()

    return {"raices_afectadas": afectadas, "subdominios": total_falsos,
            "servicios_borrados": total_srv, "aplicado": aplicar}


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")
    ap = argparse.ArgumentParser()
    ap.add_argument("--raiz", help="solo esta raíz")
    ap.add_argument("--minimo", type=int, default=5,
                    help="mínimo de vivos para revisar una raíz (def. 5)")
    ap.add_argument("--simular", action="store_true")
    a = ap.parse_args()
    r = limpiar(a.minimo, a.raiz, not a.simular)
    print(json.dumps({k: v for k, v in r.items() if k != "raices_afectadas"},
                     ensure_ascii=False))
