#!/usr/bin/env python3
"""
iconos.py — consigue el logo de los programas que no lo tienen.

Los cuatro `fetch_iconos_<plataforma>.py` ya sabían hacer su trabajo, pero
había que acordarse de lanzarlos: cada programa nuevo entraba sin icono y ahí
se quedaba. El 2026-08-16, tras recuperar los tres días de fuente caída, los
**10 programas nuevos de Bugcrowd estaban sin logo**, Zendesk incluido. Es el
mismo patrón que tenía la publicación de la web antes de `publicar.py`: el
código escrito y nadie llamándolo.

Esto es ese disparador. `sync.py` lo invoca al detectar altas, ANTES de
publicar, para que el informe llegue a la web ya con su icono en vez de
aparecer horas más tarde.

Todos los fetchers cruzan por IDENTIFICADOR de plataforma, no por parecido de
nombre, y aceptan `--solo-vacios`, así que esto es idempotente: en un día
normal no descarga nada y solo consulta las plataformas que han tenido altas.

HACKERONE. Su logo se pide por GraphQL y el fetcher recibe el mapa ya hecho por
`--json`. Su documentación decía que ese mapa había que generarlo a mano desde
la consola del navegador porque GraphQL exigía el CSRF de una sesión con login.
Comprobado el 2026-08-16: **no lo exige**, basta el token de la página pública
del directorio. `logos_hackerone.rb` lo hace con el cliente del crawler
vendorizado, y con eso HackerOne deja de ser el caso manual.
"""
import argparse
import json
import logging
import sqlite3
import subprocess
import sys
import tempfile
from pathlib import Path

BASE = Path(__file__).resolve().parent
DB_PATH = BASE / "programas.db"

# Federacy queda fuera a propósito: **no publica logos por programa**
# (comprobado 2026-08-16 sobre la página de `tuple`, su único `og:image` es la
# esfera genérica de la marca y no hay ningún dato de logo/avatar embebido).
# No hay `fetch_iconos_federacy.py` porque no habría de dónde bajarlos; sus
# programas salen sin icono, como los 7 de YesWeHack que tampoco tienen.
#
# GObugfree SÍ entra (2026-08-16): publica un logo por programa en
# `media.gobugfree.com` y 23 de sus 24 fichas lo traen —los 8 que pagan,
# todos—. Su fetcher es el único que no consulta a la plataforma para saber qué
# logo toca: la URL ya viene en el feed que genera `fetch_gobugfree.py`.
PLATAFORMAS = ("hackerone", "bugcrowd", "intigriti", "yeswehack", "gobugfree")

log = logging.getLogger(__name__)


def sin_icono(plataforma):
    """Programas activos de esta plataforma que no tienen icono."""
    con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
    try:
        return con.execute(
            "SELECT plataforma_id FROM programas "
            "WHERE plataforma=? AND activo=1 AND (icono IS NULL OR icono='')",
            (plataforma,),
        ).fetchall()
    finally:
        con.close()


def _ejecutar(cmd, log):
    proc = subprocess.run(cmd, capture_output=True, text=True, cwd=str(BASE))
    if proc.returncode != 0:
        log.warning(f"[iconos] falló {Path(cmd[1]).name}: "
                    f"{(proc.stderr or proc.stdout)[-300:]}")
        return None
    return proc.stdout


def _resumen(salida):
    """
    Última línea informativa del fetcher, para no volcar su salida entera.

    Cada uno la formatea a su manera: Bugcrowd e Intigriti empiezan la línea con
    "a descargar:", mientras HackerOne y YesWeHack la anteponen con "BD <plat>:".
    Por eso se busca la subcadena y no el principio de la línea.
    """
    if not salida:
        return ""
    utiles = [l.strip() for l in salida.splitlines()
              if "a descargar:" in l or l.strip().startswith("Descargados:")]
    return utiles[-1] if utiles else ""


def actualizar(plataformas=None, aplicar=True, log=None):
    """
    Baja los iconos que falten. Devuelve {plataforma: resumen}.

    Con `aplicar=False` los fetchers corren en simulación: dicen qué harían sin
    tocar disco ni BD. Útil para ver el estado sin gastar descargas.
    """
    log = log or logging.getLogger(__name__)
    plataformas = list(plataformas or PLATAFORMAS)
    resultados = {}

    for plat in plataformas:
        pendientes = sin_icono(plat)
        if not pendientes:
            continue        # nada que hacer: ni se consulta la plataforma

        log.info(f"[iconos] {plat}: {len(pendientes)} programa(s) sin icono")
        cmd = [sys.executable, str(BASE / f"fetch_iconos_{plat}.py"), "--solo-vacios"]
        if aplicar:
            cmd.append("--aplicar")

        if plat == "hackerone":
            # El fetcher no habla con GraphQL: se le da el mapa hecho.
            mapa = _mapa_hackerone([h for (h,) in pendientes], log)
            if not mapa:
                resultados[plat] = "sin mapa de logos"
                continue
            with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
                json.dump(mapa, f)
                ruta_mapa = f.name
            try:
                resultados[plat] = _resumen(_ejecutar(cmd + ["--json", ruta_mapa], log))
            finally:
                Path(ruta_mapa).unlink(missing_ok=True)
        else:
            resultados[plat] = _resumen(_ejecutar(cmd, log))

        if resultados.get(plat):
            log.info(f"[iconos] {plat}: {resultados[plat]}")

    return resultados


def _mapa_hackerone(handles, log):
    """handle -> {profile_picture}, vía `logos_hackerone.rb` (sin login)."""
    proc = subprocess.run(
        ["ruby", str(BASE / "logos_hackerone.rb"), *handles],
        capture_output=True, text=True, cwd=str(BASE),
    )
    if proc.returncode != 0:
        log.warning(f"[iconos] no se pudo obtener el mapa de HackerOne: "
                    f"{(proc.stderr or proc.stdout)[-300:]}")
        return {}
    try:
        return json.loads(proc.stdout.strip().splitlines()[-1])
    except (ValueError, IndexError) as e:
        log.warning(f"[iconos] mapa de HackerOne ilegible ({e})")
        return {}


def main():
    ap = argparse.ArgumentParser(description="Consigue los iconos que falten")
    ap.add_argument("--simular", action="store_true",
                    help="decir qué se bajaría, sin bajar nada")
    ap.add_argument("--plataformas", help="lista separada por comas")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")
    plats = args.plataformas.split(",") if args.plataformas else None
    resultados = actualizar(plats, aplicar=not args.simular, log=log)
    if not resultados:
        print("Todos los programas activos tienen icono.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
