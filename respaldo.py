#!/usr/bin/env python3
"""
respaldo.py — genera los feeds en local cuando la fuente primaria muere.

Todo el sistema cuelga de `bounty-targets-data`, un repo que actualiza una sola
persona desde su propia infraestructura. Cuando se para, el sync sigue corriendo
tan campante y diciendo "0 nuevos": la avería es indistinguible de la calma. Ya
ha pasado varias veces (hay issues suyos titulados "The bounty-targets-data is
stopped"), y el 2026-08-12 se paró de nuevo — tres días en los que se perdieron
un programa nuevo que paga y un wildcard nuevo en un programa de 2.500 €.

Este módulo es el plan B: detecta la parada, genera los mismos feeds con el
crawler del propio autor (MIT, copiado en `vendor/bounty-targets`, ver su
README-LOCAL.md) y se lo sirve a `sync.py` por `file://`, que no distingue
porque el formato es idéntico. En cuanto la fuente vuelve, se aparta solo.

Reparto de responsabilidades:
  generar_feeds.rb  — scrapea (una plataforma por hilo, aisladas entre sí)
  respaldo.py       — decide cuándo, valida lo que sale y lo promueve
  sync.py           — consume, sin enterarse de dónde viene

POR QUÉ SE VALIDA ANTES DE PROMOVER: `sync.marcar_inactivos()` da por cerrado
todo programa que no aparezca en el feed. Un scrape a medias —la mitad de las
páginas, un cambio de markup, un rate limit— no daría un error ruidoso: daría un
feed corto y creíble que cerraría en masa programas vivos. De ahí el suelo de
`_minimo_aceptable()`: un feed que no lo alcanza se descarta entero y se sigue
con el de GitHub, aunque esté viejo. Un dato viejo es un inconveniente; un dato
falso corrompe la BD y no se nota hasta mucho después.
"""
import fcntl
import json
import logging
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE = Path(__file__).resolve().parent
FEEDS_DIR = BASE / "feeds_local"
ESTADO_PATH = FEEDS_DIR / "estado.json"
RUNNER = BASE / "generar_feeds.rb"
DB_PATH = BASE / "programas.db"

# Cuánto silencio de la fuente convierte la sospecha en diagnóstico. Medido
# sobre 500 commits (12,2 días): mediana de 30 min entre commits y los huecos
# normales son múltiplos limpios de 30 (60 o 90 min, uno o dos ciclos sin
# cambios). El único hueco mayor de 2 h en toda la ventana fue de 29 h y
# resultó ser una avería: terminó 9 minutos después de que el autor pusheara un
# arreglo a su generador. Con 3 h el umbral se habría disparado una vez en 12
# días, y habría acertado.
UMBRAL_ACTIVAR_MIN = 3 * 60

# Un feed generado tiene que traer al menos esta fracción de lo que trajo la
# última generación buena.
RATIO_MINIMO = 0.8

# Margen sobre el número de programas que ya tenemos en la BD. Ver
# `_minimo_aceptable`: sin él, en plataformas donde casi todos los programas
# pagan (YesWeHack: 63 activos de 64 en el feed) un par de cierres normales
# bastarían para rechazar un feed bueno.
MARGEN_SUELO_BD = 0.9

# Cuánto puede envejecer un feed local antes de dejar de servirlo. Escenario que
# lo hace necesario: la fuente cae, generamos, vuelve, desactivamos... y semanas
# después vuelve a caer. Al reactivarse el modo, los ficheros de la vez anterior
# siguen en disco, y sin este corte el sync los leería como si fueran de ahora,
# haciendo retroceder la BD a un estado antiguo. Pasada esta edad se vuelve al
# feed de GitHub —congelado, pero coherente— hasta que el timer regenere.
MAX_EDAD_FEED_MIN = 180

PLATAFORMAS = ("hackerone", "bugcrowd", "intigriti", "yeswehack", "federacy")

# El último commit del repo ENTERO, sin filtrar por fichero. Es la pregunta
# correcta para "¿sigue viva la fuente?": preguntando por el path de una
# plataforma se confunde "nadie ha tocado ese feed" con "la fuente está muerta".
API_ULTIMO_COMMIT = ("https://api.github.com/repos/arkadiyt/bounty-targets-data"
                     "/commits?per_page=1")

log = logging.getLogger(__name__)


# ---------------------------------------------------------------- estado

def _estado_vacio():
    return {"activo": False, "desde": None, "commit_al_activar": None,
            "generado_en": None, "referencia": {}, "ultimo_error": None,
            "ventana_desde": None}


def leer_estado():
    try:
        d = json.loads(ESTADO_PATH.read_text())
        base = _estado_vacio()
        base.update(d)
        return base
    except (OSError, json.JSONDecodeError):
        return _estado_vacio()


def escribir_estado(estado):
    FEEDS_DIR.mkdir(parents=True, exist_ok=True)
    tmp = ESTADO_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(estado, indent=2, ensure_ascii=False))
    tmp.replace(ESTADO_PATH)


def esta_activo():
    return leer_estado()["activo"]


def consumir_ventana():
    """
    Desde cuándo se acumulan los cambios que va a ver el próximo barrido.

    Mientras la fuente está parada seguimos leyendo su último feed bueno, así
    que los datos no se refrescan aunque el sync corra cada 30 minutos. Cuando
    por fin entra un feed local, ese barrido trae de una vez TODO lo ocurrido
    desde el último commit de la fuente — tres días, en el caso que motivó esto.

    Sin esto, `construir_crono` mediría la ventana entre barridos (~30 min) y
    los informes datarían como recién salido un scope que puede llevar días
    publicado. Devuelve el timestamp una sola vez y lo borra: a partir del
    segundo barrido local la ventana ya vuelve a ser la normal.
    """
    estado = leer_estado()
    ts = estado.get("ventana_desde")
    if ts:
        estado["ventana_desde"] = None
        escribir_estado(estado)
    return ts


def edad_feeds_min():
    """Minutos desde la última generación. None si no se ha generado nunca."""
    ts = leer_estado().get("generado_en")
    if not ts:
        return None
    try:
        gen = datetime.strptime(ts, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    return int((datetime.now(timezone.utc) - gen).total_seconds() // 60)


def feed_local(plataforma):
    """
    Ruta del feed local de esta plataforma, si se puede confiar en él.

    Tres condiciones: modo activo, fichero presente y **recién generado**. Lo
    tercero es lo que evita servir los restos de una caída anterior — ver
    `MAX_EDAD_FEED_MIN`.
    """
    if not esta_activo():
        return None
    edad = edad_feeds_min()
    if edad is None or edad > MAX_EDAD_FEED_MIN:
        log.warning(f"[respaldo] feeds locales sin generar o demasiado viejos "
                    f"({edad} min): se sigue leyendo de GitHub hasta regenerarlos")
        return None
    ruta = FEEDS_DIR / f"{plataforma}_data.json"
    return ruta if ruta.exists() else None


def hay_feeds_locales():
    """
    ¿Tenemos ya algún feed generado que el sync vaya a leer?

    El modo puede estar activo sin feeds todavía: se activa en cuanto se detecta
    el silencio, pero generarlos lleva unos diez minutos. En esa franja el sync
    sigue leyendo el feed viejo de GitHub, que es la degradación segura.
    """
    return any(feed_local(p) for p in PLATAFORMAS)


# ------------------------------------------------- estado de la fuente

def ultimo_commit_fuente(intentos=2):
    """(sha, ts_utc, edad_min) del último commit del repo. (None, None, None) si no se sabe."""
    for intento in range(1, intentos + 1):
        try:
            with urllib.request.urlopen(API_ULTIMO_COMMIT, timeout=20) as r:
                commits = json.load(r)
            sha = commits[0]["sha"]
            iso = commits[0]["commit"]["committer"]["date"]
            ts = datetime.strptime(iso, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            edad = int((datetime.now(timezone.utc) - ts).total_seconds() // 60)
            return sha, ts.strftime("%Y-%m-%d %H:%M:%S"), edad
        except Exception as e:
            if intento >= intentos:
                log.warning(f"[respaldo] no se pudo leer el estado de la fuente: {e}")
                return None, None, None
            time.sleep(3)


def evaluar_fuente():
    """
    ¿Hay que entrar o salir del modo respaldo? Devuelve (transicion, detalle).

    transicion: "activado" | "desactivado" | None

    No notifica ni escribe en el log de alertas: eso lo hace quien llama
    (`sync.sincronizar`), que es quien tiene los canales de aviso. Aquí solo se
    decide y se persiste.

    Si no se puede consultar GitHub no se toca nada: no saber en qué estado está
    la fuente no es razón ni para entrar ni para salir. En modo respaldo eso
    significa seguir en local, que es el lado seguro.
    """
    estado = leer_estado()
    sha, ts, edad = ultimo_commit_fuente()
    if sha is None:
        return None, {"motivo": "no se pudo consultar la fuente"}

    detalle = {"sha": sha, "ts": ts, "edad_min": edad}

    if estado["activo"]:
        # Salir: basta con que aparezca un commit distinto del que había cuando
        # entramos. Cualquier commit nuevo significa que su cron volvió a
        # producir, que es justo lo que esperábamos.
        if sha != estado.get("commit_al_activar"):
            estado.update({"activo": False, "desde": None, "commit_al_activar": None})
            escribir_estado(estado)
            return "desactivado", detalle
        return None, detalle

    if edad is not None and edad >= UMBRAL_ACTIVAR_MIN:
        estado.update({
            "activo": True,
            "desde": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S"),
            "commit_al_activar": sha,
            # Desde cuándo NO tenemos datos frescos: el primer barrido con feeds
            # locales traerá de golpe todo lo ocurrido desde este commit, no lo
            # de los últimos 30 minutos. Ver `consumir_ventana`.
            "ventana_desde": ts,
        })
        escribir_estado(estado)
        return "activado", detalle

    return None, detalle


# -------------------------------------------------- generación y validación

def _programas_en_bd(plataforma):
    """Cuántos programas de esta plataforma tenemos ya (los que pagan)."""
    try:
        con = sqlite3.connect(f"file:{DB_PATH}?mode=ro", uri=True)
        try:
            return con.execute(
                "SELECT COUNT(*) FROM programas WHERE plataforma=? AND activo=1",
                (plataforma,),
            ).fetchone()[0]
        finally:
            con.close()
    except sqlite3.Error:
        return 0


def _minimo_aceptable(plataforma, estado):
    """
    Cuántos programas tiene que traer un feed para creérselo.

    Dos suelos, se toma el mayor:

    - **Los que ya sabemos que pagan y están activos**, con un margen. El feed
      trae TODOS los programas de la plataforma y la BD solo los que pagan, así
      que el feed no debería traer menos que la BD. Va con margen porque en
      YesWeHack casi todos pagan (63 activos de 64 en el feed) y sin él un par
      de cierres normales harían rechazar un feed perfectamente bueno: medido el
      2026-08-15, el primer barrido pasó por un solo programa de diferencia.
      Este suelo funciona desde la primera ejecución, sin historial.
    - **El 80% de la última generación buena**, cuando la hay. Detecta caídas
      parciales que el otro suelo no vería (p. ej. Bugcrowd bajando de 250 a
      200: seguiría por encima de los programas de la BD, y por eso el ratio
      importa).

    Ambos son deliberadamente laxos: buscan cazar un feed roto (vacío, truncado,
    la mitad de las páginas), no auditar diferencias de un puñado de programas.
    Rechazar de más también hace daño, porque deja el sistema leyendo datos
    congelados.
    """
    referencia = estado.get("referencia", {}).get(plataforma)
    suelos = [int(_programas_en_bd(plataforma) * MARGEN_SUELO_BD)]
    if referencia:
        suelos.append(int(referencia * RATIO_MINIMO))
    return max(suelos)


def generar(plataformas=None, log=None):
    """
    Scrapea, valida y promueve. Devuelve el resumen por plataforma.

    Los ficheros se generan en un directorio de trabajo y solo se copian a
    `feeds_local/` los que pasan la validación: así `sync.py` nunca ve un feed a
    medias, ni siquiera durante los diez minutos que dura el barrido.

    Un cerrojo impide que se solapen dos barridos. Es fácil que ocurra: el timer
    dispara cada hora y el sync puede lanzar uno más al detectar la caída, así
    que basta con que uno se alargue para pillar al siguiente. Dos a la vez
    duplicarían el tráfico contra las plataformas y se pisarían los ficheros de
    trabajo. El segundo no espera: se retira, porque el que ya corre va a dejar
    los feeds igual de frescos.
    """
    log = log or logging.getLogger(__name__)
    plataformas = list(plataformas or PLATAFORMAS)
    trabajo = FEEDS_DIR / ".trabajo"
    trabajo.mkdir(parents=True, exist_ok=True)

    cerrojo = open(FEEDS_DIR / ".generar.lock", "w")
    try:
        fcntl.flock(cerrojo, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        log.warning("[respaldo] ya hay un barrido en curso, este se retira")
        cerrojo.close()
        return {}
    try:
        return _generar(plataformas, trabajo, log)
    finally:
        try:
            fcntl.flock(cerrojo, fcntl.LOCK_UN)
        except OSError:
            pass
        cerrojo.close()


def _generar(plataformas, trabajo, log):
    """El barrido en sí. Llamar siempre desde `generar`, que sostiene el cerrojo."""

    t0 = time.time()
    log.info(f"[respaldo] generando feeds en local: {', '.join(plataformas)}")
    proc = subprocess.run(
        ["ruby", str(RUNNER), str(trabajo), ",".join(plataformas)],
        capture_output=True, text=True, cwd=str(BASE),
    )
    if proc.returncode != 0:
        log.error(f"[respaldo] el runner falló: {(proc.stderr or proc.stdout)[-400:]}")
        return {}

    try:
        resultados = json.loads(proc.stdout.strip().splitlines()[-1])["resultados"]
    except (ValueError, KeyError, IndexError) as e:
        log.error(f"[respaldo] resumen del runner ilegible ({e}): {proc.stdout[-300:]}")
        return {}

    estado = leer_estado()
    referencia = dict(estado.get("referencia", {}))
    promovidos = 0

    for plat in plataformas:
        r = resultados.get(plat, {"ok": False, "error": "sin resultado"})
        if not r.get("ok"):
            log.warning(f"[respaldo] {plat}: FALLA — {r.get('error')}")
            continue

        n = r["programas"]
        minimo = _minimo_aceptable(plat, estado)
        if n < minimo:
            # Descartar es la decisión correcta: con este feed, sync cerraría en
            # masa programas que siguen abiertos.
            log.error(f"[respaldo] {plat}: DESCARTADO — {n} programas, "
                      f"por debajo del mínimo {minimo}. Se conserva el feed anterior.")
            r["descartado"] = True
            r["minimo"] = minimo
            continue

        origen = trabajo / f"{plat}_data.json"
        destino = FEEDS_DIR / f"{plat}_data.json"
        origen.replace(destino)
        referencia[plat] = n
        promovidos += 1
        log.info(f"[respaldo] {plat}: {n} programas en {r['segundos']}s (mínimo {minimo}) ✓")

    estado["referencia"] = referencia
    estado["generado_en"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    estado["ultimo_error"] = None if promovidos == len(plataformas) else "alguna plataforma falló o se descartó"
    escribir_estado(estado)

    log.info(f"[respaldo] {promovidos}/{len(plataformas)} feeds promovidos "
             f"en {time.time() - t0:.0f}s")
    return resultados


def lanzar_generacion_en_segundo_plano(log=None):
    """
    Pide al servicio del respaldo que genere los feeds YA, sin esperar al timer.

    Al activarse el modo, esperar al siguiente disparo horario dejaría hasta 60
    minutos leyendo el feed congelado de una fuente que ya sabemos muerta. El
    barrido dura ~10 min, así que arrancarlo en cuanto se detecta la caída
    recorta la recuperación de una hora larga a diez minutos.

    Se delega en systemd en vez de lanzar el proceso a mano para que herede el
    timeout y el entorno del servicio, y para que no muera con el sync (que es
    un `oneshot` y termina enseguida). `--no-block` devuelve el control al
    momento: el barrido sigue por su cuenta.
    """
    log = log or logging.getLogger(__name__)
    try:
        subprocess.run(
            ["systemctl", "--user", "--no-block", "start", "bugbounty-respaldo.service"],
            check=True, capture_output=True, text=True, timeout=15,
        )
        log.info("[respaldo] generación de feeds lanzada en segundo plano")
        return True
    except Exception as e:
        # Que falle no es crítico: el timer horario lo hará de todos modos.
        log.warning(f"[respaldo] no se pudo lanzar la generación inmediata: {e}")
        return False


def main():
    import argparse
    ap = argparse.ArgumentParser(description="Respaldo local de la fuente de scopes")
    ap.add_argument("--generar", action="store_true",
                    help="scrapear ahora, pase lo que pase (uso manual)")
    ap.add_argument("--si-activo", action="store_true",
                    help="scrapear solo si el modo respaldo está activo (para el timer)")
    ap.add_argument("--estado", action="store_true", help="mostrar el estado y salir")
    ap.add_argument("--plataformas", help="lista separada por comas")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                        datefmt="%Y-%m-%d %H:%M:%S")

    if args.estado:
        estado = leer_estado()
        sha, ts, edad = ultimo_commit_fuente()
        print(json.dumps({"modo_respaldo": estado,
                          "fuente": {"sha": sha, "ultimo_commit": ts, "edad_min": edad}},
                         indent=2, ensure_ascii=False))
        return 0

    plats = args.plataformas.split(",") if args.plataformas else None

    if args.si_activo:
        if not esta_activo():
            log.info("[respaldo] modo inactivo: la fuente primaria funciona, no se scrapea")
            return 0
        generar(plats, log=log)
        return 0

    if args.generar:
        generar(plats, log=log)
        return 0

    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
