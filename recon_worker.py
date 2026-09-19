#!/usr/bin/env python3
"""
recon_worker.py — consume `recon_cola` y funde los hallazgos en el informe.

Reglas que rigen esto:

  - **Pool acotado**: N jobs a la vez como mucho. El control de ritmo se hace
    aquí, no en el disparo; N acota la carga sobre los recursos compartidos
    (resolvers, ancho de banda, la propia máquina).
  - **Cerrojo por programa**: nunca dos jobs sobre el mismo programa a la vez.
    Programas distintos sí van en paralelo; el límite de ritmo importa por
    objetivo, para no concentrar peticiones sobre un mismo servidor.
  - **Un informe por asunto**: todos los jobs que apunten al mismo `informe_id`
    funden su resultado en esa única fila. El feed no crece con cada job.

Uso:
    python3 recon_worker.py              # procesa lo pendiente y sale
    python3 recon_worker.py --daemon     # se queda escuchando la cola
    python3 recon_worker.py --pool 3
"""
import argparse
import json
import logging
import sqlite3
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import publicar as publicador
import recon_pipeline
import recon_scope

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH      = str(BASE / "programas.db")
POOL_DEFECTO = 2
MAX_INTENTOS = 3

# Dos velocidades. El valor del proyecto es llegar antes que nadie, así que el
# primer pase se acota a lo que da resultado en minutos y publica; lo caro va
# después, en segundo plano, y se funde en el mismo informe.
# TRES fases, de más rápida a más lenta, que reconstruyen el MISMO informe según
# van terminando (preliminar → … → definitivo). Ninguna mata a ninguna
# herramienta: la rapidez del preliminar la da este reparto, no un cronómetro.
# Historia y porqué en docs/recon.md → "Orquestación: cola, worker y fases".
CAPAS_RAPIDO   = "c2"    # CT (certspotter/crt.sh) + httpx  → preliminar en segundos
CAPAS_PASIVO   = "s2"    # subfinder + gau + httpx sobre lo nuevo (lento, SIN corte)
# El "2" (httpx) va en las tres: lo que descubren subfinder/bruteforce/github hay
# que caracterizarlo como web (título/tech/status/WAF). Idempotente para los ya
# vistos (UPDATE), así que re-sondear no duplica.
CAPAS_PROFUNDO = "123"   # bruteforce/permutaciones + github + httpx + puertos

CAPAS_DE_FASE = {"rapido": CAPAS_RAPIDO, "pasivo": CAPAS_PASIVO, "profundo": CAPAS_PROFUNDO}
# Prioridad de cola (tomar_job ordena por prioridad DESC). Los EVENTOS reales de
# sync —programa nuevo, scope ampliado, reactivado— ganan SIEMPRE al
# mantenimiento (re-ejecución periódica en masa): un evento real no puede quedar
# esperando detrás de una tanda de mantenimiento, que es lo que da valor al
# proyecto (llegar antes que nadie). Dentro de cada clase, rápido antes que
# profundo. Ojo: esto ordena la COLA; no interrumpe un job ya en curso (el pool
# no expropia), así que un evento aún espera a que se libere un slot.
# (mantenimiento, evento) por fase. Rápido > pasivo > profundo dentro de cada
# clase; y cualquier evento gana a cualquier mantenimiento.
PRIORIDAD = {
    "rapido":   (10, 100),
    "pasivo":   (5,  75),
    "profundo": (0,  50),
}
TIPOS_MANTENIMIENTO = {"periodico"}


def prioridad_de(tipo, fase):
    """Prioridad de cola según el tipo de disparo y la fase."""
    mant = tipo in TIPOS_MANTENIMIENTO
    m, e = PRIORIDAD.get(fase, PRIORIDAD["profundo"])
    return m if mant else e
# Un job en_curso más viejo que esto se da por colgado y vuelve a la cola.
COLGADO_MIN  = 120
ESPERA_DAEMON = 60

# `force=True` es imprescindible: al importar `recon_pipeline` (arriba) ya se
# ha ejecutado SU basicConfig, y basicConfig no hace nada si el root logger ya
# tiene handlers. Sin esto, el FileHandler no llega a instalarse nunca y
# `logs/worker.log` se queda vacío mientras la salida solo va a stdout.
# En un checkout recién clonado no existe `logs/` y FileHandler revienta al
# importar, antes de que nadie llegue a ver un mensaje de error.
(Path(__file__).parent / "logs").mkdir(exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [worker] %(message)s",
    datefmt="%H:%M:%S",
    handlers=[
        logging.FileHandler(Path(__file__).parent / "logs" / "worker.log"),
        logging.StreamHandler(),
    ],
    force=True,
)
log = logging.getLogger(__name__)

_lock       = threading.Lock()
_en_curso   = set()          # programa_id con un job corriendo (cerrojo por programa)


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def conectar():
    """
    Conexión con espera larga y WAL.

    El worker no está solo en la BD: comparte fichero con sync (cada 30 min),
    export_json y publicar. Con el journal clásico (`delete`) cualquier
    escritura bloquea a todo el mundo, y de ahí salió el
    `sqlite3.OperationalError: database is locked` que mató al worker el
    2026-08-11 a las 00:09 en pleno `rescatar_colgados` (lo revivió
    `Restart=always`, pero cada muerte gasta un intento de los jobs en curso).

    WAL deja que los lectores sigan mientras uno escribe, que es justo el
    patrón de aquí. Es un ajuste del fichero, persistente: basta con que lo
    ponga quien lo abra primero. `synchronous=NORMAL` es el acompañante
    habitual de WAL — seguro ante caída del proceso, y solo arriesga la última
    transacción ante un corte de corriente, que para esta BD es asumible.
    """
    con = sqlite3.connect(DB_PATH, timeout=60)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA synchronous=NORMAL")
    return con


# ── Cola ─────────────────────────────────────────────────────────────────────

def rescatar_colgados(con):
    """
    Devuelve a 'pendiente' los jobs que se quedaron en_curso (worker muerto) y
    da por perdidos los que ya no tienen intentos.

    Lo segundo importa tanto como lo primero: `tomar_job` solo mira jobs con
    `intentos < MAX_INTENTOS`, así que un job que los agota se queda en
    'pendiente' para siempre — invisible para el worker y sin constar como
    fallo en ningún sitio. Caso real: el job 37 (MoonPay) encolado el
    2026-08-07 seguía así el 2026-08-11, después de que el worker muriera
    varias veces con la BD bloqueada y cada muerte le gastara un intento.
    Un trabajo que no se va a hacer tiene que decirlo.
    """
    n = con.execute(
        f"""UPDATE recon_cola SET estado='pendiente'
            WHERE estado='en_curso'
              AND (julianday('now') - julianday(fecha_inicio)) * 1440 > {COLGADO_MIN}"""
    ).rowcount
    con.commit()
    if n:
        log.warning(f"{n} job(s) colgados devueltos a la cola")

    agotados = con.execute(
        """UPDATE recon_cola
           SET estado='error',
               mensaje=COALESCE(mensaje, '') ||
                       'agotados los ' || intentos || ' intentos sin completar',
               fecha_procesado=?
           WHERE estado='pendiente' AND intentos >= ?""",
        (ahora(), MAX_INTENTOS),
    ).rowcount
    con.commit()
    if agotados:
        log.error(f"{agotados} job(s) marcados en error: agotaron los "
                  f"{MAX_INTENTOS} intentos sin completarse")


def tomar_job(con):
    """
    Coge el siguiente job elegible y lo marca en_curso, respetando el cerrojo
    por programa. Devuelve None si no hay nada que hacer ahora mismo.
    """
    with _lock:
        # Por prioridad antes que por antigüedad: un pase rápido de dos minutos
        # no puede quedarse detrás de uno profundo de tres horas, o la ventana
        # de oportunidad se pierde igual que si no hubiéramos detectado nada.
        filas = con.execute(
            """SELECT id, programa_id, tipo, assets_nuevos, informe_id, intentos, fase
               FROM recon_cola
               WHERE estado='pendiente' AND intentos < ?
               ORDER BY prioridad DESC, id""",
            (MAX_INTENTOS,),
        ).fetchall()
        for job in filas:
            if job[1] in _en_curso:
                continue          # ese programa ya tiene un job corriendo
            _en_curso.add(job[1])
            con.execute(
                "UPDATE recon_cola SET estado='en_curso', fecha_inicio=?, intentos=intentos+1 WHERE id=?",
                (ahora(), job[0]),
            )
            con.commit()
            return job
    return None


def cerrar_job(con, job_id, programa_id, estado, mensaje=None):
    con.execute(
        "UPDATE recon_cola SET estado=?, mensaje=?, fecha_procesado=? WHERE id=?",
        (estado, mensaje, ahora(), job_id),
    )
    con.commit()
    with _lock:
        _en_curso.discard(programa_id)


# ── Fusión de hallazgos en el informe ────────────────────────────────────────

# Códigos de error que NO llevan `tool`/`fuente` propios: a qué herramienta
# pertenecen, para saber si un pase que la re-ejecutó los deja obsoletos.
_COD_TOOL = {"subfinder_cero": "subfinder", "naabu_respondon": "naabu"}


def _error_cubierto(e, ejecutadas):
    """
    ¿Este pase re-ejecutó la herramienta a la que pertenece el error `e`? Si sí,
    el error viejo se descarta (si sigue fallando, el pase lo re-reporta en sus
    hallazgos). Si el pase no tocó esa herramienta, se conserva: puede seguir
    aplicando. Un error viejo en formato str (frase suelta, informes antiguos) no
    se puede mapear → se conserva (a lo sumo un aviso viejo de más, nunca uno
    ocultado de menos).
    """
    if not isinstance(e, dict):
        return False
    t = e.get("tool") or e.get("fuente")
    if t:
        return t in ejecutadas
    cod = e.get("cod")
    if cod in _COD_TOOL:
        return _COD_TOOL[cod] in ejecutadas
    if cod == "ct_caido":                        # sin fuente: lo cubre cualquiera de los dos
        return bool({"crtsh", "certspotter"} & ejecutadas)
    return False                                 # cod desconocido: conservar


def fusionar(con, informe_id, hallazgos):
    """
    Funde el resultado de un job en el `datos_json` del informe del asunto.

    Se deduplica por clave natural (subdominio; host+puerto+protocolo) para
    que reejecutar un job no infle la lista. Si el informe ya no existe, el
    recon no se pierde: sigue en las tablas, solo no se publica.
    """
    fila = con.execute(
        "SELECT datos_json, es_rareza FROM informes WHERE id=?", (informe_id,)
    ).fetchone()
    if not fila:
        log.warning(f"informe {informe_id} no existe; hallazgos solo en la BD de recon")
        return

    datos = json.loads(fila[0]) if fila[0] else {}
    recon = datos.setdefault("recon", {})

    def mezclar(clave, nuevos, id_fn):
        previos = {id_fn(x): x for x in recon.get(clave, [])}
        for x in nuevos:
            previos[id_fn(x)] = x
        recon[clave] = list(previos.values())

    mezclar("subdominios_nuevos", hallazgos.get("subdominios_nuevos", []),
            lambda x: x["subdominio"])
    mezclar("takeovers", hallazgos.get("takeovers", []), lambda x: x["subdominio"])
    mezclar("servicios_nuevos", hallazgos.get("servicios_nuevos", []),
            lambda x: f"{x['host']}:{x['puerto']}/{x['protocolo']}")

    recon["raices"] = sorted(set(recon.get("raices", [])) | set(hallazgos.get("raices", [])))

    # Errores del pase → datos_json.errores (top-level, no dentro de recon: la
    # web los lee como d.errores). Un error se RETIRA cuando su herramienta se
    # vuelve a ejecutar y esta vez no falla: si el pase corrió subfinder y ahora
    # sí dio resultados, "subfinder devolvió 0" del ciclo viejo ya no aplica y no
    # debe quedarse (medido 2026-08-17 en Threema). Los errores de herramientas
    # que este pase NO tocó se conservan (podrían seguir aplicando). Regla: se
    # descartan del histórico los errores cuya herramienta está en
    # `hallazgos["herramientas"]` (las que corrieron en este pase); los que
    # vuelvan a fallar reaparecen porque vienen en `hallazgos["errores"]`.
    # Son dicts `{"cod": ...}` que la web traduce; se deduplica y ordena por su
    # JSON canónico (los informes viejos guardan frases sueltas, que también
    # serializan, así que se arrastran igual).
    ejecutadas = set(hallazgos.get("herramientas", []))
    previos = [e for e in datos.get("errores", [])
               if not _error_cubierto(e, ejecutadas)]
    vistos = {}
    for e in previos + list(hallazgos.get("errores", [])):
        vistos.setdefault(json.dumps(e, sort_keys=True, ensure_ascii=False), e)
    datos["errores"] = [vistos[k] for k in sorted(vistos)]

    # Lo que httpx detecta sobre el objetivo real va en su propia clave y no en
    # `tecnologias`: esa la reescribe el exportador con los identificadores
    # derivados del scope, así que cualquier cosa escrita ahí se perdería al
    # publicar. Aquí van nombres libres (un CMS, un framework, un panel).
    detectadas = list(datos.get("tec_recon", []))
    for s in hallazgos.get("servicios_nuevos", []):
        for t in (s.get("tech") or "").split(","):
            t = t.strip()
            if t and t not in detectadas:
                detectadas.append(t)
    datos["tec_recon"] = detectadas

    # Resumen: es lo que el frontend puede pintar colapsado, sin desplegar.
    # `scope` no cuenta como rareza: un host que el propio programa publica en
    # su scope es lo contrario de un hallazgo raro. Rareza es lo que aparece
    # por una vía que no es la fuente pasiva habitual.
    rarezas = [s for s in recon["subdominios_nuevos"]
               if s.get("origen") not in ("subfinder", "scope")]
    datos["resumen"] = {
        "subdominios_nuevos": len(recon["subdominios_nuevos"]),
        "servicios_nuevos":   len(recon["servicios_nuevos"]),
        "takeovers":          len(recon["takeovers"]),
        "rarezas":            len(rarezas),
    }

    con.execute(
        "UPDATE informes SET datos_json=?, es_rareza=?, fecha_enriquecido=? WHERE id=?",
        (json.dumps(datos, ensure_ascii=False),
         1 if (rarezas or recon["takeovers"]) else fila[1],
         ahora(), informe_id),
    )
    con.commit()


# Qué etapas quedan por delante en cada punto, para que el preliminar diga al
# usuario qué falta. Las claves i18n las pinta la web (etapa_<x>).
PENDIENTE_TRAS_RAPIDO = ["subfinder", "bruteforce", "puertos", "github"]
PENDIENTE_TRAS_PASIVO = ["bruteforce", "puertos", "github"]
# Un job de solo hosts directos no enumera nada (no hay raíz que buscar en
# fuentes pasivas, bruteforcear ni buscar en GitHub): tras el rápido solo le
# quedan los puertos.
PENDIENTE_DIRECTOS = ["puertos"]


def marcar_fase(con, informe_id, completo, pendiente=None):
    """
    Marca en el informe si el recon está `completo` (definitivo) o no
    (preliminar), y qué etapas faltan. La web pinta el aviso "INFORME
    PRELIMINAR — falta X" solo mientras `completo` sea falso. Se toca solo esa
    parte de `datos_json.recon`, sin pisar lo que fusionó el recon.
    """
    if not informe_id:
        return
    fila = con.execute("SELECT datos_json FROM informes WHERE id=?", (informe_id,)).fetchone()
    if not fila:
        return
    datos = json.loads(fila[0]) if fila[0] else {}
    recon = datos.setdefault("recon", {})
    recon["completo"] = bool(completo)
    recon["pendiente"] = [] if completo else list(pendiente or [])
    con.execute("UPDATE informes SET datos_json=? WHERE id=?",
                (json.dumps(datos, ensure_ascii=False), informe_id))
    con.commit()


# ── Ejecución de un job ──────────────────────────────────────────────────────

def trabajo_del_job(programa_id, tipo, assets_json):
    """
    Traduce el disparo en QUÉ hay que mirar, distinguiendo dos cosas que antes
    se confundían:

      directos — hosts concretos que ya sabemos cuáles son (`mail.acme.com`,
                 una URL). No hay nada que enumerar: se resuelven y se sondean.
                 Segundos.
      raices   — dominios bajo los que SÍ hay que buscar: un wildcard nuevo
                 (`*.dev.acme.com` → se enumera `dev.acme.com`) o un apex que
                 no conocíamos. Minutos u horas.

    Antes esto subía todo asset al apex, así que un solo subdominio nuevo
    disparaba la enumeración completa del dominio: horas de trabajo para algo
    que ya sabías, y la ventana de oportunidad perdida.

    El filtro contra el scope no es cosmético: un asset puede apuntar a un
    tercero —un repo en `github.com`, una app en `apple.com`—. Sin este cruce,
    un scope ampliado con repos de GitHub acabaría lanzando bruteforce DNS
    contra GitHub, que no ha autorizado nada.

    Devuelve (directos, raices, todo_el_scope):
        todo_el_scope=True → programa nuevo/periódico: enumerar el scope entero
    """
    if tipo not in ("scope_ampliado",) or not assets_json:
        return [], None, True
    try:
        assets = json.loads(assets_json)
    except json.JSONDecodeError:
        return [], None, True

    plat, _, scope_in, scope_out = recon_scope.cargar_programa(programa_id)
    cls = recon_scope.clasificar(scope_in, scope_out, plat)

    directos, raices, fuera = set(), set(), set()
    for asset in assets:
        texto = str(asset).strip()
        if not texto:
            continue
        if "*" in texto:
            # `*.dev.acme.com` se enumera desde `dev.acme.com`, no desde el
            # apex: el wildcard acota la rama, y respetarlo es la diferencia
            # entre mirar una rama y mirar el dominio entero.
            rama = recon_scope._host(texto.replace("*.", "").replace("*", ""))
            if not rama:
                continue
            if recon_scope._apex(rama) in cls["raices"]:
                raices.add(rama)
            else:
                fuera.add(rama)
            continue
        host = recon_scope._host(texto)
        if not host:
            continue                    # apps, repos, texto libre: no es DNS
        if recon_scope.clasificar_sub(host, cls)[0] == 1:
            directos.add(host)
        elif recon_scope._apex(host) in cls["raices"]:
            directos.add(host)
        else:
            fuera.add(host)

    if fuera:
        log.warning(f"programa {programa_id}: {len(fuera)} asset(s) del delta fuera "
                    f"del scope, descartados: {sorted(fuera)[:5]}")
    return sorted(directos), sorted(raices), False


def encolar_fase(con, programa_id, tipo, assets_json, informe_id, fase):
    """
    Encola la SIGUIENTE fase del mismo asunto: mismo informe, misma lista de
    assets. Corre después y sin prisa, y sus hallazgos se funden en la misma
    fila — el feed no crece con una segunda entrada. Cada fase, al terminar,
    encola la que le sigue (rapido → pasivo → profundo), así el informe se
    reconstruye por etapas sin que ninguna espere a otra.
    """
    con.execute(
        """INSERT INTO recon_cola
           (programa_id, tipo, assets_nuevos, estado, fecha_encolado, informe_id,
            fase, prioridad)
           VALUES (?,?,?,?,?,?,?,?)""",
        (programa_id, tipo, assets_json, "pendiente", ahora(), informe_id,
         fase, prioridad_de(tipo, fase)),
    )
    con.commit()


def procesar(job):
    job_id, programa_id, tipo, assets_json, informe_id, intentos, fase = job
    fase = fase or "rapido"
    con = conectar()
    try:
        directos, raices, todo_el_scope = trabajo_del_job(programa_id, tipo, assets_json)
        if not todo_el_scope and not directos and not raices:
            # El delta no contiene ningún dominio del scope: no hay superficie
            # que mirar. Cerrar sin escanear es el resultado correcto, no un
            # fallo — pero se deja dicho para que no parezca que el recon falló.
            log.info(f"job {job_id}: delta sin dominios del scope, nada que reconear")
            cerrar_job(con, job_id, programa_id, "hecho",
                       "sin assets DNS in-scope en el delta")
            # No habrá recon (p. ej. una app): el informe ya es definitivo, se
            # quita el "preliminar" que puso sync y se publica.
            marcar_fase(con, informe_id, completo=True)
            publicador.publicar(log=log)
            return

        capas = CAPAS_DE_FASE.get(fase, CAPAS_PROFUNDO)
        log.info(f"job {job_id} [{fase}]: programa {programa_id}, tipo {tipo}, "
                 f"{len(directos)} directo(s), "
                 f"{'todo el scope' if todo_el_scope else str(len(raices)) + ' raíz/raíces'}, "
                 f"capas {capas}")
        hallazgos = recon_pipeline.correr(
            programa_id,
            raices=None if todo_el_scope else raices,
            directos=directos,
            capas=capas,
        )
        if informe_id:
            fusionar(con, informe_id, hallazgos)
        cerrar_job(con, job_id, programa_id, "hecho")
        log.info(
            f"job {job_id} [{fase}] hecho: {len(hallazgos['subdominios_nuevos'])} subdominios, "
            f"{len(hallazgos.get('servicios_nuevos', []))} servicios, "
            f"{len(hallazgos['takeovers'])} takeover"
        )
        # Cadena de fases: rapido → pasivo → profundo. Cada una encola la
        # siguiente DESPUÉS de publicar la suya, así el informe ya está en la web
        # mientras lo lento sigue. La fase "pasivo" (subfinder/gau) solo aplica si
        # hay algo que enumerar (raíces); un job de solo hosts directos salta de
        # rapido a profundo (no hay nada que enumerar, pero sí puertos que
        # escanear — capa 3 no corre en el rápido; caso medido: Visma). El
        # profundo cierra. Las capas que no aplican se saltan solas (capa1 y
        # github exigen raíz).
        hay_enumerar = bool(todo_el_scope or raices)
        if fase == "rapido":
            siguiente = "pasivo" if hay_enumerar else ("profundo" if directos else None)
        elif fase == "pasivo":
            siguiente = "profundo"
        else:
            siguiente = None
        if siguiente:
            encolar_fase(con, programa_id, tipo, assets_json, informe_id, siguiente)
            log.info(f"job {job_id}: fase '{siguiente}' encolada")

        # Estado del informe: preliminar mientras quede alguna fase por delante,
        # definitivo cuando ya no hay más. Se publica con debounce (ver
        # publicar.py) para que una tanda no encadene un deploy por job.
        if not siguiente:
            completo, pendiente = True, None
        elif fase == "rapido":
            completo, pendiente = False, (PENDIENTE_TRAS_RAPIDO if hay_enumerar
                                          else PENDIENTE_DIRECTOS)
        else:   # terminó "pasivo", falta el profundo
            completo, pendiente = False, PENDIENTE_TRAS_PASIVO
        marcar_fase(con, informe_id, completo=completo, pendiente=pendiente)
        publicador.publicar(log=log)
    except Exception as e:
        log.error(f"job {job_id} ERROR: {e}")
        cerrar_job(con, job_id, programa_id, "error", str(e)[:500])
    finally:
        con.close()


def vaciar_cola(pool):
    """Procesa todo lo pendiente con el pool acotado. Devuelve cuántos corrió."""
    con = conectar()
    rescatar_colgados(con)
    corridos = 0
    with ThreadPoolExecutor(max_workers=pool) as ex:
        futuros = []
        while True:
            # No tomar más jobs de los que caben en el pool: `tomar_job` los
            # marca en_curso, y encolarlos en el executor los dejaba con ese
            # estado mientras solo esperaban turno. Si el worker moría, se
            # quedaban colgados jobs que ni habían empezado.
            if sum(1 for f in futuros if not f.done()) >= pool:
                time.sleep(2)
                continue
            job = tomar_job(con)
            if job is None:
                # O no queda nada, o lo que queda está bloqueado por el cerrojo
                # de su programa: en ese caso esperamos a que se libere.
                if not any(f.running() for f in futuros):
                    break
                time.sleep(2)
                continue
            futuros.append(ex.submit(procesar, job))
            corridos += 1
    con.close()
    # Al vaciarse la cola, una publicación forzada garantiza que el ÚLTIMO
    # estado salga aunque cayera dentro de la ventana de debounce de su job.
    if corridos:
        publicador.publicar(forzar=True, log=log)
    return corridos


def main():
    ap = argparse.ArgumentParser(description="Worker de recon")
    ap.add_argument("--pool", type=int, default=POOL_DEFECTO)
    ap.add_argument("--daemon", action="store_true", help="quedarse escuchando la cola")
    args = ap.parse_args()

    if args.daemon:
        log.info(f"daemon arrancado (pool={args.pool})")
        while True:
            if not vaciar_cola(args.pool):
                time.sleep(ESPERA_DAEMON)
    else:
        n = vaciar_cola(args.pool)
        log.info(f"{n} job(s) procesados")


if __name__ == "__main__":
    main()
