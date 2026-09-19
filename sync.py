#!/usr/bin/env python3
"""
Sincronización de programas de bug bounty desde bounty-targets-data.
Fuentes: HackerOne, Bugcrowd, Intigriti, YesWeHack, Federacy, GObugfree y
Standoff 365 (las dos últimas, feeds propios; ver PLATAFORMAS_PROPIAS).
"""

import hashlib
import http.cookiejar
import json
import valor_assets
import logging
import re
import socket
import sqlite3
import subprocess
import time
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import respaldo

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH        = str(BASE / "programas.db")
BACKUP_DIR     = BASE / "backup" / "sync"
LOG_PATH       = BASE / "logs" / "sync.log"
NUEVOS_LOG_PATH = BASE / "nuevos_log.txt"
MAX_BACKUPS    = 20

URLS = {
    "hackerone":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/hackerone_data.json",
    "intigriti":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/intigriti_data.json",
    "yeswehack":  "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/yeswehack_data.json",
    "bugcrowd":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/bugcrowd_data.json",
    "federacy":   "https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/main/data/federacy_data.json",
    # GObugfree NO está en bounty-targets-data: su feed lo generamos aquí con
    # `fetch_gobugfree.py` y se lee por file://. Ver PLATAFORMAS_PROPIAS.
    "gobugfree":  f"file://{BASE}/feeds_gobugfree/gobugfree_data.json",
    # Standoff 365 tampoco está en bounty-targets-data: lo genera
    # `fetch_standoff.py` contra su API pública. Ver PLATAFORMAS_PROPIAS.
    "standoff":   f"file://{BASE}/feeds_standoff/standoff_data.json",
}

# Plataformas cuyo feed producimos nosotros en vez de leerlo de la fuente de
# arkadiyt. Se comportan igual para el diff, las alertas y el recon, pero se
# apartan en dos sitios donde confundirlas con la fuente primaria haría daño:
#
#  1. `feed_a_leer` no les busca SHA en la API de GitHub (no hay commit que
#     mirar, y serían dos peticiones tiradas contra un límite de 60/h).
#  2. Su marca de tiempo NO entra en `avisar_fuente_estancada`: esa alarma juzga
#     por el feed MÁS reciente, así que un feed propio —siempre fresco, lo
#     regenera nuestro timer— la dejaría muda justo cuando bounty-targets se
#     para, que es exactamente el fallo de tres días que la motivó.
PLATAFORMAS_PROPIAS = {"gobugfree", "standoff"}

# Estado que deja el fetcher de cada plataforma propia tras un barrido bueno;
# de ahí sale la hora real del dato (no hay commit del que sacarla).
ESTADO_PROPIO = {
    "gobugfree": BASE / "feeds_gobugfree" / "estado.json",
    "standoff":  BASE / "feeds_standoff" / "estado.json",
}

# Ventana esperada entre dos barridos consecutivos, en minutos. Por debajo de
# esto, la antigüedad del evento es tan pequeña que la fecha de detección vale
# como fecha del evento y no hay nada que matizar. Por encima (máquina apagada,
# timer parado), el evento pudo publicarse en cualquier punto del hueco y eso
# hay que decirlo en vez de venderlo como recién salido.
#
# La fuente publica cada ~30 min, a los :04 y los :34 (medido 2026-08-05).
VENTANA_NORMAL_MIN = 75

# Cuánto puede llevar la fuente sin un commit antes de que sea una anomalía y
# no una racha tranquila. Con tandas cada ~30 min, seis horas son doce tandas
# perdidas: ya no es que no pase nada, es que la fuente no está publicando.
# Ver `avisar_fuente_estancada`.
UMBRAL_FUENTE_MIN  = 6 * 60
REAVISO_FUENTE_MIN = 12 * 60      # cada cuánto repetir la alarma, como mucho
FUENTE_STAMP = BASE / ".fuente_estancada.stamp"

# La alarma de arriba solo dice la verdad con la foto completa: juzga por el
# feed MÁS reciente, y el más reciente es siempre HackerOne —la única plataforma
# que commitea cada ~30 min; las demás van a días—. Si falta justo su marca, el
# máximo de las que quedan es de horas atrás y la fuente parece parada estándolo
# nosotros. Cuando eso pasa no se acusa a la fuente: se cuenta la racha aquí y,
# si dura, se avisa de lo que de verdad ocurre (no podemos leer), que es un
# problema distinto con una solución distinta. Ver `avisar_lectura_rota`.
#
# Las dos condiciones son necesarias: el reloj solo no distingue "sin red" de
# "máquina apagada desde anoche" (un único barrido fallido puede arrastrar horas
# de reloj), y los barridos solos no distinguen tres despertares seguidos de un
# corte real.
UMBRAL_LECTURA_MIN   = 2 * 60     # racha mínima de reloj antes de dar la voz
BARRIDOS_LECTURA     = 3          # …y de barridos consecutivos sin poder leer
REAVISO_LECTURA_MIN  = 12 * 60
LECTURA_STAMP = BASE / ".fuente_ilegible.json"

# Cuánto esperar a que haya DNS antes de empezar el barrido. systemd lanza el
# sync al arrancar y al despertar la máquina (`Persistent=true`) antes de que la
# red esté lista: en `logs/sync.log` hay 73 consultas de commit caídas y las 73
# son `Temporary failure in name resolution`, ninguna de GitHub. La unit declara
# `After=network-online.target`, pero esa unidad NO EXISTE en el bus de usuario
# (`systemctl --user show network-online.target` → LoadState=not-found), así que
# no ordena nada y la espera hay que hacerla aquí. Ver `esperar_red`.
ESPERA_RED_MAX_S = 90

CAMPOS_PROTEGIDOS = {
    "notas", "estado_analisis", "score",
    "stack_detectado", "dominios_resueltos", "fecha_primer_recon",
}

# Aviso que se antepone al campo `notas` cuando un programa que ya estaba
# en la BD (pagaba) deja de pagar. No se elimina el registro.
MARCADOR_NO_PAGA = "ha dejado de pagar"


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_PATH),   # fichero persistente
        logging.StreamHandler(),         # también por pantalla
    ],
)
log = logging.getLogger(__name__)


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def hacer_backup():
    """
    Copia la BD a backup/sync/ con timestamp.
    Si ya hay MAX_BACKUPS ficheros, elimina el más antiguo antes de crear el nuevo.

    Se usa la API de backup de SQLite, no `shutil.copy2`: desde que la BD está
    en WAL (2026-08-11, para que el worker deje de morir con "database is
    locked") lo último escrito puede vivir en el fichero `-wal` y no en el
    `.db`. Copiar el `.db` a pelo daría un backup silenciosamente atrasado
    —no corrupto, que es peor: parece bueno—. `backup()` además es consistente
    aunque alguien esté escribiendo mientras se hace.
    """
    backups = sorted(BACKUP_DIR.glob("*.db"))
    while len(backups) >= MAX_BACKUPS:
        eliminado = backups.pop(0)
        eliminado.unlink()
        log.info(f"[backup] eliminado {eliminado.name}")
        backups = sorted(BACKUP_DIR.glob("*.db"))

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    destino   = BACKUP_DIR / f"programas_{timestamp}.db"
    origen = sqlite3.connect(DB_PATH, timeout=60)
    copia  = sqlite3.connect(destino)
    try:
        origen.backup(copia)
    finally:
        copia.close()
        origen.close()
    log.info(f"[backup] creado {destino.name}")


def esperar_red(host="api.github.com", limite=ESPERA_RED_MAX_S):
    """
    Espera hasta `limite` segundos a que se resuelva `host`. Devuelve si hay red.

    No es un adorno: sin esto, el primer barrido tras arrancar o despertar corre
    sin DNS, HackerOne se queda sin SHA (es la primera del bucle y se lleva
    siempre el fallo) y la alarma de fuente estancada juzga con la foto
    incompleta. De los siete avisos emitidos hasta el 2026-08-29, seis salieron
    así —con `hackerone: ?` en el detalle— y en todos ellos el barrido siguiente
    leyó un commit de hacía menos de dos horas: la fuente estaba viva.

    Nunca aborta el barrido: si al agotar la espera sigue sin haber red, se
    sigue igual y cada plataforma decide qué puede leer. No poder mirar ya se
    cuenta aparte, en `avisar_lectura_rota`.
    """
    espera, gastado = 2, 0
    while True:
        try:
            socket.getaddrinfo(host, 443)
            if gastado:
                log.info(f"[red] {host} resuelve tras {gastado}s de espera")
            return True
        except socket.gaierror as e:
            if gastado >= limite:
                log.warning(f"[red] sin resolución de {host} tras {gastado}s ({e}) — "
                            f"se sigue: cada plataforma leerá lo que pueda")
                return False
            time.sleep(espera)
            gastado += espera
            espera = min(espera * 2, 30)


def descargar(url, intentos=3, pausa=20):
    """Descarga y parsea un JSON con hasta `intentos` reintentos cada `pausa` segundos."""
    for intento in range(1, intentos + 1):
        try:
            with urllib.request.urlopen(url, timeout=30) as r:
                return json.load(r)
        except Exception as e:
            if intento < intentos:
                log.warning(f"[descarga] intento {intento}/{intentos} fallido: {e}. Reintentando en {pausa}s...")
                time.sleep(pausa)
            else:
                raise


# Desfase entre el arranque del barrido y la emisión del evento a partir del
# cual conviene decirlo en el log: en un ciclo sano son segundos.
DESFASE_AVISO_MIN = 5


def construir_crono(ts_barrido_anterior, ahora_str):
    """
    Ventana en la que ocurrió el evento: entre el barrido anterior y este.

    No hace falta preguntarle a nadie cuándo cambió el dato en origen. Sabemos
    que en el barrido anterior no estaba y que ahora sí, así que el evento cae
    dentro de esa ventana. Con el sync corriendo a su ritmo la ventana es de
    minutos y la fecha de detección vale como fecha del evento; si hubo un
    hueco (máquina apagada), la ventana es el hueco entero y la antigüedad
    pasa a ser incierta — que es justo lo que hay que decir en vez de callarlo.

    Vale igual para cualquier otra fuente futura (más plataformas, o recon
    propio): toda fuente tiene un barrido anterior y uno actual.
    """
    ventana = minutos_entre(ts_barrido_anterior, ahora_str)
    return {
        "ts_barrido_anterior": ts_barrido_anterior,
        "ts_detectado":        ahora_str,
        "ventana_min":         ventana,
        "fiable":              ventana is not None and ventana <= VENTANA_NORMAL_MIN,
    }


def refrescar_crono(crono):
    """
    Vuelve a sellar la hora del evento en el momento de emitirlo.

    `construir_crono` la fija al ARRANCAR el barrido, y entre ese instante y la
    escritura del informe puede pasar mucho tiempo: basta con que la máquina se
    suspenda por medio. Pasó el 2026-08-18: un barrido arrancó a las 14:46 UTC
    dentro de un despertar de un segundo, la máquina volvió a dormirse seis
    horas y el proceso sobrevivió —los `sleep` entre reintentos no avanzan
    mientras el sistema está suspendido—, así que los dos eventos que detectó a
    las 19:51 se publicaron fechados a las 14:46. Y lo peor no era la fecha:
    con los dos extremos de la ventana congelados antes del parón, salía de 69
    minutos y los daba por FIABLES, cuando la real era de 374 y debían haber
    salido como antigüedad incierta.

    El evento se fecha cuando se detecta, no cuando se empezó a mirar. El
    principio de la ventana no se toca: sigue siendo el barrido anterior, que
    es lo que acota de verdad cuándo pudo ocurrir.
    """
    if not crono:
        return crono
    fresco = construir_crono(crono.get("ts_barrido_anterior"), ahora())
    desfase = minutos_entre(crono.get("ts_detectado"), fresco["ts_detectado"])
    if desfase and desfase >= DESFASE_AVISO_MIN:
        log.warning(
            f"[crono] este barrido lleva {fmt_antiguedad(desfase)} desde que "
            f"arrancó (¿suspensión a mitad?): los eventos se fechan al "
            f"detectarlos ({fresco['ts_detectado']} UTC), no al empezar "
            f"({crono.get('ts_detectado')} UTC)"
        )
    return fresco


def _parse(ts_str):
    """'YYYY-MM-DD HH:MM:SS' (UTC) → datetime aware. None si no se puede."""
    if not ts_str:
        return None
    try:
        return datetime.strptime(ts_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def minutos_entre(ts_ini, ts_fin):
    """Minutos enteros entre dos timestamps UTC. None si falta alguno."""
    a, b = _parse(ts_ini), _parse(ts_fin)
    if a is None or b is None:
        return None
    return int((b - a).total_seconds() // 60)


def fmt_antiguedad(minutos):
    """Minutos → '3 min' / '2 h 5 min' / '1 d 4 h'."""
    if minutos is None:
        return "?"
    if minutos < 0:
        minutos = 0
    if minutos < 60:
        return f"{minutos} min"
    horas, mins = divmod(minutos, 60)
    if horas < 24:
        return f"{horas} h {mins} min" if mins else f"{horas} h"
    dias, horas = divmod(horas, 24)
    return f"{dias} d {horas} h" if horas else f"{dias} d"


# Un programa que sale del feed y vuelve enseguida no es una oportunidad: es
# una plataforma trasteando (Liferay DXP estuvo abierto 6 minutos el 6/8/2026).
# Por debajo de este umbral la vuelta es silenciosa; por encima merece informe.
UMBRAL_REACTIVACION_DIAS = 15

# Por qué se ocultó un informe. Solo se recupera lo ocultado por esto: si algún
# día se despublica algo a mano, la reactivación no debe resucitarlo.
MOTIVO_OCULTO_SUSPENSION = "suspension"
# Informes que nunca debieron existir: sus "assets nuevos" eran el relleno de
# censura de un programa pausado (ver `scope_censurado`). Se ocultan con motivo
# propio y NO con el de suspensión, porque el de suspensión se deshace solo
# cuando el programa reabre y estos no deben volver nunca.
MOTIVO_OCULTO_CENSURA = "scope_censurado"


def dias_entre(desde_str, hasta_str):
    """Días completos entre dos marcas '%Y-%m-%d %H:%M:%S'. None si no se puede."""
    if not desde_str or not hasta_str:
        return None
    try:
        d = datetime.strptime(desde_str, "%Y-%m-%d %H:%M:%S")
        h = datetime.strptime(hasta_str, "%Y-%m-%d %H:%M:%S")
    except (ValueError, TypeError):
        return None
    return max(0, (h - d).days)


def texto_dias(dias):
    """Días tal cual, para el tiempo que un programa estuvo cerrado.

    Aquí no se redondea a meses: "101 días" es el dato, "3 meses" es una
    aproximación que además no coincidiría con lo que muestra la web.
    """
    if dias is None:
        return "un tiempo indeterminado"
    return f"{dias} día{'s' if dias != 1 else ''}"


def texto_periodo(dias):
    """Días → '18 días' / '2 meses' / '1 año'. Para el titular del informe."""
    if dias is None:
        return "un tiempo indeterminado"
    if dias < 60:
        return f"{dias} día{'s' if dias != 1 else ''}"
    if dias < 365:
        meses = dias // 30
        return f"{meses} mes{'es' if meses != 1 else ''}"
    anios = dias // 365
    return f"{anios} año{'s' if anios != 1 else ''}"


# Cuándo nació el programa según la propia plataforma. Un programa que la BD
# no tenía puede llevar años funcionando: solo estaba invisible. Preguntarlo
# cuesta una petición y únicamente se hace cuando algo parece un estreno.
URL_VERSIONES_YWH  = "https://api.yeswehack.com/programs/{}/versions"
URL_DETALLE_INTI   = "https://app.intigriti.com/api/core/public/programs/{}/{}"
URL_GRAPHQL_H1     = "https://hackerone.com/graphql"


def _a_utc(iso):
    """Fecha ISO de cualquier plataforma -> '%Y-%m-%d %H:%M:%S' UTC. None si falla."""
    if not iso:
        return None
    try:
        d = datetime.fromisoformat(str(iso).replace("Z", "+00:00"))
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=timezone.utc)
    return d.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _creacion_yeswehack(slug):
    """La entrada más antigua del historial de versiones es la creación."""
    datos = descargar(URL_VERSIONES_YWH.format(slug), intentos=2, pausa=3)
    items = datos.get("items") if isinstance(datos, dict) else datos
    fechas = [v.get("accepted_at") for v in (items or []) if v.get("accepted_at")]
    return _a_utc(min(fechas)) if fechas else None


def _creacion_hackerone(handle):
    """
    `started_accepting_at`: cuándo empezó a recibir informes, aunque fuera en
    privado. Es la edad real del programa — `launched_at` solo dice cuándo se
    hizo público, y por eso Box BB parecía estrenarse en 2026 llevando desde
    2019. Se coge la más antigua de las dos.

    GraphQL exige un CSRF, pero vale el de una sesión anónima: se saca del HTML
    de la página del programa. No hacen falta credenciales.
    """
    cj = http.cookiejar.CookieJar()
    op = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))
    op.addheaders = [("User-Agent", "Mozilla/5.0")]
    html = op.open(f"https://hackerone.com/{handle}", timeout=30).read().decode("utf-8", "replace")
    m = re.search(r'name="csrf-token"[^>]*content="([^"]+)"', html)
    if not m:
        return None
    consulta = {
        "query": "query($h:String!){ team(handle:$h){ launched_at started_accepting_at } }",
        "variables": {"h": handle},
    }
    req = urllib.request.Request(
        URL_GRAPHQL_H1, data=json.dumps(consulta).encode(),
        headers={"content-type": "application/json", "x-csrf-token": m.group(1),
                 "User-Agent": "Mozilla/5.0"})
    equipo = (json.load(op.open(req, timeout=30)).get("data") or {}).get("team") or {}
    fechas = [f for f in (_a_utc(equipo.get("launched_at")),
                          _a_utc(equipo.get("started_accepting_at"))) if f]
    return min(fechas) if fechas else None


def _creacion_intigriti(program_id, cur):
    """
    Intigriti no publica fecha de creación. Se usan dos señales del detalle:

      - `lastActivity`: el evento más antiguo da una COTA de antigüedad. Solo
        trae los 10 últimos, así que un programa movido da una cota reciente
        y parecería nuevo sin serlo (DigitalOcean daba 2 días).
      - `acceptedSubmissionCount`: un programa que ya ha aceptado informes no
        se está estrenando, diga lo que diga la cota. Esta es la que salva el
        caso anterior.

    Hace falta el par empresa/handle, que la URL del programa ya contiene:
    https://www.intigriti.com/programs/<empresa>/<handle>/detail
    """
    fila = cur.execute("SELECT url FROM programas WHERE plataforma='intigriti' "
                       "AND plataforma_id=?", (program_id,)).fetchone()
    if not fila or not fila[0]:
        return None, None
    partes = [p for p in fila[0].split("/") if p]
    if len(partes) < 3:
        return None, None
    empresa, handle = partes[-3], partes[-2]
    datos = descargar(URL_DETALLE_INTI.format(empresa, handle), intentos=2, pausa=3)
    veterano = (datos.get("acceptedSubmissionCount") or 0) > 0
    marcas = [e.get("timestamp") for e in (datos.get("lastActivity") or []) if e.get("timestamp")]
    cota = (datetime.fromtimestamp(min(marcas), timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
            if marcas else None)
    return cota, veterano


def _creacion_por_historico(plataforma, plataforma_id):
    """
    Edad de un programa cuya plataforma no publica ninguna fecha.

    Le pasa a Bugcrowd (su feed son siete campos y ninguno es una fecha,
    verificado 2026-08-11) y a Federacy (cinco campos, tampoco). Ninguna de las
    dos tiene API pública que responda por ello.

    Lo que sí hay es el histórico del propio repo de la fuente, que es una foto
    del feed cada media hora desde hace años. Si el programa ya estaba listado
    hace un mes, no se está estrenando hoy — y eso es todo lo que
    `es_estreno_real` necesita, porque su umbral son 15 días. Devuelve una COTA
    (no la fecha real de creación): "al menos desde".

    Una sola consulta en el caso normal. Si no estaba hace un mes se prueban
    puntos más lejanos por si el feed tuvo un hueco; si tampoco, se da por
    estreno, que es el comportamiento conservador de siempre (mejor un falso
    "nuevo" que perder el aviso).
    """
    ahora_dt = datetime.now(timezone.utc).replace(tzinfo=None)
    for meses in BUSQUEDA_MESES_ATRAS:
        cand = ahora_dt - timedelta(days=30 * meses)
        if _estaba_en_feed(cand, plataforma, plataforma_id):
            return cand.strftime("%Y-%m-%d %H:%M:%S")
    return None


def _creacion_standoff(slug):
    """
    Standoff publica `publishedAt` por programa y `fetch_standoff.py` lo guarda
    en el feed, así que la edad se lee del fichero local: cero peticiones,
    frente a la consulta remota que cuesta en YesWeHack, HackerOne e Intigriti.
    """
    try:
        feed = json.loads(Path(URLS["standoff"][len("file://"):]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    for p in feed:
        if p.get("slug") == slug:
            return _a_utc(p.get("published_at"))
    return None


def fecha_creacion_plataforma(plataforma, plataforma_id, cur=None):
    """
    Devuelve (fecha, veterano):

      fecha    — desde cuándo existe el programa ('%Y-%m-%d %H:%M:%S' UTC), o
                 una cota inferior. None si no se puede averiguar.
      veterano — True si consta que ya recibía informes, independientemente de
                 la fecha. None cuando la plataforma no da esa señal.

    Si no se puede averiguar nada se mantiene el comportamiento de siempre:
    darlo por nuevo. Preferimos un falso "nuevo" a perder el aviso.
    """
    try:
        if plataforma == "yeswehack":
            return _creacion_yeswehack(plataforma_id), None
        if plataforma == "hackerone":
            return _creacion_hackerone(plataforma_id), None
        if plataforma == "standoff":
            return _creacion_standoff(plataforma_id), None
        if plataforma == "intigriti" and cur is not None:
            return _creacion_intigriti(plataforma_id, cur)
        # Sin fecha en el feed: la edad sale del histórico del repo de la fuente.
        if plataforma in ("bugcrowd", "federacy"):
            return _creacion_por_historico(plataforma, plataforma_id), None
    except Exception as e:
        log.warning(f"[novedad] no se pudo consultar la edad de "
                    f"{plataforma}/{plataforma_id}: {e}")
    return None, None


# Histórico del propio feed: cada commit del repo es una foto de qué programas
# estaban listados. Con eso se averigua cuándo dejó de aparecer uno, que es lo
# que ninguna plataforma publica (registran las altas, no las bajas).
API_COMMITS = ("https://api.github.com/repos/arkadiyt/bounty-targets-data/commits"
               "?path=data/{plat}_data.json&until={fecha}Z&per_page=1")
# El mismo listado sin `until`: el último commit que tocó ese feed. Sirve para
# leer el feed POR SHA en vez de por `main` — medido el 2026-08-10, `main` sirve
# contenido cacheado y llegó a ir una tanda (~1 h) por detrás del último commit,
# lo que nos hizo ver a Sqills abierto cuando ya se había cerrado.
API_ULTIMO_COMMIT = ("https://api.github.com/repos/arkadiyt/bounty-targets-data/commits"
                     "?path=data/{plat}_data.json&per_page=1")
RAW_COMMIT  = ("https://raw.githubusercontent.com/arkadiyt/bounty-targets-data/"
               "{sha}/data/{plat}_data.json")
# Cómo sacar de una entrada del feed el mismo identificador que guardamos en
# `plataforma_id`. Casi siempre es un campo suelto; Bugcrowd no publica ninguno
# (ni id ni handle), así que su identidad se deriva de la URL y hace falta una
# función. Un str se lee como nombre de campo; un callable se aplica a la entrada.
CLAVE_FEED  = {"hackerone": "handle", "intigriti": "id", "yeswehack": "id",
               "bugcrowd": lambda p: slug_bugcrowd(p.get("url")),
               "federacy": "id",
               "gobugfree": "slug",
               "standoff": "slug"}

# Hasta dónde mirar atrás y cuánto afinar. Cada paso son dos peticiones y una
# descarga del feed entero — barato en YesWeHack (131 KB), caro en HackerOne
# (17,8 MB), así que la búsqueda se limita y solo corre cuando hace falta.
BUSQUEDA_MESES_ATRAS = [1, 3, 6, 12, 18]
BUSQUEDA_MAX_PASOS   = 10


def feed_a_leer(plataforma):
    """
    De dónde leer el feed de esta plataforma: (url, sha, ts_commit, fallo).

    `fallo` es None cuando la marca de tiempo es de fiar, y el motivo (texto)
    cuando no se pudo consultar el commit. Distinguir "no hay nada nuevo" de
    "no he podido mirar" es lo único que separa una alarma de fuente estancada
    de una de red rota, y sin este cuarto valor las dos llegaban como un None
    indistinguible. Ver `avisar_fuente_estancada`.

    Por SHA el contenido es inmutable y sabemos EXACTAMENTE de qué foto viene,
    con su hora real. Por `main` hay caché y la hora del dato es una incógnita:
    lo único que sabemos es cuándo lo descargamos nosotros.

    Cuesta una petición más a la API de GitHub por plataforma y barrido (3 cada
    30 min, contra un límite de 60/h sin token). Si falla —rate limit, caída—,
    se cae a `main`: ir con retraso es peor que no sincronizar.

    Con el MODO RESPALDO activo (la fuente lleva horas sin publicar, ver
    `respaldo.py`) se lee el feed que hemos generado aquí en vez del de GitHub.
    Es el único punto del sync que se entera: el formato del fichero es el mismo
    porque lo produce el mismo crawler, así que el resto del barrido —diff,
    alertas, informes, recon— no distingue el origen. También ahorra las 4
    consultas de SHA, que no dicen nada mientras el repo está congelado.
    """
    # Feed propio (GObugfree): ni hay commit que consultar ni modo respaldo que
    # aplicar — la fuente somos nosotros. La hora del dato es la del barrido que
    # lo generó, que es lo honesto: fechar el evento cuando lo vimos.
    if plataforma in PLATAFORMAS_PROPIAS:
        ts_propio = None
        try:
            ts_propio = json.loads(
                ESTADO_PROPIO[plataforma].read_text(encoding="utf-8")).get("generado_en")
        except (OSError, KeyError, json.JSONDecodeError, AttributeError):
            log.warning(f"[{plataforma}] sin estado del feed propio; se lee sin marca de tiempo")
        return URLS[plataforma], None, ts_propio, None

    local = respaldo.feed_local(plataforma)
    if local:
        # `urlopen` entiende file:// de serie, así que `descargar()` no cambia.
        # El ts NO es el de un commit —no hay— sino el de nuestra generación:
        # datar el evento con la hora en que lo vimos es lo honesto, y así un
        # informe no dice "hace 5 minutos" sobre algo que no sabemos cuándo pasó.
        ts_local = respaldo.leer_estado().get("generado_en")
        return f"file://{local}", None, ts_local, None

    # El SHA es un ACCESORIO: sirve para leer una foto inmutable y con hora
    # conocida en vez de `main` con caché. Que la API no conteste no puede
    # tumbar el barrido — y lo tumbaba: esta llamada estaba desnuda y quedaba
    # fuera del try/except que protege la descarga del feed, así que la caída de
    # api.github.com del 2026-08-17 (incidente suyo: 504 en /repos/*, 429 en
    # raw) abortaba `sincronizar()` con traceback en la PRIMERA plataforma. Con
    # el fallo capturado se cae al camino que ya existía para el rate limit:
    # leer `main` sin SHA.
    try:
        commits = descargar(API_ULTIMO_COMMIT.format(plat=plataforma), intentos=2, pausa=5)
    except Exception as e:
        log.warning(f"[{plataforma}] no se pudo consultar el commit ({e}), se lee main (con caché)")
        return URLS[plataforma], None, None, str(e) or e.__class__.__name__
    # Pasado el límite, GitHub responde un objeto con `message`, no una lista;
    # indexarlo reventaría el barrido entero por un dato accesorio.
    if not isinstance(commits, list) or not commits:
        log.warning(f"[{plataforma}] sin SHA del feed, se lee main (con caché)")
        return URLS[plataforma], None, None, "sin SHA (¿límite de la API?)"
    try:
        sha = commits[0]["sha"]
        iso = commits[0]["commit"]["committer"]["date"]    # '2026-08-10T09:34:15Z'
    except (KeyError, TypeError, IndexError) as e:
        log.warning(f"[{plataforma}] respuesta de commits inesperada ({e}), se lee main")
        return URLS[plataforma], None, None, f"respuesta inesperada ({e})"
    return (RAW_COMMIT.format(sha=sha, plat=plataforma), sha,
            iso.replace("T", " ").replace("Z", ""), None)


def registrar_estado(cur, programa_id, estado, motivo, fecha, ts_feed=None):
    """
    Anota una transición abierto/cerrado en `programa_estado`.

    Una fila por transición, nunca se pisa: es lo que permite ver que un
    programa abre y cierra en ciclos cortos, cosa que `ultima_suspension` (un
    solo valor) no puede contar. `ts_feed` es la hora del commit del feed —la
    buena para medir cuánto duró una ventana—; `fecha` es cuándo lo vimos.
    """
    if not programa_id:
        return
    cur.execute(
        "INSERT INTO programa_estado (programa_id, estado, motivo, fecha, ts_feed) "
        "VALUES (?,?,?,?,?)",
        (programa_id, 1 if estado else 0, motivo, fecha, ts_feed),
    )


def _estaba_en_feed(fecha, plataforma, plataforma_id):
    """¿El programa aparecía en el feed en esa fecha? None si no se puede saber."""
    commits = descargar(
        API_COMMITS.format(plat=plataforma, fecha=fecha.strftime("%Y-%m-%dT%H:%M:%S")),
        intentos=2, pausa=5)
    if not commits:
        return None
    datos = descargar(RAW_COMMIT.format(sha=commits[0]["sha"], plat=plataforma),
                      intentos=2, pausa=5)
    clave = CLAVE_FEED[plataforma]
    leer = clave if callable(clave) else (lambda p: p.get(clave))
    return any(str(leer(p)) == str(plataforma_id) for p in datos)


def ultima_vez_en_feed(plataforma, plataforma_id, ahora_str):
    """
    Cuándo se vio por última vez el programa en el feed antes de reaparecer.

    Bisección sobre el histórico del repo. Si el programa entró y salió varias
    veces, encuentra una de las transiciones, no necesariamente la última: es
    una aproximación buena, no una certeza. None si no se puede acotar.
    """
    if plataforma not in CLAVE_FEED:
        return None
    ahora_dt = _parse(ahora_str) or datetime.now(timezone.utc)
    ahora_dt = ahora_dt.replace(tzinfo=None)

    # Un punto del pasado en el que sí estaba; sin él no hay nada que biseccionar.
    desde = None
    for meses in BUSQUEDA_MESES_ATRAS:
        cand = ahora_dt - timedelta(days=30 * meses)
        if _estaba_en_feed(cand, plataforma, plataforma_id):
            desde = cand
            break
    if desde is None:
        return None

    hasta = ahora_dt - timedelta(hours=1)   # antes de la reaparición de ahora
    for _ in range(BUSQUEDA_MAX_PASOS):
        if (hasta - desde) < timedelta(hours=12):
            break
        medio = desde + (hasta - desde) / 2
        if _estaba_en_feed(medio, plataforma, plataforma_id):
            desde = medio
        else:
            hasta = medio
    return desde.strftime("%Y-%m-%d %H:%M:%S")


def es_estreno_real(plataforma, plataforma_id, ahora_str, cur=None):
    """
    ¿Un programa que la BD no tenía es realmente nuevo?

    Devuelve (es_nuevo, creado_en, dias). No es un estreno si la plataforma
    dice que lleva existiendo más de UMBRAL_REACTIVACION_DIAS, o si consta que
    ya había aceptado informes — esto último manda sobre la fecha, porque en
    Intigriti la antigüedad es solo una cota y se queda corta con los
    programas movidos.
    """
    creado, veterano = fecha_creacion_plataforma(plataforma, plataforma_id, cur)
    dias = dias_entre(creado, ahora_str) if creado else None
    if veterano:
        return False, creado, dias
    if not creado:
        return True, None, None
    if dias is not None and dias > UMBRAL_REACTIVACION_DIAS:
        return False, creado, dias
    return True, creado, dias


def ultimo_sync(cur):
    """
    Cuándo corrió el sync anterior (máximo `fecha_actualizacion` de la tabla).

    Se lee ANTES de tocar nada: con él sabemos si ha habido un hueco entre
    ejecuciones y, por tanto, si la latencia calculada es exacta o una cota.
    """
    cur.execute("SELECT MAX(fecha_actualizacion) FROM programas")
    fila = cur.fetchone()
    return fila[0] if fila else None


def hash_scope(scope_in, scope_out):
    contenido = json.dumps(scope_in, sort_keys=True) + json.dumps(scope_out, sort_keys=True)
    return hashlib.sha256(contenido.encode()).hexdigest()


# Bugcrowd tapa TODO el scope de un programa con bloques (U+2588) del mismo
# largo que el target original cuando lo PAUSA. No hay ningún campo que lo
# diga: su API de engagements devuelve `accessStatus: "open"` e
# `isPrivate: false` para los 260 programas, censurados incluidos. El scope
# tapado ES la señal.
#
# Verificado el 2026-08-22 contra su API de anuncios
# (`/engagements/<slug>/announcements.json`): de los 13 programas con el scope
# así que siguen listados, 9 tienen "Testing paused" como último anuncio y
# lululemon "[lululemon] Temporarily Pausing Bug Bounty", publicado
# 2026-08-21T22:40Z — 27 minutos antes de que este sistema creara el informe
# falso "lululemon — 6 objetivos nuevos en el alcance" (informe 66) con los
# bloques como assets. Un programa pausado prohíbe expresamente seguir
# probando: ni informe, ni recon, ni aparecer en la web.
CARACTERES_CENSURA = "\u2588\u2591\u2592\u2593"


def censurado(identificador):
    """¿Este identificador de asset es puro relleno de censura?"""
    txt = (identificador or "").strip()
    return bool(txt) and all(c in CARACTERES_CENSURA for c in txt)


def identificador_asset(item):
    """El id de un asset, sea cual sea la plataforma que lo publica."""
    return item.get("endpoint") or item.get("asset_identifier") or item.get("target")


def scope_censurado(scope_in):
    """
    ¿La plataforma ha tapado el scope entero? Es su forma de decir que el
    programa está pausado (ver CARACTERES_CENSURA).

    Se exige que TODOS los assets estén tapados, no alguno: medido el
    2026-08-22 sobre los 17 programas de Bugcrowd afectados, la censura es
    siempre total (8 de 8, 59 de 59, 13 de 13...). Un solo asset tapado en un
    scope por lo demás legible sería otra cosa y no debe cerrar el programa.
    """
    ids = [identificador_asset(it) for it in (scope_in or [])]
    ids = [i for i in ids if i]
    return bool(ids) and all(censurado(i) for i in ids)


def scope_censurado_json(scope_raw_json):
    """Igual que `scope_censurado`, pero sobre el JSON tal como se guarda."""
    try:
        return scope_censurado(json.loads(scope_raw_json) if scope_raw_json else [])
    except (TypeError, json.JSONDecodeError):
        return False


def elegible_bounty(item):
    """
    ¿Este asset del scope paga bounty?

    Dos plataformas lo publican por asset y hay que mirar las dos:
      - HackerOne, en `eligible_for_bounty` (booleano).
      - Intigriti, en `impact`: el valor `"No Bounty"` marca los objetivos que
        acepta pero NO paga. Sigue estando EN SCOPE —se puede reportar— pero no
        es la noticia que este sistema persigue, así que no dispara alerta ni
        informe. Medido el 2026-08-19: 80 assets así en 23 de sus 73 programas
        (`gammacademy.be` en Intergamma, entre otros). Hasta esa fecha aquí se
        afirmaba que Intigriti "no lo expone", lo cual es falso y es lo que
        mantuvo el campo invisible.

    YesWeHack, Bugcrowd, Federacy y GObugfree no publican el dato (comprobadas
    las claves de sus assets), así que allí todo cuenta: la ausencia del dato no
    es lo mismo que un "false" explícito.
    """
    if str(item.get("impact") or "").strip().lower() == "no bounty":
        return False
    return item.get("eligible_for_bounty") is not False


def ids_scope(scope_raw_json, solo_bounty=False):
    """
    Devuelve el conjunto de identificadores de assets de un scope_raw (JSON).

    Con solo_bounty=True se descartan los assets marcados explícitamente como
    no elegibles para bounty.

    Los assets censurados (`██████`) nunca entran: no son un objetivo, son un
    hueco. Se filtran aquí, en el único sitio del que salen los "assets
    nuevos", para que no puedan acabar ni en un informe ni en la cola de recon.
    """
    try:
        items = json.loads(scope_raw_json) if scope_raw_json else []
    except (TypeError, json.JSONDecodeError):
        return set()
    ids = set()
    for it in items:
        if solo_bounty and not elegible_bounty(it):
            continue
        val = identificador_asset(it)
        if val and not censurado(val):
            ids.add(val)
    return ids


# Tipos de asset que son apps móviles → etiqueta de plataforma. SOLO las apps
# se etiquetan: un dominio o una URL se explican solos, pero dos apps comparten
# a veces el mismo identificador (com.x.y en Google Play Y en App Store) y sin
# la plataforma se ven como un duplicado en el informe.
_PLATAFORMA_APP = {
    "google_play_app_id": "Android", "other_apk": "Android",
    "android": "Android", "mobile-application-android": "Android",
    "apple_store_app_id": "iOS", "other_ipa": "iOS", "testflight": "iOS",
    "ios": "iOS", "mobile-application-ios": "iOS",
}


def etiquetar_assets(assets, scope_raw_in):
    """
    Prepara los assets del evento para mostrarse: recorta espacios sobrantes
    (basura frecuente en el scope de HackerOne) y, si el asset es una app móvil,
    le añade su plataforma para poder distinguir Android de iOS cuando comparten
    el mismo identificador. El resto de assets se dejan tal cual.

    Se hace aquí, en la presentación, no en la detección: el diff sigue
    comparando identificadores crudos, así que no cambia qué se considera nuevo.
    """
    try:
        items = json.loads(scope_raw_in) if scope_raw_in else []
    except (TypeError, json.JSONDecodeError):
        items = []
    tipo_por_id = {}
    for it in items:
        ident = it.get("asset_identifier") or it.get("endpoint") or it.get("target")
        if ident:
            tipo_por_id[ident] = (it.get("asset_type") or it.get("type") or "").lower()
    out = []
    for a in assets:
        plat = _PLATAFORMA_APP.get(tipo_por_id.get(a, ""))
        limpio = a.strip()
        out.append(f"{limpio} — {plat}" if plat else limpio)
    return out


def inferir_scope(scope_in, scope_out):
    tipos = set()
    tiene_api = None
    tiene_android = None
    tiene_ios = None

    for item in scope_in:
        # HackerOne usa asset_type, Intigriti y YesWeHack usan type
        tipo = (item.get("asset_type") or item.get("type") or "").lower()
        endpoint = (item.get("asset_identifier") or item.get("endpoint") or item.get("target") or "").lower()

        if tipo:
            tipos.add(tipo)

        if tipo in ("api",) or "api" in endpoint:
            tiene_api = 1
        if tipo in ("google_play_app_id", "android"):
            tiene_android = 1
        if tipo in ("apple_store_app_id", "ios"):
            tiene_ios = 1

    return {
        "num_scope_in":  len(scope_in),
        "num_scope_out": len(scope_out),
        "scope_tipos":   ",".join(sorted(tipos)) if tipos else None,
        "tiene_api":     tiene_api,
        "tiene_android": tiene_android,
        "tiene_ios":     tiene_ios,
    }


def calcular_actividad(p):
    """
    Escala 0-5 de receptividad del programa, a partir de lo que publica el feed.

    Un programa recién lanzado llega con `response_efficiency_percentage: 100` y
    `average_time_to_first_program_response: 0.0`, que NO significan "responde
    perfecto y al instante": significan que aún no ha recibido un solo informe
    al que responder. Sin el corte de abajo, la fórmula le daba un 5 —la nota
    máxima, empatado con los que llevan años respondiendo bien— justo en el
    informe de estreno, que es el que más se lee. Caso que lo destapó: Vercel
    Sandbox, lanzado el 2026-08-18 y publicado ese mismo día con actividad 5,
    con los tres tiempos vacíos (`bounty_awarded` y `report_resolved` a None).
    Sin datos se devuelve None: un hueco no es una nota.
    """
    efficiency = p.get("response_efficiency_percentage")
    avg_first   = p.get("average_time_to_first_program_response")

    if efficiency is None:
        return None

    sin_historial = (
        (avg_first is None or avg_first == 0)
        and p.get("average_time_to_bounty_awarded") is None
        and p.get("average_time_to_report_resolved") is None
    )
    if sin_historial:
        return None

    if efficiency >= 90 and avg_first is not None and avg_first < 48:
        return 5
    if efficiency >= 70:
        return 4
    if efficiency >= 50:
        return 3
    if efficiency >= 25:
        return 2
    if efficiency > 0:
        return 1
    return 0


# ── Parsers por plataforma ────────────────────────────────────────────────────

def parsear_hackerone(p):
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    return {
        "plataforma":    "hackerone",
        "plataforma_id": p["handle"],
        "handle":        p["handle"],
        "nombre":        p.get("name"),
        "url":           p.get("url"),
        "website":       p.get("website"),
        "activo":        1 if p.get("submission_state") == "open" else 0,
        "disabled":      None,
        "managed":       1 if p.get("managed_program") else 0,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    None,
        "max_bounty":    None,
        "offers_bounties": 1 if p.get("offers_bounties") else 0,
        "actividad":     calcular_actividad(p),
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def parsear_intigriti(p):
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    min_b = p.get("min_bounty") or {}
    max_b = p.get("max_bounty") or {}
    max_val = max_b.get("value") or 0

    return {
        "plataforma":    "intigriti",
        "plataforma_id": p["id"],
        "handle":        p.get("handle"),
        "nombre":        p.get("name"),
        "url":           p.get("url"),
        "website":       None,
        "activo":        1 if p.get("status") == "open" else 0,
        "disabled":      None,
        "managed":       None,
        "tac_required":  1 if p.get("tacRequired") else 0,
        "two_factor_required": 1 if p.get("twoFactorRequired") else 0,
        "min_bounty":    min_b.get("value"),
        "max_bounty":    max_val or None,
        # Intigriti es la única que declara la moneda en el feed; se respeta la
        # suya en vez de suponerla por plataforma.
        "moneda":        (max_b.get("currency") or min_b.get("currency")) if max_val else None,
        "offers_bounties": 1 if max_val > 0 else 0,
        "actividad":     None,
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def parsear_yeswehack(p):
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    max_val = p.get("max_bounty") or 0

    return {
        "plataforma":    "yeswehack",
        "plataforma_id": p["id"],
        "handle":        p["id"],
        "nombre":        p.get("name"),
        "url":           f"https://yeswehack.com/programs/{p['id']}",
        "website":       None,
        "activo":        0 if p.get("disabled") else 1,
        "disabled":      1 if p.get("disabled") else 0,
        "managed":       1 if p.get("managed") else None,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    p.get("min_bounty"),
        "max_bounty":    max_val or None,
        "offers_bounties": 1 if max_val > 0 else 0,
        "actividad":     None,
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def slug_bugcrowd(url):
    """
    Identidad de un programa de Bugcrowd: el slug de su URL de engagement
    (https://bugcrowd.com/engagements/<slug>). El feed no publica ningún id ni
    handle propio, y el nombre no sirve como clave. Verificado el 2026-08-10:
    los 242 slugs del feed son únicos.
    """
    if not url:
        return None
    return url.rstrip("/").rsplit("/", 1)[-1] or None


def parsear_bugcrowd(p):
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    max_val = p.get("max_payout") or 0
    slug    = slug_bugcrowd(p.get("url"))

    return {
        "plataforma":    "bugcrowd",
        "plataforma_id": slug,
        "handle":        slug,
        "nombre":        (p.get("name") or "").strip() or None,
        "url":           p.get("url"),
        "website":       None,
        # El feed no trae estado de apertura en ningún campo, pero SÍ lo dice
        # tapando el scope entero con bloques cuando pausa el programa (ver
        # `scope_censurado`). Un programa pausado prohíbe seguir probando, así
        # que entra aquí como cerrado y el resto —ocultar sus informes, sacarlo
        # de la web, restaurarlo cuando vuelva— lo hace ya `upsert()`. Cuando
        # además desaparece del feed, de eso se encarga marcar_inactivos().
        "activo":        0 if scope_censurado(scope_in) else 1,
        "disabled":      None,
        "managed":       1 if p.get("managed_by_bugcrowd") else None,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    None,       # Bugcrowd solo publica el techo
        "max_bounty":    max_val or None,
        "offers_bounties": 1 if max_val > 0 else 0,
        "actividad":     None,
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def parsear_federacy(p):
    """
    Federacy es la más escueta de las cinco: `id`, `name`, `offers_awards`,
    `url` y los targets. Ni importes, ni fechas, ni estado de apertura.

    LO QUE LA HACE DISTINTA: **no publica cuánto paga**. Las otras cuatro traen
    `max_bounty` (o `max_payout`) y de ahí sale el filtro de "solo pagadores"
    de esta BD. Aquí lo único que hay es el booleano `offers_awards`, así que
    ese booleano ES el filtro: 7 de sus 35 programas lo tienen a true
    (verificado 2026-08-15). `min_bounty` y `max_bounty` quedan a None, que es
    lo honesto — no sabemos el importe, y poner 0 se leería como "no paga".

    Consecuencia a tener presente: sus programas no se pueden ordenar ni
    comparar por recompensa, y la ficha de la web no mostrará esa fila.
    """
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    return {
        "plataforma":    "federacy",
        "plataforma_id": p["id"],                       # UUID, estable
        # El slug de la URL es lo legible (`angellist-vdp`); el UUID no dice
        # nada a quien lea la BD a mano.
        "handle":        (p.get("url") or "").rstrip("/").rsplit("/", 1)[-1] or None,
        "nombre":        (p.get("name") or "").strip() or None,
        "url":           p.get("url"),
        "website":       None,
        # Su feed no trae estado de apertura: si está listado, está abierto.
        # Cuando se cierra desaparece, y de eso ya se encarga marcar_inactivos().
        "activo":        1,
        "disabled":      None,
        "managed":       None,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    None,       # Federacy no publica importes
        "max_bounty":    None,
        "offers_bounties": 1 if p.get("offers_awards") else 0,
        "actividad":     None,
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def parsear_gobugfree(p):
    """
    GObugfree (Suiza) — la sexta plataforma, y la única que NO viene de
    bounty-targets-data: su feed lo genera `fetch_gobugfree.py` scrapeando la
    web pública. Ver ahí el detalle de qué publica y qué no.

    Particularidades frente a las otras cinco:

    - **`offers_bounties` sale de la estructura de la página**, no de un campo:
      un programa que paga tiene tabla "Bounty Levels" y uno que no, no la
      tiene. De los 24 programas, 8 pagan (verificado 2026-08-16).
    - **Los importes son bandas por severidad** (`Critical: CHF 2000-10000`),
      así que `min_bounty` es el suelo de la banda más baja y `max_bounty` el
      techo de la más alta. Son francos suizos, no euros ni dólares: la BD no
      guarda moneda, y compararlos con el resto sin tenerlo presente induce a
      error (1 CHF ≈ 1,07 € a fecha de hoy).
    - **`scope_raw_out` va siempre vacío**: la plataforma no publica
      out-of-scope estructurado. No es que no lo parseemos, es que no está.
    - El slug de la URL es la identidad (`threema`, `swissb`): es estable,
      legible y único, así que hace de `plataforma_id` y de `handle`.
    """
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    return {
        "plataforma":    "gobugfree",
        "plataforma_id": p["slug"],
        "handle":        p["slug"],
        "nombre":        (p.get("name") or "").strip() or None,
        "url":           p.get("url"),
        "website":       None,
        # Si está listado, está abierto; cuando se cierra desaparece del índice
        # y de eso ya se encarga marcar_inactivos().
        "activo":        1,
        "disabled":      None,
        "managed":       None,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    p.get("min_bounty"),
        "max_bounty":    p.get("max_bounty"),
        "offers_bounties": 1 if p.get("offers_bounties") else 0,
        "actividad":     None,
        # Qué hace falta para ver este programa: `abierto`, `verificacion`,
        # `login` o `invitacion` (ver `fetch_gobugfree._nivel_acceso`). Es la
        # primera plataforma que aporta el dato — las cinco de la fuente de
        # arkadiyt solo publican programas abiertos, así que ahí queda a NULL.
        "acceso":        p.get("acceso"),
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


def parsear_standoff(p):
    """
    Standoff 365 (Rusia) — séptima plataforma, y la segunda con feed propio:
    lo genera `fetch_standoff.py` contra su API pública. Ver ahí qué publica la
    fuente y qué no.

    Particularidades frente a las seis anteriores:

    - **Todos los del feed pagan**: `fetch_standoff` solo emite programas
      `published` + `public`, y en esta plataforma no hay programa público sin
      recompensa declarada. `offers_bounties` viene resuelto del fetcher.
    - **Los importes son RUBLOS**, sellados por `MONEDA_PLATAFORMA`. Son
      cifras de 5-7 dígitos (hasta 3.600.000 RUB) y compararlas de memoria con
      un techo en euros induce a error: ~1 RUB ≈ 0,011 € a fecha de hoy.
    - **Trae la fecha de publicación en el propio feed** (`published_at`), cosa
      que ninguna otra plataforma propia da. Con ella `es_estreno_real`
      distingue un estreno de una reaparición sin gastar una petición.
    - **`scope_raw_out` va siempre vacío**: la plataforma no tiene campo de
      out-of-scope. Como en GObugfree, no es que no lo parseemos: no está.
    - El slug de la URL es la identidad (`wildberries`, `dzen_vk`): estable,
      legible y único, así que hace de `plataforma_id` y de `handle`.
    """
    scope_in  = p["targets"]["in_scope"]
    scope_out = p["targets"]["out_of_scope"]
    scope     = inferir_scope(scope_in, scope_out)

    return {
        "plataforma":    "standoff",
        "plataforma_id": p["slug"],
        "handle":        p["slug"],
        "nombre":        (p.get("name") or "").strip() or None,
        "url":           p.get("url"),
        "website":       None,
        "activo":        1,
        "disabled":      None,
        "managed":       None,
        "tac_required":  None,
        "two_factor_required": None,
        "min_bounty":    p.get("min_bounty"),
        "max_bounty":    p.get("max_bounty"),
        "offers_bounties": 1 if p.get("offers_bounties") else 0,
        "actividad":     None,
        # Solo llegan aquí los `visibility=public`: cualquiera los ve sin que
        # nadie tenga que admitirle. Los `with_confirmation` no salen del
        # fetcher, así que este campo nunca vale otra cosa.
        "acceso":        "abierto",
        "scope_raw_in":  json.dumps(scope_in),
        "scope_raw_out": json.dumps(scope_out),
        "hash_scope":    hash_scope(scope_in, scope_out),
        **scope,
    }


PARSERS = {
    "hackerone": parsear_hackerone,
    "intigriti": parsear_intigriti,
    "yeswehack": parsear_yeswehack,
    "bugcrowd":  parsear_bugcrowd,
    "federacy":  parsear_federacy,
    "gobugfree": parsear_gobugfree,
    "standoff":  parsear_standoff,
}

# Campos que otra fuente puede rellenar mejor que el feed: si el feed no trae
# valor, se conserva el guardado en vez de escribir NULL encima (ver `upsert`).
CAMPOS_ENRIQUECIDOS = ("min_bounty", "max_bounty", "moneda")

# Todo lo que se deriva del scope publicado. Se congela en bloque cuando el
# feed llega censurado, para no cambiar unos campos y otros no.
CAMPOS_SCOPE = (
    "scope_raw_in", "scope_raw_out", "hash_scope", "num_scope_in",
    "num_scope_out", "scope_tipos", "tiene_api", "tiene_android", "tiene_ios",
)

CAMPOS_SYNC = [
    "handle", "nombre", "url", "website", "activo", "disabled", "managed",
    "tac_required", "two_factor_required", "min_bounty", "max_bounty",
    "offers_bounties", "actividad", "num_scope_in", "num_scope_out",
    "scope_tipos", "scope_raw_in", "scope_raw_out", "tiene_api",
    "tiene_android", "tiene_ios", "fecha_actualizacion", "hash_scope",
    "acceso", "moneda",
]

# Moneda de cada plataforma, VERIFICADA una por una el 2026-08-18 (no supuesta):
#   bugcrowd  → USD  (su web muestra "$4500" en un engagement real)
#   intigriti → la trae su propio feed en `max_bounty.currency` ("EUR")
#   yeswehack → EUR  (su web muestra "€6,000" donde el feed dice 6000)
#   gobugfree → CHF  (su web muestra "CHF 2600")
#   hackerone y federacy no publican importe: su `max_bounty` es siempre None,
#   así que no tienen moneda que declarar.
#   standoff  → RUB  (su API publica `statistics.rewards.rub`; no hay otra
#                      divisa en los 220 programas del catálogo)
MONEDA_PLATAFORMA = {
    "bugcrowd":  "USD",
    "yeswehack": "EUR",
    "gobugfree": "CHF",
    "standoff":  "RUB",
}


def upsert(cur, registro, ahora_str, ts_feed=None):
    plataforma    = registro["plataforma"]
    plataforma_id = registro["plataforma_id"]
    nuevo_hash    = registro["hash_scope"]

    cur.execute(
        "SELECT id, hash_scope, activo, ultima_suspension "
        "FROM programas WHERE plataforma=? AND plataforma_id=?",
        (plataforma, plataforma_id),
    )
    fila = cur.fetchone()

    registro["fecha_actualizacion"] = ahora_str

    if fila is None:
        # Registro nuevo: todo su scope es "nuevo" por definición.
        campos = list(registro.keys())
        valores = [registro[c] for c in campos]
        placeholders = ",".join("?" * len(campos))
        cur.execute(
            f"INSERT INTO programas ({','.join(campos)}) VALUES ({placeholders})",
            valores,
        )
        # Punto de partida del histórico de este programa.
        registrar_estado(cur, cur.lastrowid, registro.get("activo"), "alta",
                         ahora_str, ts_feed)
        todos  = ids_scope(registro["scope_raw_in"])
        bounty = ids_scope(registro["scope_raw_in"], solo_bounty=True)
        return {
            "estado": "nuevo",
            "assets_nuevos": sorted(todos),
            "assets_bounty": sorted(bounty),
            "reaparece": False,
            "dias_fuera": None,
        }
    else:
        # Registro existente: actualizar solo campos de sync
        updates = {c: registro[c] for c in CAMPOS_SYNC if c in registro}

        # Un campo que el feed NO publica no debe borrar lo que sabemos por
        # otra vía. El feed de HackerOne no trae importes (sus claves son
        # `offers_bounties`, tiempos medios y `response_efficiency_percentage`,
        # ninguna de bounty), así que su parser pone `max_bounty`/`min_bounty` a
        # None y cada barrido —dos por hora— borraba los 216 importes que
        # `enrich_bounty_h1.py` saca del GraphQL público. Verificado: quedaban
        # 0 de 226 al barrido siguiente. `None` aquí significa "esta fuente no
        # lo publica", no "el programa no paga", y no puede pisar un dato real.
        for campo in CAMPOS_ENRIQUECIDOS:
            if updates.get(campo) is None:
                updates.pop(campo, None)

        # Mismo principio con el scope tapado: `██████` no es el scope nuevo
        # del programa, es la plataforma negándose a publicarlo mientras está
        # pausado. Si lo dejáramos entrar perderíamos el scope real (que sigue
        # siendo el bueno) y, al reabrirse el programa, el diff vería sus
        # assets de siempre como recién llegados y publicaría una ampliación
        # que nunca ocurrió. `activo` sí se actualiza: el cierre es real.
        censura = scope_censurado_json(registro.get("scope_raw_in"))
        if censura:
            for campo in CAMPOS_SCOPE:
                updates.pop(campo, None)

        assets_nuevos = []
        assets_bounty = []

        # Estaba fuera del feed y ha vuelto. Se anota antes de que el UPDATE
        # pise `activo`, que es lo único que hoy delata que estuvo fuera.
        reaparece = bool(not fila[2] and registro.get("activo"))
        dias_fuera = None
        restaurados = 0
        if reaparece:
            updates["ultima_reactivacion"] = ahora_str
            dias_fuera = dias_entre(fila[3], ahora_str)
            # Los informes se ocultaron al suspenderse el programa; al volver,
            # vuelven a ser válidos. Se recuperan solo los ocultados por esto,
            # nunca los que se despublicaran por cualquier otro motivo.
            cur.execute(
                "UPDATE informes SET publicado=1, oculto_por=NULL "
                "WHERE programa_id=? AND oculto_por=?",
                (fila[0], MOTIVO_OCULTO_SUSPENSION),
            )
            restaurados = cur.rowcount
            registrar_estado(cur, fila[0], 1, "reaparece", ahora_str, ts_feed)

        # Simétrico de `reaparece`: el programa SIGUE en el feed, pero la
        # plataforma lo ha marcado cerrado (`submission_state`/`status`/
        # `disabled`, según feed). Hasta ahora esa transición no ocultaba nada:
        # la ocultación solo vivía en `marcar_inactivos()`, que mira los que
        # DESAPARECEN del feed. Un programa presente pero cerrado dejaba sus
        # informes publicados, anunciando terreno al que ya no se puede entrar.
        se_suspende = bool(fila[2] and not registro.get("activo"))
        ocultados = 0
        if se_suspende:
            updates["ultima_suspension"] = ahora_str
            # Todos los del programa, no solo el último: cada informe suyo
            # apunta al mismo terreno cerrado.
            cur.execute(
                "UPDATE informes SET publicado=0, oculto_por=? "
                "WHERE programa_id=? AND publicado=1",
                (MOTIVO_OCULTO_SUSPENSION, fila[0]),
            )
            ocultados = cur.rowcount
            registrar_estado(cur, fila[0], 0,
                             "pausado_scope_censurado" if censura else "cerrado_en_feed",
                             ahora_str, ts_feed)

        # Detectar cambio de scope (con el scope tapado no hay nada que
        # comparar: el hash entrante es el de la censura, no el de un scope).
        if fila[1] != nuevo_hash and not censura:
            cur.execute(
                "SELECT scope_raw_in, scope_raw_out FROM programas WHERE plataforma=? AND plataforma_id=?",
                (plataforma, plataforma_id),
            )
            scope_anterior = cur.fetchone()
            if scope_anterior:
                updates["scope_raw_in_antiguo"]  = scope_anterior[0]
                updates["scope_raw_out_antiguo"] = scope_anterior[1]
                # Assets in-scope que no estaban antes (ampliación = oportunidad)
                ids_antes  = ids_scope(scope_anterior[0])
                ids_ahora  = ids_scope(registro["scope_raw_in"])
                assets_nuevos = sorted(ids_ahora - ids_antes)
                # De esos, los que además pagan bounty: son los únicos que
                # disparan alerta y (más adelante) encolado de recon.
                ids_bounty    = ids_scope(registro["scope_raw_in"], solo_bounty=True)
                assets_bounty = [a for a in assets_nuevos if a in ids_bounty]
            updates["hash_scope"]        = nuevo_hash
            updates["fecha_cambio_scope"] = ahora_str

        set_clause = ", ".join(f"{c}=?" for c in updates)
        valores    = list(updates.values()) + [plataforma, plataforma_id]
        cur.execute(
            f"UPDATE programas SET {set_clause} WHERE plataforma=? AND plataforma_id=?",
            valores,
        )
        return {
            "estado": "actualizado",
            "assets_nuevos": assets_nuevos,
            "assets_bounty": assets_bounty,
            # Distinguir un estreno de un programa que solo estaba fuera.
            "reaparece": reaparece,
            "dias_fuera": dias_fuera,
            "se_suspende": se_suspende,
            "informes_ocultados": ocultados,
            "informes_restaurados": restaurados,
        }


def marcar_dejo_de_pagar(cur, plataforma, plataforma_id, ahora_str):
    """
    Un programa presente en el feed ha dejado de pagar bounties.

    - Si NO existe en la BD (nunca pagó): se ignora, no entra.
    - Si existe (pagaba): NO se elimina. Se antepone MARCADOR_NO_PAGA al campo
      `notas` (una sola vez) y se pone offers_bounties=0 para que el flag
      coincida con el aviso.

    Devuelve: "ignorado" | "ya_marcado" | "marcado".
    """
    cur.execute(
        "SELECT notas FROM programas WHERE plataforma=? AND plataforma_id=?",
        (plataforma, plataforma_id),
    )
    fila = cur.fetchone()
    if fila is None:
        return "ignorado"

    notas = fila[0] or ""
    if notas.startswith(MARCADOR_NO_PAGA):
        return "ya_marcado"  # ya avisado en un sync anterior, no duplicar

    nuevas_notas = MARCADOR_NO_PAGA + (f"\n{notas}" if notas else "")
    cur.execute(
        """UPDATE programas SET notas=?, offers_bounties=0, fecha_actualizacion=?
           WHERE plataforma=? AND plataforma_id=?""",
        (nuevas_notas, ahora_str, plataforma, plataforma_id),
    )
    return "marcado"


def marcar_inactivos(cur, plataforma, ids_activos, ahora_str, ts_feed=None):
    """
    Los que ya no están en el feed pasan a activo=0.

    `activo` significa exactamente "aparece en el feed": el sync no puede
    distinguir una suspensión de un cierre, de un paso a privado o de un fallo
    del scraper de origen. Por eso se anota `ultima_suspension` sin pretender
    decir el motivo: es la fecha en que dejamos de verlo.

    Esa fecha hay que guardarla aparte porque `fecha_actualizacion` no sirve
    de huella: al reaparecer el programa se sobrescribe, y la única prueba de
    que estuvo fuera desaparecería justo cuando hace falta.
    """
    if not ids_activos:
        return 0
    placeholders = ",".join("?" * len(ids_activos))
    # Quiénes caen, antes de tocarlos: el UPDATE solo devuelve cuántos.
    caidos = cur.execute(
        f"""SELECT id, nombre FROM programas
            WHERE plataforma=? AND plataforma_id NOT IN ({placeholders})
            AND activo != 0""",
        [plataforma] + list(ids_activos),
    ).fetchall()
    cur.execute(
        f"""UPDATE programas SET activo=0, fecha_actualizacion=?, ultima_suspension=?
            WHERE plataforma=? AND plataforma_id NOT IN ({placeholders})
            AND activo != 0""",
        [ahora_str, ahora_str, plataforma] + list(ids_activos),
    )
    # Salir del feed es silencioso: no hay aviso ni informe. Pero lo ya
    # publicado sí se retira — anunciar un programa al que nadie puede entrar
    # es peor que no anunciar nada. Se oculta, no se borra: `publicado=0` con
    # el motivo, para poder devolverlo si el programa vuelve.
    for pid, nombre in caidos:
        cur.execute(
            "UPDATE informes SET publicado=0, oculto_por=? "
            "WHERE programa_id=? AND publicado=1",
            (MOTIVO_OCULTO_SUSPENSION, pid),
        )
        ocultos = cur.rowcount
        registrar_estado(cur, pid, 0, "ausente_del_feed", ahora_str, ts_feed)
        log.info(f"[{plataforma}] sale del feed: {pid} {nombre}"
                 + (f" — {ocultos} informe(s) ocultado(s)" if ocultos else ""))
    return len(caidos)


# ── ALERTAS (notificación crítica de escritorio, KDE/Plasma) ─────────────────

def _fmt_bounty(maxb):
    if not maxb:
        return "bounty máx sin especificar"
    return f"${maxb:,.0f}".replace(",", ".")


def _notificar(titulo, cuerpo_html):
    """
    Lanza una notificación crítica de escritorio vía notify-send.
    Urgencia crítica = en KDE no se auto-descarta hasta que el usuario la cierra.
    El cuerpo admite HTML: usamos <a href> para un enlace clicable.
    Nunca debe romper el sync: cualquier fallo se registra y se ignora.
    """
    try:
        subprocess.run(
            ["notify-send", "--urgency=critical", "--app-name=BugBounty DB",
             titulo, cuerpo_html],
            check=False, timeout=10,
        )
    except Exception as e:
        log.warning(f"[notify] no se pudo enviar notificación: {e}")


def _registrar_log(titulo, cuerpo_texto):
    """
    Añade la misma información de la alerta a nuevos_log.txt, en texto plano.
    Log progresivo (append): cada aviso queda como constancia aunque la
    notificación de escritorio ya se haya cerrado. Nunca debe romper el sync.
    """
    try:
        marca = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S")
        bloque = f"[{marca}] {titulo}\n{cuerpo_texto}\n\n"
        with open(NUEVOS_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(bloque)
    except Exception as e:
        log.warning(f"[log] no se pudo escribir en nuevos_log.txt: {e}")


def _linea_crono(crono):
    """
    Aviso de antigüedad incierta (ver `construir_crono`).

    En un ciclo normal no devuelve nada: el evento es de hace minutos y el
    propio momento de la alerta ya lo dice. Solo habla cuando la ventana es
    anómala, que es cuando el silencio engañaría.
    """
    if not crono or crono.get("fiable") or crono.get("ventana_min") is None:
        return ""
    return (
        f"⏱ Antigüedad incierta: el barrido anterior fue hace "
        f"{fmt_antiguedad(crono['ventana_min'])}"
    )


def avisar_modo_respaldo(transicion, detalle):
    """
    Anuncia la entrada o la salida del modo respaldo (ver `respaldo.py`).

    Las dos transiciones se notifican y quedan en `nuevos_log.txt`: son cambios
    en de dónde salen los datos que alimentan TODO lo demás, y enterarse tres
    días después de que llevábamos tres días leyendo de otro sitio no vale.
    A diferencia del aviso de fuente estancada, aquí no hay anti-spam: una
    transición ocurre una vez, no en cada barrido.
    """
    if transicion == "activado":
        titulo = "🔄 Modo respaldo ACTIVADO — generando los scopes en local"
        cuerpo = (
            f"La fuente lleva {fmt_antiguedad(detalle.get('edad_min'))} sin publicar "
            f"(último commit {detalle.get('ts')} UTC).\n"
            f"A partir de ahora los feeds se generan aquí con el crawler de "
            f"bounty-targets hasta que la fuente vuelva.\n"
            f'<a href="https://github.com/arkadiyt/bounty-targets-data/commits/main">'
            f"Ver el repo ↗</a>"
        )
        texto = cuerpo.replace(
            '<a href="https://github.com/arkadiyt/bounty-targets-data/commits/main">Ver el repo ↗</a>',
            "https://github.com/arkadiyt/bounty-targets-data/commits/main")
    elif transicion == "desactivado":
        titulo = "✅ Fuente primaria RESTABLECIDA — se desactiva el respaldo"
        cuerpo = (
            f"Hay un commit nuevo en bounty-targets-data ({detalle.get('ts')} UTC).\n"
            f"Se vuelve a leer de GitHub y se deja de scrapear en local."
        )
        texto = cuerpo
    else:
        return

    log.warning(f"[respaldo] {titulo}")
    _notificar(titulo, cuerpo)
    _registrar_log(titulo, texto)


def _estado_lectura():
    """Racha de barridos sin poder leer los commits: {desde, barridos, ultimo_aviso}."""
    try:
        return json.loads(LECTURA_STAMP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def avisar_lectura_rota(fallos):
    """
    Avisa cuando llevamos demasiado tiempo sin PODER leer la fuente.

    Es la otra mitad de `avisar_fuente_estancada`, y a propósito una alarma
    distinta: "la fuente no publica" se arregla esperando a arkadiyt, "no
    consigo leerla" se arregla aquí (DNS, red, límite de la API de GitHub). Una
    sola alarma para las dos cosas mandaba al usuario a mirar un repo que estaba
    perfectamente vivo.

    No salta a la primera: un fallo de resolución al despertar la máquina se
    cura solo en el barrido siguiente, y avisar de eso sería ruido. Hacen falta
    `UMBRAL_LECTURA_MIN` de reloj Y `BARRIDOS_LECTURA` barridos seguidos.
    """
    estado  = _estado_lectura()
    ahora_s = time.time()
    try:
        desde = float(estado.get("desde") or ahora_s)
    except (TypeError, ValueError):
        desde = ahora_s
    barridos = int(estado.get("barridos") or 0) + 1
    edad_min = (ahora_s - desde) / 60
    detalle  = ", ".join(f"{plat}: {motivo}" for plat, motivo in sorted(fallos.items()))
    nuevo_estado = {"desde": desde, "barridos": barridos,
                    "ultimo_aviso": estado.get("ultimo_aviso", 0),
                    "avisado": bool(estado.get("avisado"))}

    if edad_min >= UMBRAL_LECTURA_MIN and barridos >= BARRIDOS_LECTURA:
        log.warning(f"[lectura] {barridos} barridos seguidos ({fmt_antiguedad(edad_min)}) "
                    f"sin poder leer los commits de la fuente — {detalle}")
        try:
            ultimo = float(nuevo_estado.get("ultimo_aviso") or 0)
        except (TypeError, ValueError):
            ultimo = 0.0
        if ahora_s - ultimo >= REAVISO_LECTURA_MIN * 60:
            titulo = "📡 No se puede leer la fuente"
            cuerpo = (
                f"Llevamos {fmt_antiguedad(edad_min)} y {barridos} barridos sin "
                f"conseguir leer los commits de bounty-targets-data.\n"
                f"La fuente puede estar perfectamente viva: lo que falla es "
                f"nuestra lectura, así que mientras dure NO sabemos si hay "
                f"programas nuevos o scope ampliado.\n"
                f"Motivo por feed — {detalle}"
            )
            _notificar(titulo, cuerpo)
            _registrar_log(titulo, cuerpo)
            nuevo_estado["ultimo_aviso"] = ahora_s
            nuevo_estado["avisado"] = True
    else:
        log.info(f"[lectura] barrido {barridos} sin commits legibles "
                 f"({fmt_antiguedad(edad_min)} de racha) — {detalle}")

    try:
        LECTURA_STAMP.write_text(json.dumps(nuevo_estado), encoding="utf-8")
    except OSError as e:
        log.warning(f"[lectura] no se pudo guardar la racha: {e}")


def olvidar_lectura_rota():
    """
    Cierra la racha: hemos vuelto a leer la fuente entera.

    Si se llegó a avisar, la vuelta se anuncia igual que la ida — enterarse de
    que se recuperó vale tanto como enterarse de que se cayó, y sin esto la
    notificación crítica quedaría en pantalla sin desmentido.
    """
    estado = _estado_lectura()
    if not estado:
        return
    if estado.get("avisado"):
        titulo = "✅ Fuente legible otra vez"
        cuerpo = ("Se vuelven a leer los commits de bounty-targets-data: "
                  "el sync ya sabe si hay novedades.")
        log.info(f"[lectura] {titulo}")
        _notificar(titulo, cuerpo)
        _registrar_log(titulo, cuerpo)
    try:
        LECTURA_STAMP.unlink()
    except OSError:
        pass


def avisar_fuente_estancada(ts_feeds, fallos_lectura=None):
    """
    Avisa si `bounty-targets-data` lleva demasiado tiempo sin publicar.

    Todo el sistema cuelga de esa fuente, y su silencio es indistinguible de
    "no ha pasado nada": el sync corre, dice "0 nuevos" y todo parece sano
    mientras en realidad no estamos mirando nada. Verificado el 2026-08-15: el
    repo llevaba tres días sin un commit (último: 2026-08-12 12:34 UTC) y lo
    único que lo delataba era leer el sha a mano en el log.

    `ts_feeds` es {plataforma: ts_commit UTC | None} y `fallos_lectura`
    {plataforma: motivo} con las que no se pudieron consultar. Se juzga por el
    feed MÁS reciente: cada plataforma se commitea a su ritmo y que una vaya
    lenta es normal; que ninguna se mueva, no.

    Y solo se juzga con la foto COMPLETA. El feed más reciente es siempre
    HackerOne (cada ~30 min; el resto va a días), así que si falta justo su
    marca el máximo de las demás es de horas atrás y la fuente parece parada
    estándolo nuestra red. Verificado el 2026-08-21: a las 07:06 se leyó su
    commit de las 05:04 UTC, a las 07:50 falló el DNS al despertar la máquina y
    a las 07:51 saltó "8 h 16 min sin commits" con la fuente publicando. Que
    falte una marca no es una fuente estancada, es que no hemos podido mirar, y
    eso lo cuenta `avisar_lectura_rota`.
    """
    if fallos_lectura:
        log.info(f"[fuente] juicio aplazado: sin commit de "
                 f"{', '.join(sorted(fallos_lectura))} — con la foto incompleta, "
                 f"'sin commits' hablaría de nuestra lectura, no de la fuente")
        avisar_lectura_rota(fallos_lectura)
        return
    olvidar_lectura_rota()

    marcas = [ts for ts in ts_feeds.values() if ts]
    if not marcas:
        return
    edad = minutos_entre(max(marcas), ahora())
    if edad is None or edad < UMBRAL_FUENTE_MIN:
        return

    log.warning(f"[fuente] bounty-targets-data lleva {fmt_antiguedad(edad)} sin "
                f"commits — no hay nada nuevo que detectar en NINGUNA plataforma")

    # Sin esto la misma alarma saltaría en cada barrido (48 al día con la
    # fuente parada) y acabaría ignorándose, que es como no tenerla.
    try:
        ultimo = float(FUENTE_STAMP.read_text())
    except (OSError, ValueError):
        ultimo = 0.0
    if time.time() - ultimo < REAVISO_FUENTE_MIN * 60:
        return

    titulo = "⚠️ Fuente de datos estancada"
    detalle = ", ".join(f"{p}: {ts or '?'}" for p, ts in sorted(ts_feeds.items()))
    cuerpo = (
        f"bounty-targets-data lleva {fmt_antiguedad(edad)} sin commits.\n"
        f"Mientras siga así, el sync no puede detectar programas nuevos ni "
        f"ampliaciones de alcance en ninguna plataforma.\n"
        f"Último commit por feed (UTC) — {detalle}\n"
        f'<a href="https://github.com/arkadiyt/bounty-targets-data/commits/main">'
        f"Ver el repo ↗</a>"
    )
    cuerpo_texto = (
        f"bounty-targets-data lleva {fmt_antiguedad(edad)} sin commits.\n"
        f"Mientras siga así, el sync no puede detectar programas nuevos ni "
        f"ampliaciones de alcance en ninguna plataforma.\n"
        f"Último commit por feed (UTC) — {detalle}\n"
        f"https://github.com/arkadiyt/bounty-targets-data/commits/main"
    )
    _notificar(titulo, cuerpo)
    _registrar_log(titulo, cuerpo_texto)
    try:
        FUENTE_STAMP.write_text(str(time.time()))
    except OSError as e:
        log.warning(f"[fuente] no se pudo escribir la marca de reaviso: {e}")


def _sufijo_omitidos(omitidos):
    """Coletilla para dejar constancia de los assets descartados por no pagar."""
    if not omitidos:
        return ""
    return f"  (+{omitidos} sin bounty, omitido{'s' if omitidos > 1 else ''})"


def avisar_programa_nuevo(registro, assets_bounty, omitidos=0, crono=None):
    plat   = registro["plataforma"]
    nombre = registro.get("nombre") or registro.get("handle")
    url    = registro.get("url") or ""
    n      = len(assets_bounty)
    titulo = f"🆕 Nuevo programa que paga — {plat}"
    plural = "objetivo" if n == 1 else "objetivos"
    linea  = (
        f"Bounty máx: {_fmt_bounty(registro.get('max_bounty'))}  ·  "
        f"{n} {plural} en el alcance con bounty{_sufijo_omitidos(omitidos)}"
    )
    edad = _linea_crono(crono)
    edad_bloque = f"{edad}\n" if edad else ""
    cuerpo = (
        f"{nombre}\n"
        f"{linea}\n"
        f"{edad_bloque}"
        f'<a href="{url}">Abrir programa en {plat} ↗</a>'
    )
    cuerpo_texto = f"{nombre}\n{linea}\n{edad_bloque}{url}"
    _notificar(titulo, cuerpo)
    _registrar_log(titulo, cuerpo_texto)


def avisar_scope_ampliado(registro, assets_nuevos, omitidos=0, crono=None):
    plat   = registro["plataforma"]
    nombre = registro.get("nombre") or registro.get("handle")
    url    = registro.get("url") or ""
    n      = len(assets_nuevos)
    muestra = "\n".join(f"• {a}" for a in assets_nuevos[:4])
    if n > 4:
        muestra += f"\n… y {n - 4} más"
    titulo = f"📈 Alcance ampliado — {plat}"
    plural = "objetivo nuevo" if n == 1 else "objetivos nuevos"
    encabezado = f"{nombre} — {n} {plural} en el alcance{_sufijo_omitidos(omitidos)}"
    edad = _linea_crono(crono)
    edad_bloque = f"{edad}\n" if edad else ""
    cuerpo = (
        f"{encabezado}\n"
        f"{muestra}\n"
        f"{edad_bloque}"
        f'<a href="{url}">Ver programa ↗</a>'
    )
    cuerpo_texto = (
        f"{encabezado}\n"
        f"{muestra}\n"
        f"{edad_bloque}"
        f"{url}"
    )
    _notificar(titulo, cuerpo)
    _registrar_log(titulo, cuerpo_texto)


def avisar_programa_reactivado(registro, extra, crono=None):
    """
    Un programa que estuvo fuera y vuelve. Terreno conocido que se reabre: el
    scope pudo cambiar mientras nadie miraba y la competencia aún no se ha
    enterado. Solo llega aquí si estuvo fuera más de UMBRAL_REACTIVACION_DIAS.
    """
    plat   = registro["plataforma"]
    nombre = registro.get("nombre") or registro.get("handle")
    url    = registro.get("url") or ""
    if extra.get("dias_fuera") is not None:
        linea = f"Estuvo desactivado {texto_dias(extra['dias_fuera'])}"
        if extra.get("creado_en"):
            linea += f" · en {plat} desde {extra['creado_en'][:10]}"
    elif extra.get("creado_en"):
        linea = (f"No es nuevo: existe en {plat} desde {extra['creado_en'][:10]}"
                 f" ({texto_periodo(extra.get('dias_existiendo'))})")
    else:
        linea = "Estuvo desactivado un tiempo indeterminado"
    edad   = _linea_crono(crono)
    edad_bloque = f"{edad}\n" if edad else ""
    titulo = f"🔄 Programa reactivado — {plat}"
    cuerpo = (
        f"{nombre}\n"
        f"{linea}\n"
        f"{edad_bloque}"
        f'<a href="{url}">Abrir programa en {plat} ↗</a>'
    )
    cuerpo_texto = f"{nombre}\n{linea}\n{edad_bloque}{url}"
    _notificar(titulo, cuerpo)
    _registrar_log(titulo, cuerpo_texto)
# ─────────────────────────────────────────────────────────────────────────────


# ── INFORMES (sistema de producción: lo que se publica en la web) ────────────

# Un informe = un asunto. Un evento sobre un programa produce UNA fila aquí, y
# todo lo que el recon encuentre después se funde en su `datos_json`. Nunca dos
# informes con el mismo asunto: el detalle se despliega en el frontend.

TITULOS = {
    "programa_nuevo": "Nuevo programa que paga: {nombre}",
    "scope_ampliado": "{nombre} — {n} objetivos nuevos en el alcance",
    "programa_reactivado": "Programa reactivado: {nombre} — tras {tiempo} desactivado",
}

# Un objetivo no es "objetivo(s)": cuando la cantidad cambia la frase, la frase
# se escribe entera. La web hace lo mismo con sus claves `_uno`.
TITULOS_UNO = {
    "scope_ampliado": "{nombre} — 1 objetivo nuevo en el alcance",
}

# Una reactivación se detecta de dos maneras y cada una sabe una cosa distinta:
# si vimos al programa salir del feed, sabemos cuánto estuvo fuera; si nunca lo
# tuvimos y la plataforma nos dice su edad, solo sabemos desde cuándo existe.
# Decir "tras X desactivado" en el segundo caso sería inventarse el dato.
TITULO_REACTIVADO_DESDE = "Programa reactivado: {nombre} — activo en la plataforma desde {desde}"


def titulo_informe(tipo, nombre, n, extra):
    extra = dict(extra or {})
    # `tiempo` es solo la forma legible de `dias_fuera`: se deriva aquí para
    # que nadie tenga que acordarse de pasar las dos cosas en sintonía.
    if extra.get("dias_fuera") is not None and not extra.get("tiempo"):
        extra["tiempo"] = texto_dias(extra["dias_fuera"])
    # Lo relevante de una reactivación es cuánto estuvo cerrada, no su edad.
    # Solo si no se pudo averiguar el tiempo fuera se cae a "existe desde".
    if tipo == "programa_reactivado" and extra.get("dias_fuera") is None \
            and extra.get("creado_en"):
        return TITULO_REACTIVADO_DESDE.format(nombre=nombre, desde=extra["creado_en"][:10])
    plantilla = (TITULOS_UNO.get(tipo) if n == 1 else None) or TITULOS[tipo]
    return plantilla.format(nombre=nombre, n=n, **extra)

# Qué tecnología anuncia cada flag. Es lo primero que mira un hunter para
# decidir si un objetivo encaja con lo que sabe atacar, así que va en la
# cabecera del informe y alimenta el filtro de tecnología del buscador.
TECNOLOGIAS = [
    ("tiene_graphql",   "GraphQL"),
    ("tiene_api",       "API"),
    ("tiene_api_docs",  "API docs"),
    ("tiene_spa",       "SPA"),
    ("tiene_oauth",     "OAuth"),
    ("tiene_pagos",     "Pagos"),
    ("tiene_android",   "Android"),
    ("tiene_ios",       "iOS"),
]


def contexto_programa(con, programa_id):
    """
    Tecnologías detectadas y perfil del programa, para el informe.

    `pagos` y `actividad` son escalas 0-5 comparables entre plataformas. Se
    devuelven tal cual, incluido `None`: la cobertura es desigual y un hueco
    debe verse como hueco, no como un cero.
    """
    fila = con.execute(
        f"""SELECT {', '.join(c for c, _ in TECNOLOGIAS)},
                   stack_detectado, pagos, actividad, max_bounty, moneda
            FROM programas WHERE id=?""",
        (programa_id,),
    ).fetchone()
    if not fila:
        return {"tecnologias": [], "programa": {}}

    tecnologias = [nombre for (_, nombre), valor in zip(TECNOLOGIAS, fila) if valor == 1]
    stack, pagos, actividad, max_bounty, moneda = fila[len(TECNOLOGIAS):]
    for t in (stack or "").split(","):
        if t.strip() and t.strip() not in tecnologias:
            tecnologias.append(t.strip())

    return {
        "tecnologias": tecnologias,
        # `max_bounty` es el techo DEL PROGRAMA, no el del asset del informe:
        # la web lo rotula así para que no se lea como el máximo de lo que se
        # acaba de publicar. La moneda viaja con él — no todas las plataformas
        # pagan en dólares (Intigriti mezcla EUR, USD y GBP en su propio feed).
        "programa": {"pagos": pagos, "actividad": actividad,
                     "max_bounty": max_bounty, "moneda": moneda},
    }


def crear_informe(con, tipo, registro, assets, omitidos, crono, extra=None):
    """
    Crea el informe del asunto y devuelve su id.

    Se publica ya (`publicado=1`): el evento en sí tiene valor y llegar pronto
    es la ventaja del proyecto. El recon lo enriquecerá después sin generar una
    entrada nueva en el feed.
    """
    fila = con.execute(
        "SELECT id FROM programas WHERE plataforma=? AND plataforma_id=?",
        (registro["plataforma"], registro["plataforma_id"]),
    ).fetchone()
    if not fila:
        log.warning(f"[informe] no encuentro el programa {registro['plataforma_id']} en la BD")
        return None
    programa_id = fila[0]

    nombre = registro.get("nombre") or registro.get("handle")
    # Todos los assets de un informe pagan bounty por construcción (el filtro
    # de elegibilidad ya corrió antes), así que no se lleva la cuenta de los
    # descartados: el feed habla solo de lo que se puede cobrar.
    datos = {
        "assets": assets[:50],          # el resto vive en la BD, no en el feed
        "assets_total": len(assets),
        # Nace preliminar: el informe se publica YA con lo que da el scope, y el
        # recon lo completa después. El worker marcará `completo=true` (o lo
        # dejará definitivo si no hay nada que reconear, p. ej. una app).
        "recon": {"completo": False, "pendiente": ["recon"]},
        **contexto_programa(con, programa_id),
        **(extra or {}),
    }
    # Valor del asset, donde la plataforma lo publique. El techo del programa no
    # es el techo de lo que se acaba de publicar: en YesWeHack un asset LOW paga
    # la mitad que el máximo anunciado. Se consulta su API solo aquí —una
    # petición por evento— y si falla el informe sale como salía antes.
    if registro["plataforma"] == "yeswehack":
        valores = valor_assets.techos(registro.get("handle"), datos["assets"])
        if valores:
            datos["assets_valor"] = valores
    cur = con.execute(
        """INSERT INTO informes
           (timestamp, plataforma, programa_id, programa_nombre, tipo, titulo,
            datos_json, url_programa, relevancia, es_rareza, publicado, origen,
            ts_barrido_anterior)
           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (
            crono["ts_detectado"], registro["plataforma"], programa_id, nombre, tipo,
            titulo_informe(tipo, nombre, len(assets), extra),
            json.dumps(datos, ensure_ascii=False),
            registro.get("url") or "",
            0,      # relevancia: el scoring está pendiente
            0,      # es_rareza: lo activa el recon si encuentra algo raro
            1,
            "sync",
            crono.get("ts_barrido_anterior"),
        ),
    )
    return cur.lastrowid


def encolar_recon(con, informe_id, registro, tipo, assets):
    """
    Encola el trabajo de recon que alimentará ese informe.

    Un job por evento: el pipeline ya sabe recorrer varias raíces. Lo que
    distingue a un disparo de otro es solo qué se le pasa en `assets_nuevos`
    — vacío significa "todas las raíces del scope".
    """
    if informe_id is None:
        return
    fila = con.execute(
        "SELECT id FROM programas WHERE plataforma=? AND plataforma_id=?",
        (registro["plataforma"], registro["plataforma_id"]),
    ).fetchone()
    if not fila:
        return
    # Siempre entra por el pase rápido y con prioridad de EVENTO (100): lo que
    # se publica en minutos es lo que da ventaja, y un evento real nunca debe
    # esperar detrás de una tanda de mantenimiento. Espejo de
    # recon_worker.PRIORIDAD_EVENTO_RAPIDO (no se importa para no acoplar el
    # timer de sync al pipeline). El worker encola el profundo cuando termine.
    PRIORIDAD_EVENTO_RAPIDO = 100
    con.execute(
        """INSERT INTO recon_cola
           (programa_id, tipo, assets_nuevos, estado, fecha_encolado, informe_id,
            fase, prioridad)
           VALUES (?,?,?,?,?,?,?,?)""",
        (
            fila[0], tipo,
            json.dumps(assets, ensure_ascii=False) if tipo == "scope_ampliado" else None,
            "pendiente", ahora(), informe_id, "rapido", PRIORIDAD_EVENTO_RAPIDO,
        ),
    )


def registrar_evento(tipo, registro, assets, omitidos, crono, extra=None):
    """
    Persiste un evento como informe + job de recon.

    Se abre conexión propia porque esto corre después del commit del sync, en
    el mismo punto que las notificaciones. Nunca debe romper el sync: si algo
    falla, se registra y el ciclo continúa.
    """
    try:
        con = sqlite3.connect(DB_PATH, timeout=30)
        try:
            informe_id = crear_informe(con, tipo, registro, assets, omitidos, crono, extra)
            encolar_recon(con, informe_id, registro, tipo, assets)
            con.commit()
            return informe_id
        finally:
            con.close()
    except Exception as e:
        log.warning(f"[informe] no se pudo registrar el evento {tipo}: {e}")
        return None


def sincronizar():
    # Lo primero: ¿hay red? systemd nos lanza al arrancar y al despertar la
    # máquina, y sin esperar aquí el barrido corre a ciegas y deja marcas de
    # tiempo a medias. Nunca aborta: si no la hay, se sigue y se cuenta aparte.
    esperar_red()

    # Backup antes de cualquier cambio, cola máxima de MAX_BACKUPS ficheros
    hacer_backup()

    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    ahora_str = ahora()

    # ¿Sigue viva la fuente primaria? Lo primero de todo: decide de dónde se
    # leen los feeds de este barrido y, con ello, cuál es la ventana real de los
    # eventos. Una sola consulta al repo entero — preguntando por el fichero de
    # cada plataforma se confundiría "nadie ha tocado ese feed" con "la fuente
    # está muerta".
    transicion, detalle_fuente = respaldo.evaluar_fuente()
    avisar_modo_respaldo(transicion, detalle_fuente)
    if transicion == "activado":
        # Sin esto habría que esperar al timer horario para tener datos frescos.
        respaldo.lanzar_generacion_en_segundo_plano(log)
    if respaldo.esta_activo():
        estado_resp = respaldo.leer_estado()
        log.info(f"[respaldo] MODO ACTIVO desde {estado_resp.get('desde')} UTC — "
                 f"feeds locales generados {estado_resp.get('generado_en')} UTC")

    # Antes de tocar nada: cuándo corrió el sync anterior. Marca el inicio de
    # la ventana en la que pudo ocurrir cualquier evento que detectemos hoy.
    ts_anterior = ultimo_sync(cur)
    # …salvo cuando el modo respaldo acaba de traer datos frescos tras días de
    # fuente parada: ahí la ventana real no es "desde el último barrido" sino
    # "desde el último dato bueno de la fuente". El sync corría cada 30 minutos,
    # pero leyendo siempre el mismo feed congelado. Sin esta corrección, un
    # scope publicado hace tres días se anunciaría como recién salido.
    # Solo se consume cuando hay feeds locales que leer: entre que el modo se
    # activa y que termina el primer barrido (~10 min) el sync sigue con el feed
    # viejo de GitHub, y gastar ahí la ventana la desperdiciaría.
    ventana_respaldo = respaldo.consumir_ventana() if respaldo.hay_feeds_locales() else None
    if ventana_respaldo and (ts_anterior is None or ventana_respaldo < ts_anterior):
        log.info(f"[respaldo] primer barrido con datos frescos: la ventana de los "
                 f"eventos arranca en {ventana_respaldo} UTC (último dato bueno de la fuente), "
                 f"no en el barrido anterior")
        ts_anterior = ventana_respaldo
    crono = construir_crono(ts_anterior, ahora_str)
    if crono["ventana_min"] is not None:
        log.info(
            f"[crono] barrido anterior hace {fmt_antiguedad(crono['ventana_min'])}"
            f"{'' if crono['fiable'] else ' — antigüedad de los eventos de este ciclo INCIERTA'}"
        )

    totales = {"nuevo": 0, "actualizado": 0, "inactivo": 0, "suspendido": 0,
               "restaurado": 0, "dejaron_pagar": 0}
    # Eventos de alta prioridad: se notifican DESPUÉS del commit, nunca antes.
    alertas = []
    # Hora del último commit de cada feed: dice si la fuente sigue viva.
    ts_feeds = {}
    # …y de cuáles no se pudo leer, que es lo que decide si esa lectura vale.
    fallos_lectura = {}

    for plataforma in URLS:
        # Estrenar una plataforma no es un aluvión de noticias: sus programas
        # llevan ahí toda la vida, lo nuevo es que nosotros miramos. Sin esto,
        # dar de alta una fuente dispararía una alerta, un informe y un job de
        # recon por CADA programa (Bugcrowd: 239 de golpe). La primera carga
        # entra muda y a partir de la siguiente pasada ya solo hay deltas.
        carga_inicial = cur.execute(
            "SELECT 1 FROM programas WHERE plataforma=? LIMIT 1", (plataforma,)
        ).fetchone() is None

        # Por SHA: contenido inmutable y con hora conocida. `main` va con caché
        # y puede servir una foto vieja (medido: una tanda de retraso).
        url, sha, ts_feed, fallo_ts = feed_a_leer(plataforma)
        # Un feed propio siempre está fresco: dejarlo entrar aquí silenciaría la
        # alarma de fuente estancada (juzga por el más reciente de todos).
        if plataforma not in PLATAFORMAS_PROPIAS:
            ts_feeds[plataforma] = ts_feed
            if fallo_ts:
                fallos_lectura[plataforma] = fallo_ts
        log.info(f"[{plataforma}] descargando... "
                 + (f"commit {sha[:8]} ({ts_feed} UTC)" if sha else "main (sin SHA, con caché)"))
        # Una plataforma que no se puede leer se SALTA; no tumba el barrido.
        # `descargar` lanza tras agotar los reintentos y esta llamada estaba
        # desnuda, así que un feed caído —o el feed propio de GObugfree aún sin
        # generar— abortaba la sincronización entera y las otras cinco
        # plataformas se quedaban sin procesar. Es el mismo fallo que tumbó la
        # fuente durante tres días en agosto: una plataforma rota se llevaba por
        # delante a las demás. Saltar es además lo seguro para los datos: se
        # salta ANTES de `marcar_inactivos`, así que no se da de baja a nadie
        # por no haber podido mirar.
        try:
            # Un fichero local que no está no va a aparecer esperando 20 s:
            # reintentar solo tiene sentido contra la red.
            datos = descargar(url, intentos=1 if plataforma in PLATAFORMAS_PROPIAS else 3)
        except Exception as e:
            log.error(f"[{plataforma}] feed ILEGIBLE ({e}) — se salta esta "
                      f"plataforma en este barrido, sus programas quedan intactos")
            continue
        parser = PARSERS[plataforma]

        ids_vistos = set()
        nuevos = actualizados = ignorados = dejaron_pagar = suspendidos = restaurados = 0

        for p in datos:
            try:
                registro = parser(p)
                # La moneda por plataforma se aplica aquí y no en cada parser:
                # es una propiedad de la plataforma, no del programa. Intigriti
                # es la excepción —la trae en su feed— y por eso no se pisa.
                if registro.get("max_bounty") and not registro.get("moneda"):
                    registro["moneda"] = MONEDA_PLATAFORMA.get(plataforma)
            except Exception as e:
                log.error(f"[{plataforma}] ERROR parseando "
                          f"{p.get('handle') or p.get('id') or p.get('url')}: {e}")
                continue

            # La BD solo alberga programas que pagan bounties.
            if not registro.get("offers_bounties"):
                resultado = marcar_dejo_de_pagar(
                    cur, plataforma, registro["plataforma_id"], ahora_str
                )
                if resultado == "ignorado":
                    # Nunca estuvo en la BD: no entra.
                    ignorados += 1
                else:
                    # Sigue presente en el feed aunque ya no pague: se conserva
                    # y no debe marcarse inactivo por marcar_inactivos().
                    ids_vistos.add(registro["plataforma_id"])
                    if resultado == "marcado":
                        dejaron_pagar += 1
                continue

            ids_vistos.add(registro["plataforma_id"])
            resultado = upsert(cur, registro, ahora_str, ts_feed)

            # Un asset con eligible_for_bounty=false no es una oportunidad:
            # ni alerta ni (más adelante) encolado de recon. Solo cuentan los
            # que pagan; los demás quedan en la BD pero se omiten aquí.
            assets_bounty = resultado["assets_bounty"]
            omitidos      = len(resultado["assets_nuevos"]) - len(assets_bounty)
            handle        = registro.get("handle") or registro["plataforma_id"]

            if resultado["estado"] == "nuevo":
                nuevos += 1
                if carga_inicial:
                    # Alta de la plataforma: se guarda, no se anuncia. Tampoco
                    # se pregunta la edad (una petición por programa para una
                    # respuesta que no vamos a usar).
                    pass
                elif assets_bounty:
                    # Que no esté en la BD no lo hace nuevo: puede llevar años
                    # en la plataforma y haber estado invisible. Se pregunta
                    # antes de anunciarlo como estreno.
                    estreno, creado, dias = es_estreno_real(
                        plataforma, registro["plataforma_id"], ahora_str, cur)
                    if estreno:
                        alertas.append(("nuevo", dict(registro), assets_bounty, omitidos, crono, {}))
                    else:
                        # Lo relevante no es su edad, es cuánto estuvo cerrado.
                        # Como nunca estuvo en la BD no hay `ultima_suspension`,
                        # así que se busca en el histórico del feed.
                        visto = ultima_vez_en_feed(plataforma, registro["plataforma_id"], ahora_str)
                        fuera = dias_entre(visto, ahora_str) if visto else None
                        extra = {"creado_en": creado, "dias_existiendo": dias}
                        if fuera is not None:
                            extra["dias_fuera"] = fuera
                            extra["tiempo"] = texto_dias(fuera)
                            extra["ultima_vez_visto"] = visto
                        log.info(
                            f"[{plataforma}] {handle}: NO es nuevo — existe desde {creado}"
                            + (f", fuera del feed {fuera} día(s)" if fuera is not None
                               else ", no se pudo acotar cuánto estuvo fuera")
                        )
                        alertas.append(("reactivado", dict(registro), assets_bounty,
                                        omitidos, crono, extra))
                else:
                    log.info(
                        f"[{plataforma}] {handle}: programa nuevo sin assets "
                        f"elegibles para bounty ({omitidos} descartados) — sin alerta"
                    )
            else:
                actualizados += 1
                # Cerrado sin salir del feed. Como al salir: no se avisa (un
                # programa que cierra no es una oportunidad), pero lo publicado
                # se retira y queda en el log por qué desapareció de la web.
                if resultado.get("se_suspende"):
                    n_oc = resultado.get("informes_ocultados") or 0
                    suspendidos += 1
                    log.info(f"[{plataforma}] pasa a suspendido en el feed: {handle}"
                             + (f" — {n_oc} informe(s) ocultado(s)" if n_oc
                                else " — sin informes que ocultar"))
                restaurados += resultado.get("informes_restaurados") or 0
                if resultado.get("reaparece"):
                    dias = resultado.get("dias_fuera")
                    # Volver enseguida no es noticia: la plataforma estaba
                    # trasteando. Solo una ausencia larga significa que el
                    # terreno estuvo cerrado el tiempo suficiente para que
                    # haya cambiado algo.
                    if dias is not None and dias >= UMBRAL_REACTIVACION_DIAS:
                        log.info(f"[{plataforma}] vuelve al feed: {handle} "
                                 f"tras {dias} día(s) — se avisa")
                        alertas.append(
                            ("reactivado", dict(registro), [], 0, crono,
                             {"dias_fuera": dias, "tiempo": texto_dias(dias)}))
                    else:
                        log.info(f"[{plataforma}] vuelve al feed: {handle} "
                                 f"tras {dias} día(s) — por debajo del umbral, sin aviso")
                if assets_bounty:
                    # Ampliación de scope: oportunidad de terreno sin explorar.
                    alertas.append(("scope", dict(registro), assets_bounty, omitidos, crono, {}))
                elif resultado["assets_nuevos"]:
                    log.info(
                        f"[{plataforma}] {handle}: {omitidos} asset(s) nuevos "
                        f"sin bounty — sin alerta"
                    )

        inactivos = marcar_inactivos(cur, plataforma, ids_vistos, ahora_str, ts_feed)

        # `inactivos` = desaparecidos del feed; `suspendidos` = siguen listados
        # pero cerrados. Dos caminos distintos a la misma consecuencia (informes
        # ocultos), así que se cuentan aparte para saber cuál actuó.
        log.info(
            f"[{plataforma}] {len(datos)} programas — {nuevos} nuevos, "
            f"{actualizados} actualizados, {inactivos} inactivos, "
            f"{suspendidos} suspendidos en feed, "
            f"{dejaron_pagar} dejaron de pagar, {ignorados} ignorados (no pagan)"
            + (" — CARGA INICIAL de la plataforma, sin alertas" if carga_inicial else "")
        )
        totales["nuevo"]         += nuevos
        totales["actualizado"]   += actualizados
        totales["inactivo"]      += inactivos
        totales["suspendido"]    += suspendidos
        totales["restaurado"]    += restaurados
        totales["dejaron_pagar"] += dejaron_pagar

    con.commit()
    con.close()

    log.info(
        f"[total] {totales['nuevo']} nuevos, {totales['actualizado']} actualizados, "
        f"{totales['inactivo']} inactivos, {totales['suspendido']} suspendidos en feed, "
        f"{totales['dejaron_pagar']} dejaron de pagar"
    )

    # Notificaciones (tras commit): solo eventos de alta prioridad.
    # `assets` ya viene filtrado a los elegibles para bounty; es también la
    # lista que debe usar el futuro hook de encolado de recon.
    informes = 0
    for tipo, registro, assets, omitidos, crono, extra in alertas:
        # La hora del evento se sella AQUÍ, no al arrancar el barrido: entre una
        # cosa y otra la máquina puede haber dormido horas (ver `refrescar_crono`).
        crono = refrescar_crono(crono)
        # Etiqueta las apps con su plataforma (Android/iOS) y limpia espacios,
        # para que dos apps con el mismo identificador no parezcan duplicadas.
        assets = etiquetar_assets(assets, registro.get("scope_raw_in"))
        if tipo == "nuevo":
            avisar_programa_nuevo(registro, assets, omitidos, crono)
            tipo_informe = "programa_nuevo"
        elif tipo == "reactivado":
            avisar_programa_reactivado(registro, extra, crono)
            tipo_informe = "programa_reactivado"
        else:
            avisar_scope_ampliado(registro, assets, omitidos, crono)
            tipo_informe = "scope_ampliado"
        # El informe es lo que acaba en la web; la notificación de escritorio
        # sigue siendo el aviso inmediato para el usuario.
        if registrar_evento(tipo_informe, registro, assets, omitidos, crono, extra):
            informes += 1

    if alertas:
        log.info(f"[notify] {len(alertas)} alerta(s) enviada(s)")
        log.info(f"[informe] {informes}/{len(alertas)} evento(s) registrados y encolados")

    # Un barrido sin eventos puede significar dos cosas muy distintas: que no
    # ha pasado nada, o que la fuente no publica y no estamos mirando nada.
    #
    # En modo respaldo esta alarma sobra y encima mentiría: ya avisamos al
    # entrar en el modo, y los `ts_feeds` de este barrido son horas de
    # generación local, no de commits de la fuente.
    if not respaldo.esta_activo():
        avisar_fuente_estancada(ts_feeds, fallos_lectura)

    # Nivel instantáneo: si sync creó algún informe, se publica la web AL
    # MOMENTO (forzar), sin esperar al recon. El evento fresco llega a la web en
    # segundos desde que se detecta — antes esto no pasaba: el informe se
    # quedaba en la BD hasta un deploy manual. `publicar` es un módulo ligero
    # (subprocess + lock), no arrastra el pipeline; import local por si acaso.
    #
    # Retirar corre la misma prisa que anunciar: ocultar un informe solo lo
    # despublica en la BD, y el feed de la web se genera al exportar. Sin este
    # disparo, un programa cerrado seguiría anunciándose en la web hasta el
    # siguiente deploy por otro motivo — que puede no llegar en horas.
    # Y lo mismo al revés: un programa que reabre restaura sus informes en la
    # BD, pero sin publicar seguirían ausentes de la web hasta vaya a saber
    # cuándo. Cualquier cambio en QUÉ se ve tiene que llegar a la web ya.
    # Antes de publicar: el logo de los programas que acaban de entrar. Los
    # fetchers existían desde hacía tiempo, pero había que acordarse de
    # lanzarlos, así que cada alta llegaba a la web sin icono y ahí se quedaba
    # (el 2026-08-16 eran 10 de golpe, Zendesk incluido). Va aquí y no después
    # de publicar para que el informe salga ya con su icono, en vez de aparecer
    # sin él y arreglarse en el siguiente deploy.
    #
    # Solo cuando ha habido altas, y cada fetcher consulta solo su plataforma si
    # tiene programas sin icono: en un barrido normal esto no hace ni una
    # petición. Nunca debe tumbar el sync — un icono que falta es cosmético, y
    # el evento en sí vale mucho más que su logo.
    if totales["nuevo"] or totales["restaurado"]:
        try:
            import iconos
            iconos.actualizar(log=log)
        except Exception as e:
            log.warning(f"[iconos] no se pudieron actualizar los iconos: {e}")

    retiradas   = totales["suspendido"] + totales["inactivo"]
    devueltos   = totales["restaurado"]
    if informes or retiradas or devueltos:
        import publicar as publicador
        if publicador.publicar(forzar=True, log=log):
            if informes:
                log.info("[web] publicada tras el evento")
            else:
                log.info(f"[web] publicada tras retirar {retiradas} programa(s) "
                         f"y devolver {devueltos} informe(s)")


if __name__ == "__main__":
    sincronizar()
