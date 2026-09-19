#!/usr/bin/env python3
"""
fetch_standoff.py — Genera aquí el feed de Standoff 365 (bugbounty.standoff365.com).

POR QUÉ EXISTE
--------------
Séptima plataforma de la BD y segunda que NO viene de `bounty-targets-data`
(la otra es GObugfree). Es la mayor plataforma rusa de bug bounty: 220
programas en catálogo, de los que 88 están vivos.

El sondeo de ~20 plataformas del 2026-08-16 la había dado por descartada junto
al resto ("solo GObugfree publica scope sin login"). Eso era falso para esta:
publica el catálogo Y el scope estructurado sin autenticación, solo que por
una API que la web usa desde el navegador y que no está enlazada en ningún
sitio. Verificado el 2026-08-19 sobre los 88 programas vivos.

QUÉ PUBLICA, Y POR DÓNDE (verificado 2026-08-19)
------------------------------------------------
Dos endpoints, ambos 200 sin credenciales, exigiendo cabeceras de navegador
(`Origin`/`Referer`; sin ellas contesta el WAF):

1. Catálogo entero en UNA petición (3,1 MB):
      GET {API}/bug-bounty/ui/program?page=1&pagesize=500
   Trae `status`, `visibility`, `publishedAt`, `logo` y `statistics.rewards`.

2. Scope ESTRUCTURADO, una petición por programa:
      GET {API}/bug-bounty/program/scope?program_id=<id>&sort=severity
   Devuelve `[{scope, severity, appTypeName, appTypeId, id, programId}]`.
   Nótese que cuelga de `bug-bounty/program`, no de `bug-bounty/ui/program`:
   es el mismo camino que usa el panel del vendor, pero la lectura es pública.

   Esto es lo que hace que la plataforma valga la pena: hay tipo por asset
   (Domain, Wildcard, CIDR, API, Android, iOS, Other) y severidad máxima por
   asset, que es más de lo que dan cuatro de las seis plataformas actuales. Sin
   él habría que sacar los hosts de la prosa de `description`, donde in-scope y
   out-of-scope conviven en el mismo texto (en `ati_su` la lista más larga de
   hosts son EXCLUSIONES) y confundirlos significaría lanzar el recon contra lo
   que el programa declara fuera.

QUÉ SE COGE Y QUÉ NO
--------------------
Entran los `status=published`, no `finished` y `visibility=public`: 82 de los
88 vivos. Los otros 6 son `with_confirmation` y su scope responde 404 —
comprobado que el conjunto de los 6 que dan 404 es EXACTAMENTE el de los 6
`with_confirmation`, no una coincidencia de dos listas parecidas—. Son además
los 6 de `terms=only_risks` ("eventos inaceptables": se paga por lograr un
impacto de negocio pactado, no por vulnerabilidad). Que la propia plataforma no
enseñe su scope sin pasar por confirmación los deja fuera por la regla de
siempre: si hace falta que te admitan, no se publica.

LO QUE ESTA FUENTE **NO** DA, Y CÓMO SE TRATA
---------------------------------------------
1. **No hay out-of-scope estructurado**: no existe campo ni tipo para ello, así
   que `out_of_scope` sale SIEMPRE vacío, igual que en GObugfree. Las
   exclusiones están en la prosa de `description` y ahí se quedan: el recon no
   tendrá exclusiones que aplicar en esta plataforma.
2. **Un `scope` es un bloque de texto, no un identificador**: llegan varias
   líneas en el mismo campo, con viñetas markdown (`* host`), enlaces
   (`[dom.ru](https://dom.ru)`), comentarios tras guión y prosa en ruso. De ahí
   `_identificadores()`, que saca los identificadores por forma y deja como
   `other` lo que no tiene ninguno — que es lo que el recon ignora.
3. **Los importes son RUBLOS** (`statistics.rewards.rub`). `sync.MONEDA_PLATAFORMA`
   sella `RUB` para que la web no los pinte como si fueran euros. Que
   `statistics.rewards.rub.max` es el techo real del programa, y no una
   estadística de lo ya pagado, está verificado contra la tabla por severidad
   de la ficha (cloud_ru: 400.000 en ambos sitios).

Uso:
    python3 fetch_standoff.py            # barre y promueve el feed
    python3 fetch_standoff.py --simular  # barre y enseña, sin escribir nada
    python3 fetch_standoff.py --estado   # qué hay guardado y de cuándo
"""
import argparse
import json
import logging
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

API       = "https://api.standoff365.com/api"
URL_LISTA = f"{API}/bug-bounty/ui/program?page=1&pagesize=500"
URL_SCOPE = f"{API}/bug-bounty/program/scope?program_id={{pid}}&sort=severity"
URL_PROG  = "https://bugbounty.standoff365.com/programs/{slug}"
# El catálogo trae el logo como nombre de fichero (`<uuid>.jpeg`), pero NO la
# ruta desde la que se sirve: probadas las cuatro que se deducen del bundle
# (`cdn.standoff365.com/standoff-bugbounty/`, `/content/`, `api/content/`) y las
# cuatro dan 404. Se guarda el identificador crudo en vez de una URL inventada:
# el día que se capture la petición real del navegador, el dato ya está aquí y
# solo hay que anteponerle el prefijo. Sin esto, `fetch_iconos_*` bajaría 404s.
LOGO_SIN_RUTA = True

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DIR_FEED = BASE / "feeds_standoff"
FEED     = DIR_FEED / "standoff_data.json"
ESTADO   = DIR_FEED / "estado.json"

# Sin estas cabeceras el WAF responde 403: la API está pensada para que la
# llame su propio front, no para clientes sueltos.
CABECERAS = {
    "User-Agent": ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                   "(KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"),
    "Origin":  "https://bugbounty.standoff365.com",
    "Referer": "https://bugbounty.standoff365.com/",
    "Accept":  "application/json",
    # El scope de muchos programas está redactado en los dos idiomas; pidiendo
    # en-US se obtiene la variante inglesa cuando existe y la rusa cuando no.
    "Accept-Language": "en-US,en;q=0.9",
}

PAUSA_PETICION = 0.7      # el mismo espaciado que se usa con GObugfree
TIMEOUT        = 40

# Suelos del sanity check. El catálogo se mueve despacio (88 vivos hoy), así que
# un barrido que devuelva mucho menos es un fallo de red o un cambio de la API,
# no una desbandada de programas. Ver `sanity`.
MIN_PROGRAMAS = 40
RATIO_MINIMO  = 0.80

# appTypeName de la plataforma -> vocabulario de tipos que ya entiende
# `recon_scope.KEYS`/`TIPOS_*`. Se traduce aquí, en la frontera, para que el
# resto del sistema no tenga que conocer a Standoff.
#   Domain/API      -> website : entran por TIPOS_HOST y se enumeran
#   Wildcard        -> wildcard: raíz a enumerar entera
#   CIDR/IP Address -> cidr    : reconocidos y hoy ignorados por el recon (v1)
#   Android/iOS     -> android/ios: no son DNS, el recon los salta
#   Other           -> other   : lo que no tiene forma de asset
TIPOS = {
    "Domain": "website",
    "API": "website",
    "Wildcard": "wildcard",
    "CIDR": "cidr",
    "IP Address": "ip_address",
    "Android: Play Store": "android",
    "Android: .apk": "android",
    "iOS: App Store": "ios",
    "Other": "other",
}

# Un enlace markdown: nos quedamos con el DESTINO, no con el texto. El texto es
# decorativo y a veces va abreviado ("Маркетплейс"), mientras que el destino es
# la forma canónica y estable del asset.
RE_MD_LINK = re.compile(r"\[[^\]]*\]\(\s*([^)\s]+)[^)]*\)")
# Viñeta de lista al principio de la línea. El espacio es obligatorio: sin él
# se comería el `*.` de un wildcard, que es justo el dato que hay que conservar.
RE_VINETA  = re.compile(r"^\s*[*\-•—]\s+")
# Host o URL dentro de una línea que puede llevar prosa alrededor.
RE_HOST = re.compile(
    r"(?:https?://)?"
    r"(?:\*\.?)?"                              # comodín, con o sin punto
    r"(?:[A-Za-z0-9_-]+\.)+[A-Za-z]{2,}"       # dominio
    r"(?::\d+)?"                               # puerto
    r"(?:/[^\s,;()<>\[\]]*)?"                  # ruta
)
# Negrita/cursiva markdown. Hay que quitarla ANTES de buscar hosts: VK titula
# sus bloques `**dzen.ru домены**`, y el asterisco de apertura pegado al dominio
# se leía como comodín, inventando un wildcard `*dzen.ru` que nadie declaró.
RE_ENFASIS = re.compile(r"\*{2,3}|__")
RE_IP    = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?:/\d{1,2})?\b")
RE_PLAY  = re.compile(r"play\.google\.com/store/apps/details\?id=([A-Za-z0-9_.]+)")
RE_APPLE = re.compile(r"apps\.apple\.com/\S*?/id(\d+)")
RE_RUSTORE = re.compile(r"rustore\.ru/catalog/app/([A-Za-z0-9_.]+)")
RE_PAQUETE = re.compile(r"^[a-z][a-z0-9_]*(?:\.[a-z0-9_]+){2,}$", re.I)
# A partir de cuántas palabras un `other` deja de ser una etiqueta y es una
# NOTA del programa. Wildberries mete en el scope frases como "dominios y
# subdominios no registrados en la zona *.ru": guardarlas como asset no solo
# engorda `num_scope_in`, es que `recon_scope._wildcard_de_host` mira el patrón
# del identificador y no el tipo, así que el `*.ru` de esa frase entraba como
# WILDCARD y ponía `ru` a un paso de las raíces a enumerar. Las etiquetas
# cortas sí se conservan (`WEB`, `Мобильные приложения`): identifican algo.
MAX_PALABRAS_OTHER = 4

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s",
                    datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger(__name__)


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def pedir(url, intentos=3):
    """GET que devuelve JSON. Un 404 se propaga tal cual: para el scope
    significa "este programa no lo enseña", que es información, no un error."""
    ultimo = None
    for n in range(intentos):
        try:
            req = urllib.request.Request(url, headers=CABECERAS)
            with urllib.request.urlopen(req, timeout=TIMEOUT) as r:
                return json.loads(r.read().decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                raise
            ultimo = e
        except Exception as e:
            ultimo = e
        if n < intentos - 1:
            time.sleep(2 * (n + 1))
    raise ultimo


def _lineas(bloque):
    """El campo `scope` trae varios assets separados por saltos de línea."""
    for cruda in (bloque or "").splitlines():
        ln = RE_VINETA.sub("", cruda).strip()
        # Placeholder de "aquí no hay nada": 35 de las 36 entradas `Other` son
        # exactamente esto. Guardarlas engordaría `num_scope_in` con vacío.
        if not ln or ln in {"-", "—", "–"}:
            continue
        yield ln


def _limpiar_host(bruto):
    """Host/URL crudo -> identificador estable, sin esquema ni barra final."""
    h = bruto.strip().rstrip(".,;)")
    h = re.sub(r"^https?://", "", h)
    h = re.sub(r"^www\.", "", h)
    return h.rstrip("/") or None


def _identificadores(linea, tipo):
    """
    Identificadores de una línea de scope, ya normalizados.

    Devuelve lista de (identificador, tipo). Puede devolver varios: hay líneas
    con dos apps o dos dominios juntos. Y puede devolver `other` cuando la
    línea es prosa: es lo honesto —el asset existe y el programa lo declara—
    pero sin forma que el recon pueda enumerar.

    Todo lo que hace depende solo del texto de entrada, nunca de la red ni del
    orden de las llamadas: si el vendor no toca su scope, el identificador de
    mañana es idéntico al de hoy. Esa estabilidad es la condición para que el
    diff de `sync.upsert` no invente "assets nuevos" en cada barrido.
    """
    # El destino del enlace sustituye al par completo: así el texto decorativo
    # no llega al identificador.
    texto = RE_ENFASIS.sub(" ", RE_MD_LINK.sub(r" \1 ", linea))

    if tipo in ("android", "ios"):
        ids = ([f"{p} — Google Play" for p in RE_PLAY.findall(texto)]
               + [f"id{n} — App Store" for n in RE_APPLE.findall(texto)]
               + [f"{p} — RuStore"     for p in RE_RUSTORE.findall(texto)])
        if ids:
            return [(i, tipo) for i in ids]
        # Sin enlace de tienda: a veces ponen el paquete pelado
        # (`com.konsolpro.konsolpro`).
        crudo = texto.strip()
        if RE_PAQUETE.match(crudo):
            return [(crudo, tipo)]
        # Prosa sin enlace de tienda ni paquete: es la ETIQUETA de la app, y su
        # enlace real viene en la línea siguiente del mismo bloque
        # (`Мобильное приложение «Госуслуги» iOS` + la URL del App Store).
        # Guardarla sumaría un asset `other` que ni se puede enumerar ni
        # identifica nada — solo ruido en `num_scope_in` y en los informes.
        return []

    if tipo in ("cidr", "ip_address"):
        ips = RE_IP.findall(texto)
        return [(ip, tipo) for ip in ips] or [(texto.strip(), "other")]

    # website / wildcard / other: manda la forma, no la etiqueta. Un `Other`
    # que contiene una URL (fedsfm publica ahí `https://new.fedsfm.ru:7443`) es
    # un host de verdad, y un `Domain` que es una frase en ruso no lo es.
    fuera = []
    for m in RE_HOST.finditer(texto):
        ident = _limpiar_host(m.group(0))
        if not ident:
            continue
        # Un identificador que empieza por `*` es una raíz a enumerar entera,
        # aunque la plataforma lo haya etiquetado como Domain: en Standoff los
        # wildcards viajan sobre todo dentro de `Domain` (393 líneas) y no en
        # el tipo `Wildcard` (2). Es el mismo caso que Bugcrowd, y
        # `recon_scope._wildcard_de_host` ya lo detecta por el patrón.
        # Todo lo que llega aquí casó con RE_HOST, así que tiene forma de host
        # aunque su etiqueta fuera `Other`: se trata como tal.
        fuera.append((ident, "wildcard" if ident.startswith("*") else "website"))
    if fuera:
        return fuera
    return [(texto.strip(), "other")]


# --- Rescate del scope que no está en el endpoint de scope ---------------
#
# 24 de los 82 programas publicables dejan el scope estructurado en `-`. De
# ellos, 14 son productos on-premise de Positive Technologies (PT NGFW,
# MaxPatrol...): no tienen superficie DNS y quedarse a cero es lo correcto. Los
# otros 10 son de VK y RuStore —los de mayor techo de la plataforma, hasta
# 3.600.000 RUB— y publican sus dominios en la prosa de `description`, bajo una
# sección de encabezados fija.
#
# Leer prosa para sacar scope es justo lo que este fetcher evita, porque en
# esta plataforma in-scope y out-of-scope conviven en el mismo texto. Por eso
# el rescate es DELIBERADAMENTE estrecho: solo entra lo que cuelga de un
# encabezado que dice "Dominios" DENTRO del que dice "Ámbito del Bug Bounty", y
# nada que cuelgue de un encabezado con negación. Todo lo demás se ignora
# aunque tenga forma de host.
#
# Lo que ese filtro descarta a propósito (verificado 2026-08-19):
#   - other_vk y vk_cs_vk no tienen sección "Домены": sus únicos hosts en prosa
#     van bajo "Мы не принимаем уязвимости на следующих доменах" (no aceptamos
#     vulnerabilidades en estos dominios). Se quedan a cero, que es lo correcto.
#   - vkworkspace_vk sí la tiene, y aparte otra sección donde los informes "se
#     aceptan sin pago con fines informativos": esa no entra.
SEC_AMBITO  = re.compile(r"область\s+действия|scope", re.I)
SEC_DOMINIO = re.compile(r"домен|domain|hosts?\b", re.I)
# Negaciones que invalidan un encabezado. `не ` con espacio: `не` pegada a otra
# palabra forma términos que no niegan nada.
SEC_NEGADA  = re.compile(
    r"\bне\s|\bбез\s|информацион|исключ|not\s|out\s+of\s+scope|exclu", re.I)
RE_ENCABEZADO = re.compile(r"^(#{1,6})\s*(.+?)\s*$")


def scope_de_descripcion(descripcion):
    """
    Hosts declarados en la prosa, solo desde la sección de dominios del ámbito.

    Devuelve [] cuando no existe esa sección, que es el caso normal: este
    rescate no es un parser de la descripción, es una excepción acotada.
    """
    encabezados = []          # [(nivel, título)] vigentes sobre la línea actual
    dentro = False
    hosts = []
    for linea in (descripcion or "").splitlines():
        m = RE_ENCABEZADO.match(linea.strip())
        if m:
            nivel, titulo = len(m.group(1)), m.group(2)
            encabezados = [(n, t) for n, t in encabezados if n < nivel]
            encabezados.append((nivel, titulo))
            titulos = [t for _, t in encabezados]
            dentro = (any(SEC_AMBITO.search(t) for t in titulos)
                      and any(SEC_DOMINIO.search(t) for t in titulos)
                      and not any(SEC_NEGADA.search(t) for t in titulos))
            continue
        if not dentro:
            continue
        # Dentro de la sección buena los hosts llegan separados por comas o uno
        # por línea; RE_HOST los saca igual en ambos casos.
        limpia = RE_ENFASIS.sub(" ", RE_MD_LINK.sub(r" \1 ", linea))
        for mh in RE_HOST.finditer(limpia):
            ident = _limpiar_host(mh.group(0))
            if ident:
                hosts.append(ident)
    return hosts


def parsear_scope(entradas):
    """Las entradas del endpoint de scope -> lista de targets del feed."""
    vistos = set()
    salida = []
    for e in entradas or []:
        tipo = TIPOS.get(e.get("appTypeName"), "other")
        # `severity` es la severidad MÁXIMA admitida en ese asset (como el
        # `max_severity` de HackerOne), NO si paga o no: 21 programas tienen
        # todo su scope en `none` y son programas que pagan. Por eso no filtra
        # nada aquí; se guarda como dato del asset y ya.
        sev = e.get("severity") or None
        for linea in _lineas(e.get("scope")):
            for ident, tipo_final in _identificadores(linea, tipo):
                if not ident or ident in vistos:
                    continue
                if tipo_final == "other" and len(ident.split()) >= MAX_PALABRAS_OTHER:
                    continue      # nota en prosa, no un asset (ver MAX_PALABRAS_OTHER)
                vistos.add(ident)
                salida.append({
                    "target": ident,
                    "type": tipo_final,
                    "severity": sev,
                    # La línea de la que salió, para poder auditar una
                    # extracción rara sin volver a pedirla a la plataforma.
                    "description": linea if linea != ident else None,
                })
    return salida


def es_publicable(p):
    """
    ¿Este programa entra en el feed?

    `with_confirmation` queda fuera aunque el catálogo lo liste: hace falta que
    el programa te admita, y su scope no es legible sin eso (404). Es la misma
    línea que aplica `export_json.FILTRO_PUBLICABLE` con `acceso='invitacion'`.
    """
    return (p.get("status") == "published"
            and not p.get("finished")
            and p.get("visibility") == "public")


def barrer():
    """(programas, incidencias). Una petición al catálogo + una por programa."""
    cat = pedir(URL_LISTA)
    items = cat.get("items") if isinstance(cat, dict) else None
    if not isinstance(items, list):
        raise ValueError("el catálogo no trae 'items'")
    log.info(f"catálogo: {len(items)} programas")

    vivos = [p for p in items if es_publicable(p)]
    log.info(f"publicables: {len(vivos)}")

    programas, incidencias = [], []
    for i, p in enumerate(vivos, 1):
        slug = p.get("slug")
        try:
            entradas = pedir(URL_SCOPE.format(pid=p["id"]), intentos=2)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Sin scope legible no hay nada que vigilar ni que enumerar:
                # se deja fuera y se anota, en vez de publicarlo vacío.
                incidencias.append(f"{slug}: scope 404")
                log.warning(f"[{slug}] sin scope público (404) — se omite")
                time.sleep(PAUSA_PETICION)
                continue
            incidencias.append(f"{slug}: HTTP {e.code}")
            log.error(f"[{slug}] scope HTTP {e.code} — se omite")
            time.sleep(PAUSA_PETICION)
            continue
        except Exception as e:
            incidencias.append(f"{slug}: {e}")
            log.error(f"[{slug}] scope ilegible ({e}) — se omite")
            time.sleep(PAUSA_PETICION)
            continue

        in_scope = parsear_scope(entradas)
        # El disparador NO es "no hay assets", es "no hay ninguno enumerable".
        # VK rellena el scope estructurado con etiquetas de sección —`WEB`,
        # `Мобильные приложения`— que quedan como `other`: con la condición
        # ingenua el programa parecía tener scope y se perdían sus 14 dominios
        # reales, que están en la prosa (odnoklassniki_vk, vkontakte_vk).
        origen_prosa = False
        if not any(a["type"] != "other" for a in in_scope):
            rescatados = scope_de_descripcion(p.get("description"))
            if rescatados:
                origen_prosa = True
                # Los `other` que ya había se conservan: son declaraciones del
                # programa, aunque no se puedan enumerar.
                vistos = {a["target"] for a in in_scope}
                for h in rescatados:
                    if h in vistos:
                        continue
                    vistos.add(h)
                    in_scope.append({
                        "target": h,
                        "type": "wildcard" if h.startswith("*") else "website",
                        "severity": None,
                        "description": "sección «Домены» de la descripción",
                    })
                log.info(f"[{slug}] sin scope enumerable en el endpoint — "
                         f"{len(rescatados)} host(s) desde la descripción")

        rub = ((p.get("statistics") or {}).get("rewards") or {}).get("rub") or {}
        maxb = rub.get("max") or None
        minb = rub.get("min") or None
        logo = p.get("logo")

        programas.append({
            "slug": slug,
            "name": (p.get("name") or "").strip() or slug,
            "url": URL_PROG.format(slug=slug),
            # Ver LOGO_SIN_RUTA: identificador, no URL.
            "logo_url": None,
            "logo_id": logo,
            # En esta plataforma no hay programas sin recompensa: se llega aquí
            # solo con `visibility=public`, y el techo lo publica el catálogo.
            "offers_bounties": bool(maxb),
            "min_bounty": minb,
            "max_bounty": maxb,
            # Fecha de publicación REAL de la plataforma. Ninguna otra fuente
            # propia la da: con ella `sync.es_estreno_real` distingue un
            # estreno de una reaparición sin gastar una petición extra.
            "published_at": p.get("publishedAt") or p.get("createdAt"),
            "targets": {"in_scope": in_scope, "out_of_scope": []},
        })
        if i % 20 == 0:
            log.info(f"  {i}/{len(vivos)}...")
        time.sleep(PAUSA_PETICION)
    return programas, incidencias


def feed_anterior():
    try:
        return json.loads(FEED.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []


def sanity(programas, previo):
    """
    (ok, motivo). Rechaza un barrido flaco antes de promoverlo.

    Sin esto, media caída de la API se traduciría en bajas masivas:
    `sync.marcar_inactivos` cierra todo programa ausente del feed y sus
    informes desaparecerían de la web hasta el barrido siguiente.
    """
    n = len(programas)
    if n < MIN_PROGRAMAS:
        return False, f"solo {n} programas (mínimo {MIN_PROGRAMAS})"
    if previo and n < len(previo) * RATIO_MINIMO:
        return False, f"{n} programas frente a {len(previo)} del feed anterior"
    if not any(p["targets"]["in_scope"] for p in programas):
        return False, "ningún programa trae scope"
    return True, ""


def escribir(programas):
    """Escritura atómica: sync.py puede estar leyendo el feed justo ahora."""
    DIR_FEED.mkdir(parents=True, exist_ok=True)
    tmp = FEED.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(programas, ensure_ascii=False, indent=1), encoding="utf-8")
    os.replace(tmp, FEED)
    ESTADO.write_text(json.dumps({
        "generado_en": ahora(),
        "programas": len(programas),
        "assets": sum(len(p["targets"]["in_scope"]) for p in programas),
    }, ensure_ascii=False, indent=1), encoding="utf-8")


def leer_estado():
    try:
        return json.loads(ESTADO.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def resumen(programas):
    total = sum(len(p["targets"]["in_scope"]) for p in programas)
    print(f"programas: {len(programas)}  |  assets in-scope: {total}")
    for p in sorted(programas, key=lambda x: -(x["max_bounty"] or 0)):
        tipos = {}
        for a in p["targets"]["in_scope"]:
            tipos[a["type"]] = tipos.get(a["type"], 0) + 1
        detalle = " ".join(f"{k}:{v}" for k, v in sorted(tipos.items()))
        print(f"  {p['slug'][:24]:26} {(p['max_bounty'] or 0):>9,} RUB  "
              f"{len(p['targets']['in_scope']):>3} assets  {detalle}")


def main():
    ap = argparse.ArgumentParser(description="Genera el feed de Standoff 365")
    ap.add_argument("--simular", action="store_true",
                    help="barre y enseña el resultado, sin escribir nada")
    ap.add_argument("--estado", action="store_true",
                    help="qué feed hay guardado y de cuándo")
    args = ap.parse_args()

    if args.estado:
        est = leer_estado()
        if not est:
            print("sin feed guardado")
        else:
            print(json.dumps(est, ensure_ascii=False, indent=1))
        return

    programas, incidencias = barrer()
    if args.simular:
        resumen(programas)
        if incidencias:
            print(f"\nincidencias ({len(incidencias)}): {incidencias}")
        return

    ok, motivo = sanity(programas, feed_anterior())
    if not ok:
        log.error(f"barrido RECHAZADO ({motivo}) — se conserva el feed anterior")
        raise SystemExit(1)
    escribir(programas)
    log.info(f"feed escrito: {len(programas)} programas, "
             f"{sum(len(p['targets']['in_scope']) for p in programas)} assets"
             + (f" | {len(incidencias)} incidencia(s)" if incidencias else ""))


if __name__ == "__main__":
    main()
