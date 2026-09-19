#!/usr/bin/env python3
"""
tecnologias.py — qué tecnologías tiene un programa, en un único sitio.

Dos orígenes distintos que aquí se unifican:

  - El TIPO DE ASSET que publica la plataforma (`asset_type` en HackerOne,
    `type` en Intigriti y YesWeHack). Es gratis, ya está en la BD y tiene
    cobertura del 100%: si el programa mete un contrato inteligente en scope,
    lo dice el propio scope.
  - Los FLAGS sondeados por los `enrich*.py` (`tiene_graphql`, `tiene_api`…),
    que exigen tocar el objetivo y solo cubren lo que se haya sondeado.

Se devuelven identificadores, no nombres: el nombre visible depende del idioma
del que mira, y el icono se elige por id. Traducciones en `web/i18n/*.json`
bajo la clave `tec_<id>`.
"""
import json
import re

# Vocabulario de tipos de asset por plataforma. Las siete están aquí a
# propósito: la que falte no da error, simplemente no enciende ninguna
# tecnología del scope, y eso no se nota hasta que alguien mira un informe suyo
# (le pasó a federacy y gobugfree entre el 16 y el 19 de agosto de 2026, y a
# standoff hasta el 19 de septiembre).
CLAVE_TIPO = {
    "hackerone": "asset_type",
    "intigriti": "type",
    "yeswehack": "type",
    "bugcrowd":  "type",
    "federacy":  "type",
    "gobugfree": "type",
    "standoff":  "type",
}

# id -> tipos de asset que lo declaran. Un mismo id puede venir de varias
# plataformas con nombres distintos: aquí es donde se reconcilian.
POR_TIPO_ASSET = {
    "android":       {"google_play_app_id", "other_apk", "android",
                      "mobile-application-android"},
    "ios":           {"apple_store_app_id", "other_ipa", "testflight", "ios",
                      "mobile-application-ios"},
    "api":           {"api"},
    "codigo_fuente": {"source_code", "open-source"},
    "escritorio":    {"downloadable_executables", "windows_app_store_app_id",
                      "desktop"},
    "hardware":      {"hardware", "device", "iot"},
    "infra_ip":      {"cidr", "iprange", "ip_address", "network"},
    "blockchain":    {"smart_contract"},
    "ia":            {"ai_model"},
}

# id -> columna de la BD que lo enciende (detectores de enrich*.py).
POR_FLAG = {
    "graphql":  "tiene_graphql",
    "api":      "tiene_api",
    "api_docs": "tiene_api_docs",
    "oauth":    "tiene_oauth",
    "pagos":    "tiene_pagos",
    "spa":      "tiene_spa",
    "android":  "tiene_android",
    "ios":      "tiene_ios",
}

# Orden estable de presentación: lo que más condiciona por dónde se ataca va
# primero (interfaces y autenticación), después la plataforma del objetivo.
# Sin esto el orden dependería de un set y bailaría entre informes.
ORDEN = [
    "graphql", "api", "api_docs", "oauth", "pagos", "spa",
    "blockchain", "ia", "android", "ios",
    "escritorio", "codigo_fuente", "hardware", "infra_ip",
]


def desde_scope(scope_raw_in, plataforma):
    """Identificadores que declara el propio scope del programa."""
    clave = CLAVE_TIPO.get(plataforma)
    if not clave or not scope_raw_in:
        return set()
    try:
        items = json.loads(scope_raw_in)
    except (json.JSONDecodeError, TypeError):
        return set()
    tipos = {(a.get(clave) or "").strip().lower() for a in items if isinstance(a, dict)}
    return {tec for tec, marcas in POR_TIPO_ASSET.items() if tipos & marcas}


def desde_flags(fila):
    """Identificadores que encendieron los detectores. `fila` es un dict-like."""
    return {tec for tec, col in POR_FLAG.items() if fila.get(col) == 1}


def de_assets(scope_raw_in, plataforma, assets):
    """
    Identificadores de un SUBCONJUNTO de assets: los que anuncia un informe de
    "nuevo objetivo en el alcance".

    Ese informe habla del objetivo nuevo, no del programa (criterio del usuario,
    2026-08-19), así que sus chips salen del `asset_type` de los assets
    anunciados y **no** de los flags `tiene_*`: esos los sondean los `enrich*.py`
    sobre el programa entero y no dicen nada del asset nuevo — el informe 25
    (Amazon, objetivo `Vega OS`) encendía API por el flag y Android/iOS/Hardware
    por el resto del scope del programa.

    Un asset que ya no está en el scope (se retiró después del evento) no tiene
    tipo que consultar y se ignora, igual que uno que la plataforma no tipa.

    `assets` viene de `datos_json.assets`, o sea ya pasado por
    `sync.etiquetar_assets`, que a las apps móviles les cuelga " — Android" /
    " — iOS" para distinguir dos assets con el mismo bundle: se recorta para
    volver al identificador crudo con el que cruzar.
    """
    clave = CLAVE_TIPO.get(plataforma)
    if not clave or not scope_raw_in or not assets:
        return []
    try:
        items = json.loads(scope_raw_in)
    except (json.JSONDecodeError, TypeError):
        return []
    quiero = {str(a).split(" — ")[0].strip() for a in assets}
    tipos = set()
    for it in items:
        if not isinstance(it, dict):
            continue
        ident = (it.get("asset_identifier") or it.get("endpoint")
                 or it.get("target") or "")
        if ident.strip() in quiero:
            tipos.add((it.get(clave) or "").strip().lower())
    return [t for t in ORDEN if POR_TIPO_ASSET.get(t, set()) & tipos]


def de_programa(fila):
    """
    Lista ordenada de identificadores de un programa.

    `fila` necesita al menos: plataforma, scope_raw_in y las columnas `tiene_*`.
    """
    encontradas = desde_scope(fila.get("scope_raw_in"), fila.get("plataforma"))
    encontradas |= desde_flags(fila)
    return [t for t in ORDEN if t in encontradas]


# --- Stack detectado por el recon (httpx/Wappalyzer) --------------------------
#
# httpx devuelve una lista plana de nombres ("React", "Next.js:14",
# "Google Analytics"…) sin decir cuáles son objetivo y cuáles ruido. Aquí se
# separa el grano de la paja para lo que se muestra en el informe.

# Ruido: cabeceras y transporte, analítica, gestores de consentimiento,
# captchas, CDN de librerías de terceros y frameworks de maquetación. No son
# objetivos —varios corren en infra de terceros, siempre fuera de scope— ni
# sirven para filtrar: nadie busca un programa por su Google Analytics. La
# lista es corta a propósito; crece a medida que el recon destape ruido nuevo.
RUIDO = {
    "hsts", "http/2", "http/3",
    "google analytics", "google tag manager", "google hosted libraries",
    "jquery cdn",
    "onetrust", "hcaptcha", "recaptcha",
    "webpack", "bootstrap",
}

# CDN y WAF de terceros. No son ruido —saber que un activo está detrás de
# Cloudflare cambia cómo se ataca— pero tampoco son el stack del objetivo: se
# muestran aparte, por host, en su propia columna. Solo entran aquí los que
# httpx reconoce como CDN (rellenan `cdn_name`), para que sacarlos del stack no
# pierda el dato: sale de un sitio y aparece en el otro.
#
# Deliberadamente FUERA: Envoy, Tengine, Nginx, BIG-IP y demás proxies que
# corren en la infra del propio objetivo. Son superficie suya, no de un tercero.
CDN_WAF = {
    "cloudflare", "cloudflare bot management",
    "akamai", "akamai bot manager",
    "fastly", "amazon cloudfront", "cloudfront",
    "google cloud cdn", "azure front door",
    "sucuri", "incapsula", "imperva", "stackpath",
    "cdn77", "keycdn", "bunnycdn", "edgecast",
}

# Una "versión" que en realidad es un hash largo (integrity, id de build) no
# informa de nada: se descarta y queda solo el nombre.
_HASH = re.compile(r"^[0-9a-f]{12,}$", re.I)


def nombre_base(tech):
    """'jQuery:1.8.3' -> 'jQuery'. Lo que sirve para agrupar y filtrar."""
    return tech.split(":", 1)[0].strip()


def _con_version(tech):
    """Normaliza 'Nombre:version' y tira las versiones-basura (hashes)."""
    nombre = nombre_base(tech)
    if ":" not in tech:
        return nombre
    version = tech.split(":", 1)[1].strip()
    if not version or _HASH.match(version) or len(version) > 16:
        return nombre
    return f"{nombre}:{version}"


def es_ruido(tech):
    n = nombre_base(tech).lower()
    return n in RUIDO or n in CDN_WAF


def waf_de_tech(techs):
    """
    El CDN/WAF que se deduce de la lista de tecnologías, si lo hay.

    Respaldo para los servicios sondeados antes de que la capa 2 capturase
    `cdn_name`: sin esto, sacar Cloudflare del stack lo haría desaparecer de un
    informe viejo hasta que se reejecute su recon. Lo que dice httpx en `cdn`
    manda; esto solo habla cuando aquello viene vacío.
    """
    for t in techs:
        n = nombre_base(t or "").lower()
        if n in CDN_WAF:
            return nombre_base(t).strip()
    return None


# PÁGINAS POR DEFECTO: cuando el título ES el nombre del producto
#
# Wappalyzer (el detector que lleva httpx) reconoce aplicaciones web, no
# servidores que aún no sirven ninguna: `apix.vodafone.om` responde 200 con
# "Welcome to WildFly" y httpx devuelve `tech: null` — comprobado en vivo el
# 2026-08-19. La página gritaba el nombre del servidor de aplicaciones y el
# stack del informe salía vacío.
#
# La regla para entrar aquí es estricta: el texto solo puede ser la PORTADA POR
# DEFECTO de un producto, esa que aparece cuando alguien lo instala y no llega
# a configurarlo. Un mensaje de error genérico NO entra aunque sea típico de un
# producto ("403 - Forbidden: Access is denied." suena a IIS, pero cualquiera
# puede escribir eso en cualquier servidor): deducir de ahí sería inventar.
#
# Que estas páginas sigan en pie es además una señal en sí misma —instalación
# reciente o abandonada—, no solo un dato de stack.
HUELLAS_PAGINA = (
    ("welcome to wildfly",                "WildFly"),
    ("welcome to jboss",                  "JBoss"),
    ("welcome to nginx",                  "Nginx"),
    ("welcome to openresty",              "OpenResty"),
    ("welcome to jetty",                  "Jetty"),
    ("apache2 ubuntu default page",       "Apache"),
    ("apache2 debian default page",       "Apache"),
    ("apache http server test page",      "Apache"),
    ("test page for the apache http server", "Apache"),
    ("apache tomcat",                     "Tomcat"),
    ("welcome to tomcat",                 "Tomcat"),
    ("iis windows server",                "IIS"),
    ("glassfish server",                  "GlassFish"),
    ("welcome to caddy",                  "Caddy"),
    ("phpmyadmin",                        "phpMyAdmin"),
    ("rabbitmq management",               "RabbitMQ"),
    ("minio console",                     "MinIO"),
    ("portainer",                         "Portainer"),
    ("swagger ui",                        "Swagger UI"),
    # Añadido tras ver el título literal en la BD (2 hosts): es el nombre de la
    # UI del producto, no un mensaje de error.
    ("argo cd",                           "Argo CD"),
)


def tec_de_pagina(title):
    """
    Tecnologías que se deducen del título cuando ES la portada por defecto de un
    producto. Devuelve lista (vacía casi siempre): solo habla ante coincidencia
    literal con `HUELLAS_PAGINA`, nunca por parecido.
    """
    t = (title or "").lower()
    if not t:
        return []
    return [nombre for patron, nombre in HUELLAS_PAGINA if patron in t]


def limpiar_stack(techs):
    """
    Quita el ruido, normaliza versiones y deduplica por nombre.

    Si una tecnología llega con y sin versión ('jQuery' y 'jQuery:1.8.3'), gana
    la que trae versión: es lo que convierte "tiene jQuery" en un CVE concreto.
    """
    mejor = {}
    for t in techs:
        t = (t or "").strip()
        if not t or es_ruido(t):
            continue
        norm = _con_version(t)
        clave = nombre_base(norm).lower()
        if clave not in mejor or (":" in norm and ":" not in mejor[clave]):
            mejor[clave] = norm
    return sorted(mejor.values(), key=lambda s: s.lower())
