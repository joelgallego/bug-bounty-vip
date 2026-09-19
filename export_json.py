#!/usr/bin/env python3
"""
export_json.py — genera los JSON que sirve la web y (opcionalmente) los publica.

La web no tiene backend: solo sirve estos dos ficheros ya generados.

  informes.json  — el feed. Todos los informes publicados, más recientes
                   primero. Se regenera entero en cada publicación: a este
                   volumen pesa poco y Cloudflare comprime en tránsito. Un
                   informe puede cambiar después de publicado (el recon lo
                   enriquece), así que exportar "lo pendiente" no valdría:
                   se exporta el estado actual completo.
  programas.json — alimenta el buscador facetado.

Uso:
    python3 export_json.py             # solo genera los ficheros
    python3 export_json.py --deploy    # genera y publica en Cloudflare
"""
import argparse
import json
import sqlite3
import subprocess
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import recon_scope
import tecnologias

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta. La web es su hermana.
BASE     = Path(__file__).resolve().parent
WEB_DIR  = BASE.parent / "web"
DB_PATH  = str(BASE / "programas.db")
DEPLOY   = WEB_DIR / "deploy.py"

# Tope de seguridad: si el feed crece hasta aquí, toca revisar la decisión de
# servir un único fichero (la vía de escape ya identificada es Cloudflare D1).
AVISO_TAMANO_MB = 4

# QUÉ SE PUEDE PUBLICAR Y QUÉ NO (criterio del usuario, 2026-08-16)
#
# La línea no es "¿hace falta cuenta?" sino **"¿puede cualquiera acceder?"**:
#
#   - Si cualquiera puede registrarse y verlo, es información pública aunque
#     esté detrás de un login o de una verificación de identidad. Se publica.
#   - Si hace falta que te INVITEN, es información privada: te la confiaron a
#     ti. No se publica, por mucho que nuestra sesión pueda leerla.
#
# Se filtra aquí, en el export, y no al ingerir: así los programas por
# invitación se vigilan igual (alertas, informes y recon en local, que es su
# valor real) sin que puedan acabar en la web por descuido. Es una garantía
# estructural, no una convención que haya que recordar en cada cambio.
ACCESO_NO_PUBLICABLE = ("invitacion",)
FILTRO_PUBLICABLE = (
    "(acceso IS NULL OR acceso NOT IN ("
    + ",".join(f"'{a}'" for a in ACCESO_NO_PUBLICABLE) + "))"
)


def tecnologias_por_programa(con):
    """
    id de programa -> (identificadores de tecnología, stack detectado).

    Se calcula al exportar y no se lee lo que se guardó en `datos_json` cuando
    nació el informe: así, si mañana se añade un detector o se afina el mapeo
    de tipos de asset, los informes viejos se benefician sin tocar la BD.
    """
    cur = con.execute(
        """SELECT id, plataforma, scope_raw_in, stack_detectado,
                  tiene_graphql, tiene_api, tiene_android, tiene_ios
           FROM programas"""
    )
    columnas = [d[0] for d in cur.description]
    out = {}
    for fila in cur.fetchall():
        f = dict(zip(columnas, fila))
        stack = [s.strip() for s in (f.get("stack_detectado") or "").split(",") if s.strip()]
        out[f["id"]] = (tecnologias.de_programa(f), stack)
    return out


def subdominios_in_scope(con, programa_id):
    """
    Conjunto de subdominios `in_scope=1` de un programa, según la BD.

    Se lee al exportar y no de lo materializado en el informe: el scope es la
    verdad viva (un wildcard nuevo puede meter en scope hosts ya descubiertos),
    igual que con las tecnologías. Sin programa (informe huérfano) → set vacío,
    y entonces todo se trata como colateral, que es lo prudente.
    """
    if not programa_id:
        return set()
    filas = con.execute(
        """SELECT s.subdominio
           FROM subdominios s
           JOIN programa_subdominio ps ON ps.subdominio_id = s.id
           WHERE ps.programa_id = ? AND ps.in_scope = 1""",
        (programa_id,),
    ).fetchall()
    return {f[0] for f in filas}


def _host_de_asset(a):
    """'https://api.toom.de/x' -> 'api.toom.de'. Para cruzar assets con subs."""
    a = str(a).strip().lower()
    if "://" in a:
        a = a.split("://", 1)[1]
    a = a.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
    return a.lstrip("*.").strip(".")


def patrones_sin_bounty(scope_raw_in):
    """
    Patrones de los assets que el programa acepta pero NO paga.

    Intigriti los marca con `impact: "No Bounty"` (el único feed que publica el
    dato por asset, junto al `eligible_for_bounty` de HackerOne). Siguen EN
    SCOPE —se puede reportar ahí— pero conviene que se vea, porque un objetivo
    que no paga no es lo mismo que uno que sí: sin la marca, `gammacademy.be`
    se leía en el informe de Intergamma igual que un Tier 1.
    """
    try:
        items = json.loads(scope_raw_in) if scope_raw_in else []
    except (TypeError, json.JSONDecodeError):
        return []
    fuera = []
    for a in items:
        if str(a.get("impact") or "").strip().lower() != "no bounty":
            continue
        ident = str(a.get("endpoint") or a.get("target")
                    or a.get("asset_identifier") or a.get("identifier") or "").strip()
        bruto = recon_scope._host_bruto(ident) if ident else None
        if bruto:
            fuera.append(bruto.lower())
    return fuera


def marca_sin_bounty(host, patrones):
    """Cierto si el host cae bajo un asset que no paga."""
    h = (host or "").lower()
    for p in patrones:
        if "*" in p:
            apex = p.replace("*.", "").replace("*", "")
            if fnmatchcase(h, p) or (apex and (h == apex or h.endswith("." + apex))):
                return True
        elif h == p or h.endswith("." + p):
            return True
    return False


def marcar_scope(datos, en_scope):
    """
    Reparte los subdominios del recon en dentro / fuera de scope.

    Antes se quitan los que ya se muestran arriba como "objetivos nuevos en el
    alcance" (los assets del evento): esos no son un descubrimiento del recon,
    y listarlos otra vez aquí los duplica. Un asset con wildcard (`*.test.com`)
    no filtra a sus hijos (`mail.test.com`): solo desaparece la coincidencia
    exacta de host, que es la que sí está repetida.

    Lo que queda fuera de scope no es superficie del programa —lo capta la
    enumeración pasiva pero el propio programa no lo cubre—; se marca, no se
    tira (un env de staging expuesto puede ser la joya) y la web lo enseña
    aparte. Los conteos van al `resumen`, que es lo que el frontend pinta sin
    desplegar la lista.
    """
    recon = datos.get("recon")
    if not isinstance(recon, dict):
        return
    subs = recon.get("subdominios_nuevos")
    if not isinstance(subs, list):
        return
    sin_pago = datos.pop("_sin_bounty", []) or []
    assets_host = {_host_de_asset(a) for a in (datos.get("assets") or [])}
    subs = [s for s in subs if (s.get("subdominio") or "").lower() not in assets_host]
    recon["subdominios_nuevos"] = subs
    n_scope = 0
    for s in subs:
        dentro = s.get("subdominio") in en_scope
        s["in_scope"] = 1 if dentro else 0
        if dentro and sin_pago and marca_sin_bounty(s.get("subdominio"), sin_pago):
            s["sin_bounty"] = True
        n_scope += dentro
    if isinstance(datos.get("resumen"), dict):
        datos["resumen"]["subdominios_nuevos"] = len(subs)
        datos["resumen"]["subdominios_scope"] = n_scope
        datos["resumen"]["subdominios_colaterales"] = len(subs) - n_scope


# NOMBRE DEL SERVICIO: qué se puede normalizar sin mentir
#
# `capa3` parsea el formato GREPPABLE de nmap (`-oG`), que aplana en un solo
# string cosas que en el XML van separadas: el nombre, el túnel (`tunnel="ssl"`
# → prefijo `ssl|`) y si el servicio está confirmado o solo deducido del número
# de puerto (`method="table"` → sufijo `?`).
#
# Por eso la normalización es un mapa EXPLÍCITO y no una regla general del tipo
# "quitar todo lo que hay antes de la tubería". Lo que esa regla rompería
# (medido sobre el feed del 2026-08-19):
#   - `ssl|http-proxy` (×3): un proxy HTTP NO es un servidor web. Aplanarlo a
#     "https" borra justo lo que hace interesante ese puerto (proxy abierto,
#     CONNECT, SSRF).
#   - `ssl|https?`     (×23): el `?` es la marca de que nmap NO lo comprobó.
#     Quitarlo vendería una conjetura como un hecho. Se conserva.
#   - `tcpwrapped`     (×19): no es un servicio, es "abrió y cerró sin hablar".
#   - `ssl|https-alt`  (×3): "alt" solo significa puerto no estándar, y eso ya
#     lo dice la columna Puerto — pero no es asunto nuestro reescribirlo.
# Todo lo que no esté en el mapa se pinta tal cual lo dijo nmap.
SERVICIO_NORMALIZADO = {
    "ssl|http":   "https",     # HTTP dentro de TLS: eso es https, sin más
    "ssl|https":  "https",     # redundancia del propio nmap
    "ssl|https?": "https?",    # se quita el túnel, se CONSERVA la conjetura
}


def limpiar_servicios(recon):
    """
    Deja cada servicio listo para pintarse como fila de tabla.

    `tech` llega de httpx como CSV crudo (con su ruido y sus hashes) y sale como
    lista ya limpia; el CDN/WAF se separa a su propio campo porque no es stack
    del objetivo. Se hace al exportar y no al guardar: así afinar el filtro
    mejora también los informes ya publicados, sin tocar la BD.
    """
    for s in recon.get("servicios_nuevos", []):
        crudo = s.get("tech")
        techs = ([t.strip() for t in crudo.split(",") if t.strip()]
                 if isinstance(crudo, str) else list(crudo or []))
        s["tech"] = tecnologias.limpiar_stack(
            techs + tecnologias.tec_de_pagina(s.get("title")))
        s["cdn"] = s.get("cdn") or tecnologias.waf_de_tech(techs)
        s["servicio"] = SERVICIO_NORMALIZADO.get(s.get("servicio"), s.get("servicio"))


def _tiene_ruta(texto):
    """Cierto si el asset apunta DENTRO de un host (`host/algo`), no al host."""
    cuerpo = texto.split("://", 1)[-1].strip()
    _, sep, ruta = cuerpo.partition("/")
    return bool(sep) and ruta.strip(" /") not in ("", "*")


def assets_retirados(assets, plataforma, scope_in, scope_out):
    """
    Cuáles de los objetivos que anuncia el informe YA NO están en el scope.

    Un asset retirado no es solo información caduca: tocarlo ha dejado de estar
    autorizado. Caso real: `*.telenorcdn.net` entró en Telenor el 18-ago y salió
    dos horas después, y su informe seguía publicando 141 subdominios como si
    fueran objetivo. Se comprueba en cada export y no se escribe en la BD, así
    que si el asset vuelve al scope el informe se recupera solo.

    Vigente = el identificador sigue listado igual, o el scope de ahora lo
    cubre (un host bajo un wildcard vigente cuenta como vigente). De un patrón
    con comodín se prueba una instancia concreta.
    """
    if not assets:
        return []
    try:
        cls = recon_scope.clasificar(scope_in, scope_out, plataforma)
    except Exception:
        return []          # sin scope legible no se afirma nada
    literales = set()
    for a in json.loads(scope_in or "[]"):
        ident = str(a.get("target") or a.get("endpoint") or a.get("asset_identifier")
                    or a.get("identifier") or "").strip().lower()
        if ident:
            literales.add(ident)
    fuera = []
    for a in assets:
        base = str(a).split(" — ")[0].strip()
        if not base or base.lower() in literales:
            continue
        bruto = recon_scope._host_bruto(base)
        if not bruto:
            continue           # apps, repos, texto libre: no se juzgan aquí
        prueba = bruto.replace("*", "zzq7x4no") if "*" in bruto else bruto
        if recon_scope.clasificar_sub(prueba, cls)[0] != 1:
            fuera.append(a)
    return fuera


def alcance_del_evento(assets):
    """
    Qué parte de la superficie del programa habla de los objetivos ANUNCIADOS.

    Un informe de "nuevo objetivo en el alcance" cubre el objetivo nuevo, no el
    programa entero: sus hosts directos y lo colateral que cuelga de ellos —
    incluido lo que un wildcard nuevo acaba de meter in-scope y ya estaba
    guardado en la BD de barridos anteriores (criterio del usuario, 2026-08-19).

    Devuelve un predicado `pertenece(host) -> bool`. Si el evento no trae
    ningún asset DNS del scope (assets de app, repo, hardware o texto libre) el
    predicado no acepta nada: no hay superficie que enseñar y el informe se
    queda con la lista de objetivos, que es toda la noticia. Caso real: el
    informe 12 (Exodus) anunciaba contratos de Solana, repos y paquetes npm y
    enseñaba 333 subdominios del programa que no tenían que ver con ellos.

    Un asset se descarta si su apex está en `recon_scope.TERCEROS`: sin eso, un
    asset como `https://github.com/acme/*` arrastraría a github.com. NO se
    cruza contra el scope vigente del programa, aunque sería el filtro más
    estrecho: un informe cuenta lo que pasó el día del evento y el asset puede
    haberse retirado después (caso real: `*.telenorcdn.net` entró el 18-ago en
    Telenor y salió del scope dos horas más tarde; cruzar contra el scope de
    hoy dejaba su informe sin los 141 subdominios que sí encontró entonces).
    """
    patrones, hosts = set(), set()
    for a in assets or []:
        texto = str(a).strip()
        if not texto:
            continue
        bruto = recon_scope._host_bruto(texto)
        if not bruto:
            continue
        if "*" in bruto:
            # El comodín acota la rama y además vale como patrón exacto:
            # `static*.twilio.com` casa `static1.twilio.com`, no `dev.twilio.com`.
            apex = recon_scope._apex(bruto.replace("*.", "").replace("*", ""))
            if not apex or apex in recon_scope.TERCEROS:
                continue
            patrones.add(bruto)
            if bruto == f"*.{apex}":
                hosts.add(apex)      # `*.acme.com` mete también el apex
            continue
        host = recon_scope._host(texto)
        if not host or recon_scope._apex(host) in recon_scope.TERCEROS:
            continue
        hosts.add(host)
    if not patrones and not hosts:
        return lambda h: False

    def pertenece(h):
        h = (h or "").lower()
        if any(h == x or h.endswith("." + x) for x in hosts):
            return True
        return any(fnmatchcase(h, p) for p in patrones)

    return pertenece


def superficie_de_bd(con, programa_id, pertenece=None):
    """
    Superficie IN-SCOPE viva del programa leída de la BD — lo que el informe
    muestra. NO el delta acumulado en `datos_json.recon`.

    `pertenece` acota esa superficie a los objetivos que anuncia el informe
    (ver `alcance_del_evento`). Sin él se devuelve el programa entero, que es
    lo correcto para `programa_nuevo` y para el barrido periódico.

    Por qué (2026-08-17): `subdominios_nuevos` del delta solo contiene lo que
    cada job descubrió COMO nuevo. En un reproceso de un programa ya reconeado,
    los subdominios ya están en la BD, así que el delta queda casi vacío aunque
    la superficie sea grande (caso Threema: 272 in-scope vivos, el informe
    mostraba 42; los `safe-*`/`mediator-*` bajo wildcard no salían). Leyendo la
    superficie de la BD el informe refleja siempre lo que de verdad hay, y se
    arreglan de un golpe los reprocesos y los hijos de wildcard. Ver docs/web_informes.md
    → "El informe muestra superficie, no delta".

    Devuelve (subdominios, servicios) en el formato que espera la web: TODOS los
    subdominios VIVOS del programa (in-scope Y colaterales, con su marca
    `in_scope`), igual que mostraba el delta pero leído de la BD. La web ya los
    separa en "en scope" / "colaterales" y aplica su `CAP_LISTA`. Los muertos no
    entran: siguen en la BD para el diff, pero no son superficie.

    OJO: filtrar por `in_scope=1` vacía los programas cuya superficie es
    mayormente colateral (medido 2026-08-17: toom 855 vivos pero 2 in-scope,
    DECATHLON 398 vivos y 0 in-scope) — por eso se traen todos los vivos.
    """
    subs = [
        {"subdominio": r[0], "origen": r[1], "ip": r[2], "cname": r[3],
         "vivo": r[4], "in_scope": r[5]}
        for r in con.execute(
            """SELECT s.subdominio, s.origen, s.ip, s.cname, s.vivo, ps.in_scope
               FROM subdominios s
               JOIN programa_subdominio ps ON ps.subdominio_id = s.id
               WHERE ps.programa_id = ? AND s.vivo = 1
               ORDER BY ps.in_scope DESC, s.subdominio""",
            (programa_id,),
        )
    ]
    # `sondeado` viaja como booleano y no como fecha: la web solo necesita
    # saber si el silencio de un servicio es "no lo hemos mirado" o "lo miramos
    # y no contestó" (ver backfill_httpx.py). La fecha exacta queda en la BD.
    servicios = [
        {"host": r[0], "puerto": r[1], "protocolo": r[2], "servicio": r[3],
         "version": r[4], "status": r[5], "title": r[6], "tech": r[7],
         "server": r[8], "cdn": r[9], "sondeado": bool(r[10])}
        for r in con.execute(
            """SELECT s.subdominio, sv.puerto, sv.protocolo, sv.servicio, sv.version,
                      sv.status, sv.title, sv.tech, sv.server, sv.cdn, sv.ts_sondeo
               FROM servicios sv
               JOIN subdominios s ON s.id = sv.subdominio_id
               JOIN programa_subdominio ps ON ps.subdominio_id = s.id
               WHERE ps.programa_id = ? AND s.vivo = 1
               ORDER BY s.subdominio, sv.puerto""",
            (programa_id,),
        )
    ]
    if pertenece is not None:
        subs      = [s for s in subs      if pertenece(s["subdominio"])]
        servicios = [s for s in servicios if pertenece(s["host"])]
    return subs, servicios


# La web (index.html) solo pinta CAP_WEB por lista (su CAP_LISTA=300) y avisa si
# hay más. Enviar más al JSON es peso muerto que nadie ve (MoonPay: 4592 subs
# para 300 mostrados; el JSON pasaba de 1,5 a 2,4 MB). Se recorta aquí, alineado
# con lo que la web renderiza (300 in-scope + 300 colaterales), pero el `resumen`
# conserva el TOTAL real (lo calculó marcar_scope antes), así que la web sigue
# diciendo "300 de 4592" — de ahí que su aviso de truncado lea el resumen, no la
# longitud de la lista.
CAP_WEB = 100

# Lo que el recorte deja fuera no se pierde: se vuelca a un fichero de texto por
# informe y sección en `web/listas/`, y la web enlaza a él. Es la única forma de
# dar la lista entera sin que la pague quien no la pide: el JSON lo descarga
# todo el mundo en cada visita, un asset suelto solo quien hace clic (MoonPay
# son 256 KB él solo). Texto plano y sin cabeceras a propósito: se pega directo
# en httpx/nuclei. Solo se escribe la sección que de verdad se recorta; la URL
# es determinista, así que la web deduce el enlace del total sin dato extra.
LISTAS_DIR = WEB_DIR / "listas"


def _tsv(v):
    """Una celda de TSV no puede llevar tabuladores ni saltos: los come."""
    return str(v if v is not None else "").replace("\t", " ").replace("\n", " ").strip()


def _escribir_lista(nombre, lineas):
    LISTAS_DIR.mkdir(exist_ok=True)
    (LISTAS_DIR / nombre).write_text("\n".join(lineas) + "\n", encoding="utf-8")
    return nombre


def volcar_listas(informe_id, recon):
    """Escribe las listas completas de este informe. Devuelve los ficheros creados."""
    escritos = set()
    subs = recon.get("subdominios_nuevos") or []
    for clave, sufijo in (("scope", "scope"), ("colateral", "colateral")):
        trozo = [s for s in subs
                 if bool(s.get("in_scope")) == (clave == "scope")]
        if len(trozo) > CAP_WEB:
            escritos.add(_escribir_lista(f"{informe_id}-{sufijo}.txt",
                                         [s["subdominio"] for s in trozo]))
    srv = recon.get("servicios_nuevos") or []
    if len(srv) > CAP_WEB:
        cols = ("host", "puerto", "protocolo", "servicio", "version",
                "status", "title", "tech", "server", "cdn")
        filas = ["\t".join(cols)]
        for s in srv:
            tech = s.get("tech")
            fila = dict(s, tech=", ".join(tech) if isinstance(tech, list) else tech)
            filas.append("\t".join(_tsv(fila.get(c)) for c in cols))
        escritos.add(_escribir_lista(f"{informe_id}-servicios.tsv", filas))
    return escritos


def limpiar_listas(vigentes):
    """Un informe que encoge (o que se despublica) deja su fichero huérfano, y
    el deploy lo subiría igual. Se barre lo que ya no toca."""
    if not LISTAS_DIR.is_dir():
        return
    for f in LISTAS_DIR.iterdir():
        if f.name not in vigentes:
            f.unlink()


def _recortar_para_web(recon):
    subs = recon.get("subdominios_nuevos") or []
    if len(subs) > CAP_WEB:
        en_scope = [s for s in subs if s.get("in_scope")][:CAP_WEB]
        colat    = [s for s in subs if not s.get("in_scope")][:CAP_WEB]
        recon["subdominios_nuevos"] = en_scope + colat
    srv = recon.get("servicios_nuevos") or []
    if len(srv) > CAP_WEB:
        recon["servicios_nuevos"] = srv[:CAP_WEB]


# Códigos de permiso (neutros de idioma) que la web pinta como chips, en orden
# de severidad. El export los emite; el frontend elige etiqueta y color por
# idioma, igual que con las tecnologías. Un permiso que borra o administra el
# Jira ajeno es donde un fallo de control de acceso más duele; act-as-user
# (suplantar al usuario) y el acceso a emails van también arriba.
_PERM_ORDEN = ("borra", "admin", "suplanta", "email", "config", "escribe")


def _cat_permiso(p):
    p = (p or "").lower()
    if "delete" in p:
        return "borra"
    if "admin" in p:
        return "admin"
    if "act-as-user" in p or "act_as_user" in p:
        return "suplanta"
    if "access-email" in p or "access_email" in p:
        return "email"
    if p.startswith("manage") or ":manage" in p or "manage:" in p:
        return "config"
    if p.startswith("write") or ":write" in p or "write:" in p:
        return "escribe"
    return None


# Tope de apps por informe en el JSON: acota el peso (Atlassian-Built Apps son
# 136) sin perder el recuento real, que viaja aparte para el "+N" de la web.
CAP_APPS = 80


def apps_de_programa(con, programa_id):
    """
    Ficha compacta de las apps de Marketplace de un programa (tabla
    `apps_marketplace` vía `programa_app`), para los ~70 programas de Bugcrowd
    cuyo scope es un enlace de tienda. Se lee al exportar, como todo lo demás,
    para reflejar la resolución más reciente. Devuelve None si el programa no
    tiene apps. Las apps se ordenan por interés: primero las que tienen host
    propio (Connect, superficie escaneable), luego por número de permisos.
    """
    if not programa_id:
        return None
    filas = con.execute(
        """SELECT am.nombre, am.app_id, am.connect, am.bounty_cloud,
                  am.cloud_fortified, am.n_permisos, am.permisos_json,
                  am.host, am.resuelto
           FROM apps_marketplace am
           JOIN programa_app pa ON pa.app_id = am.app_id
           WHERE pa.programa_id = ?""",
        (programa_id,),
    ).fetchall()
    if not filas:
        return None
    apps = []
    for nombre, app_id, connect, bounty, fortified, nperm, perms_json, host, resuelto in filas:
        try:
            perms = json.loads(perms_json) if perms_json else []
        except json.JSONDecodeError:
            perms = []
        cats = [c for c in _PERM_ORDEN if c in {_cat_permiso(p) for p in perms}]
        apps.append({
            "nombre": nombre or f"App {app_id}",
            "id": app_id,
            "connect": bool(connect),
            "bounty": bounty,                       # approved | not-a-participant | None
            "fortified": fortified == "approved",
            "n_permisos": nperm or 0,
            "peligros": cats,
            "host": host,
            "resuelto": bool(resuelto),
        })
    apps.sort(key=lambda a: (a["host"] is None, -a["n_permisos"], a["nombre"].lower()))
    total = len(apps)
    con_host = sum(1 for a in apps if a["host"])
    return {"apps": apps[:CAP_APPS], "total": total, "con_host": con_host}


def exportar_informes(con, tecs):
    # El icono se trae con JOIN y no se resuelve en el navegador cruzando con
    # programas.json: ese export solo lleva los activos que pagan, y un informe
    # puede hablar de un programa que ya no cumpla ninguna de las dos cosas.
    filas = con.execute(
        """SELECT i.id, i.timestamp, i.ts_barrido_anterior, i.plataforma, i.programa_id,
                  i.programa_nombre, i.tipo, i.titulo, i.cuerpo, i.datos_json,
                  i.url_programa, i.relevancia, i.es_rareza, i.origen,
                  i.fecha_enriquecido, p.icono
           FROM informes i
           LEFT JOIN programas p ON p.id = i.programa_id
           WHERE i.publicado = 1
             AND (p.acceso IS NULL OR p.acceso NOT IN ('invitacion'))
           ORDER BY i.timestamp DESC"""
    ).fetchall()

    out = []
    listas = set()          # ficheros de `web/listas/` que siguen haciendo falta
    for f in filas:
        try:
            datos = json.loads(f[9]) if f[9] else {}
        except json.JSONDecodeError:
            datos = {}
        # El informe muestra la SUPERFICIE in-scope viva actual, leída de la BD,
        # no el delta acumulado en datos_json (que un reproceso deja casi vacío
        # aunque la superficie sea grande). Ver superficie_de_bd(). Los takeovers
        # y errores del pase sí se conservan de datos_json.
        #
        # Un `scope_ampliado` la acota a los objetivos que anuncia: la noticia es
        # el objetivo nuevo, no el programa entero (ver alcance_del_evento).
        # Objetivos que ya NO están en el scope: si no queda ninguno vigente el
        # informe se retira de la web —anuncia terreno donde ya no se puede
        # entrar—, y si quedan, los caídos se marcan uno a uno. Se decide en
        # cada export y no en la BD, así que un asset que vuelva al scope
        # recupera su informe solo (ver `assets_retirados`).
        if f[6] == "scope_ampliado" and (datos.get("assets") or []):
            fila_sc = con.execute(
                "SELECT plataforma, scope_raw_in, scope_raw_out FROM programas WHERE id=?",
                (f[4],)).fetchone()
            if fila_sc:
                caidos = assets_retirados(datos.get("assets"), fila_sc[0],
                                          fila_sc[1], fila_sc[2])
                if caidos and len(caidos) == len(datos.get("assets") or []):
                    continue
                if caidos:
                    datos["assets_retirados"] = caidos

        recon = datos.get("recon")
        tech_servicios = []
        if isinstance(recon, dict):
            alcance = (alcance_del_evento(datos.get("assets"))
                       if f[6] == "scope_ampliado" else None)
            subs_bd, srv_bd = superficie_de_bd(con, f[4], alcance)
            # Un servicio describe el HOST (puerto, código, título), así que no
            # dice nada de un asset que apunta dentro de él: el informe de
            # Infomaniak anunciaba `manager.infomaniak.com/*proxy*` y enseñaba
            # "manager.infomaniak.com:443 → 200", que ni es el objetivo ni es
            # nuevo (el host ya estaba en scope por otro asset con ruta). Qué
            # selecciona ese patrón exige conocer la aplicación y no se
            # interpreta aquí: mejor no enseñar nada que enseñar algo a medias,
            # que induce a error a quien lee la web. Los servicios se acotan a
            # los assets que SÍ apuntan a un host; los subdominios no, que ahí
            # el host sigue siendo la rama donde buscar.
            if alcance is not None:
                al_host = alcance_del_evento(
                    [a for a in (datos.get("assets") or [])
                     if not _tiene_ruta(str(a))])
                srv_bd = [s for s in srv_bd if al_host(s.get("host"))]
            recon["subdominios_nuevos"] = subs_bd
            recon["servicios_nuevos"] = srv_bd
            if alcance is not None:
                # Los takeovers vienen del pase, no de la BD, así que hay que
                # acotarlos igual: el informe 9 (Varonis) anunciaba cuatro hosts
                # y colgaba dos takeovers de otras ramas del programa.
                recon["takeovers"] = [t for t in (recon.get("takeovers") or [])
                                      if alcance(t.get("subdominio"))]
            if isinstance(datos.get("resumen"), dict):
                datos["resumen"]["subdominios_nuevos"] = len(subs_bd)
                datos["resumen"]["servicios_nuevos"] = len(srv_bd)
                datos["resumen"]["takeovers"] = len(recon.get("takeovers") or [])
            # Los assets que el programa acepta pero no paga se marcan, no se
            # ocultan: siguen en scope (ver `patrones_sin_bounty`).
            fila_sb = con.execute(
                "SELECT scope_raw_in FROM programas WHERE id=?", (f[4],)).fetchone()
            pats_sb = patrones_sin_bounty(fila_sb[0]) if fila_sb else []
            datos["_sin_bounty"] = pats_sb
            marcar_scope(datos, subdominios_in_scope(con, f[4]))
            limpiar_servicios(recon)
            listas |= volcar_listas(f[0], recon)
            # Los chips del informe recogen lo visto en CADA host, no solo en el
            # que quedó guardado en `tec_recon` (que es un acumulado histórico
            # de los pases, y se queda corto cuando un reproceso caracteriza
            # hosts nuevos). Se toma ANTES del recorte: si no, un informe con
            # más de CAP_WEB servicios perdería el stack de los que se recortan.
            tech_servicios = [x for s in (recon.get("servicios_nuevos") or [])
                              for x in (s.get("tech") or [])]
            _recortar_para_web(recon)
        # Las tecnologías se recalculan aquí y pisan lo que hubiera guardado:
        # se emiten como identificadores (la web elige icono y nombre según
        # idioma), y el stack de frameworks va aparte porque es texto libre.
        ids_tec, stack = tecs.get(f[4], ([], []))
        if f[6] == "scope_ampliado":
            # Los chips describen el objetivo anunciado, no el programa: ver
            # tecnologias.de_assets(). El scope se lee suelto y no del mapa de
            # `tecs` porque son megas de JSON que solo hacen falta aquí.
            fila_scope = con.execute(
                "SELECT plataforma, scope_raw_in FROM programas WHERE id=?", (f[4],)
            ).fetchone()
            ids_tec = tecnologias.de_assets(
                fila_scope[1], fila_scope[0], datos.get("assets")) if fila_scope else []
        # Assets que el programa acepta pero NO paga (Intigriti los marca con
        # `impact: "No Bounty"`). Siguen en scope, así que se señalan en vez de
        # ocultarse: sin la marca, `gammacademy.be` se leía en el informe de
        # Intergamma igual que un objetivo Tier 1. Se recalcula aquí y no se
        # congela con el informe, porque un asset puede empezar a pagar.
        fila_sb2 = con.execute(
            "SELECT scope_raw_in FROM programas WHERE id=?", (f[4],)).fetchone()
        pats = patrones_sin_bounty(fila_sb2[0]) if fila_sb2 else []
        if pats:
            sin_pago = [a for a in (datos.get("assets") or [])
                        if marca_sin_bounty(_host_de_asset(a), pats)]
            if sin_pago:
                datos["assets_sin_bounty"] = sin_pago
        datos["tecnologias"] = ids_tec
        # Ficha de apps de Marketplace (los ~70 programas de Bugcrowd cuyo scope
        # es un enlace de tienda). Se adjunta al informe para que la web muestre
        # las apps, sus permisos sobre el Jira ajeno y su host propio, en vez del
        # antiguo "0 activos". Solo aparece cuando el programa tiene apps.
        apps_mkt = apps_de_programa(con, f[4])
        if apps_mkt:
            datos["apps_marketplace"] = apps_mkt
        # Lo que paga el programa se lee de la BD en cada export, no del bloque
        # que se congeló al crear el informe: HackerOne no publica importes en el
        # feed (los rellena `enrich_bounty_h1.py` a posteriori), así que un
        # informe suyo nacía con `max_bounty: null` y se quedaba así para
        # siempre. Y "cuánto paga" es un dato del presente, no del día del
        # evento — al contrario que los assets, que sí se cuentan como fueron.
        fila_pago = con.execute(
            "SELECT pagos, actividad, max_bounty, moneda FROM programas WHERE id=?",
            (f[4],)
        ).fetchone()
        if fila_pago:
            datos["programa"] = {"pagos": fila_pago[0], "actividad": fila_pago[1],
                                 "max_bounty": fila_pago[2], "moneda": fila_pago[3]}
        # Al stack declarado se le suma lo que el recon vio de verdad sobre el
        # objetivo (`tec_recon`), que es más valioso porque no lo dice el
        # programa: lo hemos comprobado nosotros.
        datos["stack"] = tecnologias.limpiar_stack(
            list(stack) + (datos.get("tec_recon") or []) + tech_servicios)
        out.append({
            "id": f[0],
            "timestamp": f[1],
            "ts_barrido_anterior": f[2],
            "plataforma": f[3],
            "programa_id": f[4],
            "programa_nombre": f[5],
            "tipo": f[6],
            "titulo": f[7],
            "cuerpo": f[8],
            "datos_json": datos,
            "url_programa": f[10],
            "relevancia": f[11],
            "es_rareza": f[12],
            "origen": f[13],
            "fecha_enriquecido": f[14],
            "icono": f[15],
        })
    limpiar_listas(listas)
    return out


def exportar_programas(con, tecs):
    """
    Los programas activos que pagan, con los campos que usa el buscador.

    No se exporta `scope_raw_*` (son megas de JSON que el navegador no
    necesita) ni los campos del sistema personal (`notas`, `estado_analisis`).
    """
    filas = con.execute(
        f"""SELECT id, plataforma, handle, nombre, url, max_bounty, moneda, offers_bounties,
                  num_scope_in, scope_tipos, tiene_api, tiene_graphql, tiene_android,
                  tiene_ios, tiene_spa, tiene_api_docs, tiene_oauth, tiene_pagos,
                  pagos, actividad, fecha_cambio_scope, icono, acceso
           FROM programas
           WHERE activo = 1 AND offers_bounties = 1
             AND {FILTRO_PUBLICABLE}
           ORDER BY nombre"""
    ).fetchall()
    campos = [
        "id", "plataforma", "handle", "nombre", "url", "max_bounty", "moneda", "offers_bounties",
        "num_scope_in", "scope_tipos", "tiene_api", "tiene_graphql", "tiene_android",
        "tiene_ios", "tiene_spa", "tiene_api_docs", "tiene_oauth", "tiene_pagos",
        "pagos", "actividad", "fecha_cambio_scope", "icono", "acceso",
    ]
    salida = []
    for f in filas:
        p = dict(zip(campos, f))
        ids, stack = tecs.get(p["id"], ([], []))
        p["tecnologias"], p["stack"] = ids, tecnologias.limpiar_stack(stack)
        salida.append(p)
    return salida


def escribir(ruta, datos):
    ruta.write_text(
        json.dumps(datos, ensure_ascii=False, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    mb = ruta.stat().st_size / 1_048_576
    aviso = "  ⚠️ revisar si conviene partirlo / pasar a D1" if mb > AVISO_TAMANO_MB else ""
    print(f"  {ruta.name}: {len(datos)} registros, {mb:.2f} MB{aviso}")


def main():
    ap = argparse.ArgumentParser(description="Exporta los JSON de la web")
    ap.add_argument("--deploy", action="store_true", help="publicar en Cloudflare al terminar")
    args = ap.parse_args()

    con = sqlite3.connect(DB_PATH)
    try:
        tecs      = tecnologias_por_programa(con)
        informes  = exportar_informes(con, tecs)
        programas = exportar_programas(con, tecs)
    finally:
        con.close()

    if not informes:
        print("No hay informes publicados: el feed quedaría vacío. Nada que exportar.")
        return 1

    print("Exportando:")
    escribir(WEB_DIR / "informes.json", informes)
    escribir(WEB_DIR / "programas.json", programas)

    if args.deploy:
        print("Publicando en Cloudflare...")
        r = subprocess.run([sys.executable, str(DEPLOY)], capture_output=True, text=True)
        print(r.stdout[-500:] if r.returncode == 0 else r.stderr[-1000:])
        if r.returncode != 0:
            return 1
        print("Publicado. Comprobar con recarga forzada: la copia en caché del "
              "navegador puede seguir sirviendo la versión anterior.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
