#!/usr/bin/env python3
"""
fetch_marketplace.py — Resuelve el scope real de los programas de Bugcrowd cuyo
"target" es un enlace del Atlassian Marketplace.

POR QUÉ EXISTE
--------------
70 de los ~246 programas de Bugcrowd (62 de ellos al 100 %) no listan un
dominio: listan la FICHA DE TIENDA de una app de Atlassian, del tipo

    https://marketplace.atlassian.com/apps/1223472/trophies-for-jira?hosting=cloud

Ese enlace es el índice, no la superficie. `recon_scope.TERCEROS` bloquea
`atlassian.com` a propósito (enumerar `marketplace.atlassian.com` sería recon
contra Atlassian), así que estos programas salían en la web con CERO activos
pese a ser perfectamente atacables. Lo que se ataca de verdad son dos cosas, y
de ambas se sacan datos por API pública sin credenciales:

  1. La APP corriendo dentro de un Jira/Confluence ajeno — sus PERMISOS sobre
     ese tenant (leer, escribir, borrar, administrar) son la superficie lógica;
     el bug caro es la fuga entre tenants. El investigador se monta su propia
     instancia `bugbounty-test-<usuario>.atlassian.net`, instala la app y prueba.
  2. El HOST DEL VENDOR donde vive la app — solo las apps "Connect" tienen
     servidor propio (`baseUrl` en el descriptor) con endpoints y parámetros.
     Las apps "Forge" corren en infraestructura de Atlassian: no hay host.

QUÉ HACE, Y POR QUÉ ASÍ
-----------------------
Para cada app del scope (id numérico de `/apps/<id>`):

  a) Resuelve  id -> appKey  contra un ÍNDICE cacheado del Marketplace
     (`feeds_marketplace/indice.json`, ~6.900 apps). El índice se pagina una vez
     y se reutiliza; solo con HTML de la ficha como respaldo para las que no
     estén (ids reusados, listados retirados). Sin el índice haría una descarga
     de HTML de ~250 KB por app; con él, una llamada REST pequeña.

  b) Enriquece por API REST: permisos (`appScopes`/`scopes`), estado de bug
     bounty POR HOSTING (cloud/server/dataCenter), Cloud Fortified, si guarda
     datos personales, versión, ARI, y —si es Connect— el `baseUrl` y las rutas
     del descriptor.

  c) Vuelca a `apps_marketplace` (una fila por app, compartida entre programas)
     y `programa_app` (el puente: apps del mismo vendor se repiten entre sus
     engagements).

  d) RECON, línea conservadora (criterio del usuario, 2026-08-27): del host de
     una app Connect entra al recon SOLO EL HOST EXACTO del `baseUrl`
     (`trophiesjira.cloudapp.caelor.com`), NO el apex del vendor
     (`caelor.com`) — no se enumeran hermanos en casa del vendor. Ese host se
     inserta en `subdominios` (origen `marketplace`) + `programa_subdominio`
     (in_scope=1, motivo `marketplace_app`) y se caracteriza con httpx, con los
     mismos flags que la capa 2 del pipeline. Así aparece en la superficie del
     programa en la web sin tocar el export ni el frontend.

LÍMITES DE LA FUENTE
--------------------
El Marketplace responde 429 a partir de ~3 req/s: todo va serializado a <=2/s
con reintento por backoff. `bugBountyParticipant` viene por app pero el estado
por hosting importa: una app puede estar en bounty en cloud y no en server/DC,
y el scope de Bugcrowd es la variante cloud.

Uso:
    python3 fetch_marketplace.py                # resuelve todo lo pendiente + recon httpx
    python3 fetch_marketplace.py --sin-httpx    # resuelve y persiste, sin sondear hosts
    python3 fetch_marketplace.py --reindexar     # fuerza reconstruir el índice del Marketplace
    python3 fetch_marketplace.py --programa <id>  # solo un programa (id de la BD)
    python3 fetch_marketplace.py --estado        # qué hay resuelto, sin tocar nada
    python3 fetch_marketplace.py --simular        # qué haría, sin red ni BD
"""
import argparse
import json
import re
import socket
import sqlite3
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE      = Path(__file__).resolve().parent
DB_PATH   = str(BASE / "programas.db")
FEED_DIR  = BASE / "feeds_marketplace"
INDICE    = FEED_DIR / "indice.json"

MKT       = "https://marketplace.atlassian.com"
UA        = "Mozilla/5.0 (bug-bounty.vip recon; +https://www.bug-bounty.vip)"

# El Marketplace corta a ~3 req/s: nos quedamos por debajo. `_pausa` serializa
# TODAS las peticiones a este host desde una sola marca de tiempo global.
INTERVALO   = 0.5           # s entre peticiones (=2/s)
MAX_REINTENTOS = 4
INDICE_MAX_DIAS = 7         # el índice se reconstruye si es más viejo que esto

# Un id de `/apps/<id>` reusado, o un listado retirado, deja la app sin appKey:
# se guarda igual con resuelto=0 para que conste y no se reintente en bucle.
_ultima_peticion = 0.0


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def conectar():
    # isolation_level=None -> autocommit: cada escritura toma el lock un instante
    # y lo suelta. CRÍTICO aquí: entre app y app hay llamadas HTTP de ~2,5 s, y en
    # modo transacción por defecto sqlite3 dejaba una transacción de escritura
    # ABIERTA durante esas esperas, bloqueando la BD y haciendo fallar el sync de
    # los :06/:36 con "database is locked". En autocommit ninguna transacción
    # sobrevive a una petición de red. (Medido 2026-08-27: dos fallos del sync.)
    con = sqlite3.connect(DB_PATH, timeout=60, isolation_level=None)
    con.execute("PRAGMA journal_mode=WAL")
    con.execute("PRAGMA busy_timeout=60000")
    con.execute("PRAGMA synchronous=NORMAL")
    con.execute("PRAGMA foreign_keys=ON")
    return con


def _pausa():
    global _ultima_peticion
    delta = time.monotonic() - _ultima_peticion
    if delta < INTERVALO:
        time.sleep(INTERVALO - delta)
    _ultima_peticion = time.monotonic()


def _get(url, accept="application/json"):
    """GET serializado con backoff ante 429/5xx. Devuelve texto o lanza."""
    for intento in range(MAX_REINTENTOS):
        _pausa()
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            if e.code in (429, 500, 502, 503, 504) and intento < MAX_REINTENTOS - 1:
                espera = 2 ** intento * 2      # 2, 4, 8 s
                time.sleep(espera)
                continue
            raise
        except (urllib.error.URLError, socket.timeout):
            if intento < MAX_REINTENTOS - 1:
                time.sleep(2 ** intento)
                continue
            raise
    raise RuntimeError(f"agotados reintentos: {url}")


def _get_json(url):
    return json.loads(_get(url))


# ── Índice id -> appKey ──────────────────────────────────────────────────────

def construir_indice():
    """
    Pagina `/rest/2/addons` (cloud y datacenter) y guarda {app_id: {...}}.
    ~130 peticiones, ~2-3 min. Con `withVersion=true` cada página ya trae el
    deployment y el artifact, así que no hay que pedir cada app por separado
    para saber si es Connect.
    """
    FEED_DIR.mkdir(exist_ok=True)
    idx = {}
    for hosting in ("cloud", "datacenter"):
        off = 0
        while True:
            d = _get_json(f"{MKT}/rest/2/addons?limit=50&hosting={hosting}"
                          f"&offset={off}&withVersion=true")
            ads = d.get("_embedded", {}).get("addons", [])
            if not ads:
                break
            for a in ads:
                alt = (a.get("_links") or {}).get("alternate", {}).get("href", "")
                g = re.search(r"/apps/(\d+)", alt)
                if not g:
                    continue
                v = a.get("_embedded", {}).get("version") or {}
                art = ((v.get("_links") or {}).get("artifact") or {}).get("href")
                idx.setdefault(g.group(1), {})[hosting] = {
                    "key": a.get("key"),
                    "name": a.get("name"),
                    "connect": (v.get("deployment") or {}).get("connect"),
                    "artifact": art,
                }
            off += 50
    tmp = INDICE.with_suffix(".json.tmp")
    tmp.write_text(json.dumps({"generado": ahora(), "apps": idx}, ensure_ascii=False))
    tmp.replace(INDICE)                       # escritura atómica
    return idx


def cargar_indice(reindexar=False):
    if not reindexar and INDICE.exists():
        try:
            d = json.loads(INDICE.read_text())
            gen = datetime.strptime(d["generado"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if (datetime.now(timezone.utc) - gen).days < INDICE_MAX_DIAS:
                return d["apps"]
        except Exception:
            pass
    return construir_indice()


# ── Resolución de una app ────────────────────────────────────────────────────

def _app_key_por_html(app_id):
    """Respaldo para ids que no están en el índice: appKey del HTML de la ficha."""
    try:
        h = _get(f"{MKT}/apps/{app_id}", accept="text/html")
    except Exception:
        return None
    m = re.search(r'"appKey":"([^"]+)"', h)
    return m.group(1) if m else None


def _host_de_base_url(base_url):
    if not base_url:
        return None
    s = re.sub(r"^https?://", "", base_url.strip())
    return s.split("/", 1)[0].split(":", 1)[0].lower().strip(". ") or None


def _rutas_del_descriptor(desc):
    """Endpoints declarados (relativos), sin imágenes."""
    rutas = sorted({u for u in re.findall(r'"url":\s*"(/[^"]*)"', json.dumps(desc))})
    return [r for r in rutas if not re.search(r"\.(png|svg|jpe?g|ico|gif)(\?|$)", r)]


def resolver_app(app_id, idx):
    """
    Devuelve el dict de la fila `apps_marketplace` para un app_id. `resuelto=0`
    si no se localiza el appKey.
    """
    fila = {"app_id": app_id, "app_key": None, "nombre": None, "slug": None,
            "connect": None, "bounty_cloud": None, "bounty_server": None,
            "bounty_dc": None, "cloud_fortified": None, "datos_personales": None,
            "version": None, "ari": None, "n_permisos": None, "permisos_json": None,
            "base_url": None, "host": None, "rutas_json": None, "resuelto": 0,
            "fecha_actualizado": ahora()}

    ent = idx.get(app_id) or {}
    prefer = ent.get("cloud") or ent.get("datacenter") or {}
    key = prefer.get("key")
    fila["nombre"] = prefer.get("name")
    if not key:
        key = _app_key_por_html(app_id)
    if not key:
        return fila                       # id reusado / listado retirado
    fila["app_key"] = key

    # Ficha de la app: bounty por hosting, fortified, datos personales.
    try:
        ad = _get_json(f"{MKT}/rest/2/addons/{key}")
        fila["nombre"] = fila["nombre"] or ad.get("name")
        prog = ad.get("programs") or {}
        bb = prog.get("bugBountyParticipant") or {}
        fila["bounty_cloud"]  = (bb.get("cloud") or {}).get("status")
        fila["bounty_server"] = (bb.get("server") or {}).get("status")
        fila["bounty_dc"]     = (bb.get("dataCenter") or {}).get("status")
        fila["cloud_fortified"] = (prog.get("cloudFortified") or {}).get("status")
        fila["datos_personales"] = 1 if ad.get("storesPersonalData") else 0
    except Exception:
        pass

    # Versión latest: permisos, deployment (connect), ARI, artifact del descriptor.
    try:
        v = _get_json(f"{MKT}/rest/2/addons/{key}/versions/latest")
        fila["version"] = v.get("name")
        dep = v.get("deployment") or {}
        fila["connect"] = 1 if dep.get("connect") else 0
        cl = v.get("cloud") or {}
        fila["ari"] = cl.get("appId")
        perms = [s.get("key") for s in (cl.get("appScopes") or []) if s.get("key")]
        fila["n_permisos"] = len(perms)
        fila["permisos_json"] = json.dumps(perms, ensure_ascii=False) if perms else None

        art = ((v.get("_links") or {}).get("artifact") or {}).get("href")
        if art:
            a = _get_json(MKT + art)
            binario = (a.get("_links") or {}).get("binary", {}).get("href")
            remote = (a.get("_links") or {}).get("remote", {}).get("href")
            desc = None
            # El descriptor Connect llega por `binary` (descriptor.json) o, en su
            # defecto, por `remote` si apunta a un atlassian-connect.json.
            if binario:
                try:
                    desc = json.loads(_get(binario))
                except Exception:
                    desc = None
            if desc is None and remote and remote.endswith(".json"):
                try:
                    desc = json.loads(_get(remote))
                except Exception:
                    desc = None
            if isinstance(desc, dict):
                fila["base_url"] = desc.get("baseUrl")
                fila["host"] = _host_de_base_url(desc.get("baseUrl"))
                rutas = _rutas_del_descriptor(desc)
                fila["rutas_json"] = json.dumps(rutas, ensure_ascii=False) if rutas else None
                if not perms and desc.get("scopes"):     # Connect clásico: scopes en el descriptor
                    fila["permisos_json"] = json.dumps(desc["scopes"], ensure_ascii=False)
                    fila["n_permisos"] = len(desc["scopes"])
    except Exception:
        pass

    # Host de vendor conocido de terceros (Atlassian, Heroku…) NO entra al recon:
    # no es del vendor. Se guarda el dato, pero `host` se anula para no encolarlo.
    if fila["host"] and _es_host_de_tercero(fila["host"]):
        fila["host"] = None

    fila["resuelto"] = 1
    return fila


# Hosts que NO son del vendor aunque salgan como baseUrl: infraestructura de
# Atlassian y PaaS compartidos. Enumerar/sondear estos sería recon contra un
# tercero, igual que `recon_scope.TERCEROS`.
_TERCEROS_HOST = (
    "atl-paas.net", "atlassian.com", "atlassian.net", "herokuapp.com",
    "appspot.com", "azurewebsites.net", "amazonaws.com",
)


def _es_host_de_tercero(host):
    return any(host == t or host.endswith("." + t) for t in _TERCEROS_HOST)


# ── Persistencia ─────────────────────────────────────────────────────────────

_COLS = ("app_id", "app_key", "nombre", "slug", "connect", "bounty_cloud",
         "bounty_server", "bounty_dc", "cloud_fortified", "datos_personales",
         "version", "ari", "n_permisos", "permisos_json", "base_url", "host",
         "rutas_json", "resuelto", "fecha_actualizado")


def guardar_app(con, fila):
    cols = ",".join(_COLS)
    ph = ",".join("?" for _ in _COLS)
    upd = ",".join(f"{c}=excluded.{c}" for c in _COLS if c != "app_id")
    con.execute(
        f"INSERT INTO apps_marketplace ({cols}) VALUES ({ph}) "
        f"ON CONFLICT(app_id) DO UPDATE SET {upd}",
        tuple(fila[c] for c in _COLS),
    )


def vincular(con, programa_id, app_id):
    con.execute(
        "INSERT OR IGNORE INTO programa_app (programa_id, app_id) VALUES (?,?)",
        (programa_id, app_id),
    )


def _ids_de_scope(scope_raw_in):
    """Ids de `/apps/<id>` del scope, en orden y sin repetir."""
    ids = []
    try:
        arr = json.loads(scope_raw_in or "[]")
    except Exception:
        return ids
    for a in arr:
        m = re.search(r"marketplace\.atlassian\.com/apps/(\d+)", a.get("target") or "")
        if m and m.group(1) not in ids:
            ids.append(m.group(1))
    return ids


def programas_con_marketplace(con, solo_programa=None):
    sql = ("SELECT id, nombre, scope_raw_in FROM programas "
           "WHERE plataforma='bugcrowd' AND activo=1 "
           "AND scope_raw_in LIKE '%marketplace.atlassian.com/apps/%'")
    params = []
    if solo_programa:
        sql += " AND id=?"
        params.append(solo_programa)
    return con.execute(sql, params).fetchall()


# ── Recon del host exacto del baseUrl ────────────────────────────────────────

def _resolver_dns(host):
    try:
        infos = socket.getaddrinfo(host, None)
        for fam, *_rest, sa in infos:
            ip = sa[0]
            if ":" not in ip:        # preferimos IPv4 para la ficha
                return ip
        return infos[0][4][0]
    except Exception:
        return None


def encolar_hosts(con, pares):
    """
    `pares` = [(programa_id, host)]. Inserta cada host EXACTO en `subdominios` +
    `programa_subdominio` (in_scope=1, motivo `marketplace_app`). NO añade raíz:
    el host no se enumera, solo se caracteriza. Devuelve los hosts insertados.
    """
    import recon_scope
    ts = ahora()
    hosts = set()
    for programa_id, host in pares:
        if not host:
            continue
        hosts.add(host)
        ip = _resolver_dns(host)
        vivo = 1 if ip else 0
        fila = con.execute("SELECT id FROM subdominios WHERE subdominio=?", (host,)).fetchone()
        if fila is None:
            cur = con.execute(
                """INSERT INTO subdominios
                   (subdominio, raiz, origen, vivo, ip, cname, fecha_descubierto, fecha_ultima_vivo)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (host, recon_scope._apex(host), "marketplace", vivo, ip, None,
                 ts, ts if vivo else None),
            )
            sub_id = cur.lastrowid
        else:
            sub_id = fila[0]
            con.execute(
                "UPDATE subdominios SET vivo=?, ip=COALESCE(?,ip), "
                "fecha_ultima_vivo=COALESCE(?,fecha_ultima_vivo) WHERE id=?",
                (vivo, ip, ts if vivo else None, sub_id),
            )
        con.execute(
            """INSERT INTO programa_subdominio (programa_id, subdominio_id, in_scope, scope_motivo)
               VALUES (?,?,1,'marketplace_app')
               ON CONFLICT(programa_id, subdominio_id)
               DO UPDATE SET in_scope=1, scope_motivo='marketplace_app'""",
            (programa_id, sub_id),
        )
    con.commit()
    return hosts


def caracterizar_hosts(con, hosts):
    """httpx sobre host:443 (y :80), mismos flags que la capa 2. Rellena `servicios`."""
    if not hosts:
        return 0
    from backfill_httpx import sondear, cdn_de
    objetivos = []
    for h in sorted(hosts):
        objetivos.append(f"{h}:443")
    ts = ahora()
    try:
        resp = sondear(objetivos)
    except Exception as e:
        print(f"  ⚠️ httpx falló ({e}); los hosts quedan sin caracterizar (se reintenta luego)")
        return 0
    n = 0
    for h in sorted(hosts):
        clave = f"{h}:443"
        fila = con.execute("SELECT id FROM subdominios WHERE subdominio=?", (h,)).fetchone()
        if not fila:
            continue
        sub_id = fila[0]
        d = resp.get(clave)
        ya = con.execute(
            "SELECT id FROM servicios WHERE subdominio_id=? AND puerto=443 AND protocolo='tcp'",
            (sub_id,),
        ).fetchone()
        if d:
            valores = (d.get("status_code"), d.get("title"),
                       ",".join(d.get("tech") or []) or None, d.get("webserver"),
                       cdn_de(d), ts, ts)
            if ya:
                con.execute(
                    """UPDATE servicios SET status=COALESCE(?,status), title=COALESCE(?,title),
                       tech=COALESCE(?,tech), server=COALESCE(?,server), cdn=COALESCE(?,cdn),
                       ts_sondeo=?, fecha_analisis=? WHERE id=?""",
                    valores + (ya[0],),
                )
            else:
                con.execute(
                    """INSERT INTO servicios
                       (subdominio_id, puerto, protocolo, servicio, version, status,
                        title, tech, server, cdn, ts_sondeo, fecha_analisis)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (sub_id, 443, "tcp", "https", None, d.get("status_code"),
                     d.get("title"), ",".join(d.get("tech") or []) or None,
                     d.get("webserver"), cdn_de(d), ts, ts),
                )
            n += 1
        else:
            # Sondeado y sin respuesta: fila con ts_sondeo y status NULL (la web
            # lo pinta distinto de "no mirado"), como hace backfill_httpx.
            if ya:
                con.execute("UPDATE servicios SET ts_sondeo=? WHERE id=?", (ts, ya[0]))
            else:
                con.execute(
                    """INSERT INTO servicios
                       (subdominio_id, puerto, protocolo, servicio, status, ts_sondeo)
                       VALUES (?,?,?,?,?,?)""",
                    (sub_id, 443, "tcp", "https", None, ts),
                )
    con.commit()
    return n


# ── Estado / CLI ─────────────────────────────────────────────────────────────

def estado(con):
    tot = con.execute("SELECT COUNT(*) FROM apps_marketplace").fetchone()[0]
    res = con.execute("SELECT COUNT(*) FROM apps_marketplace WHERE resuelto=1").fetchone()[0]
    host = con.execute("SELECT COUNT(*) FROM apps_marketplace WHERE host IS NOT NULL").fetchone()[0]
    prog = con.execute("SELECT COUNT(DISTINCT programa_id) FROM programa_app").fetchone()[0]
    con_perm = con.execute("SELECT COUNT(*) FROM apps_marketplace WHERE n_permisos>0").fetchone()[0]
    print(f"apps en BD: {tot}  (resueltas {res}, con host propio {host}, con permisos {con_perm})")
    print(f"programas Marketplace cubiertos: {prog}")
    subs = con.execute(
        "SELECT COUNT(*) FROM subdominios WHERE origen='marketplace'").fetchone()[0]
    print(f"hosts de vendor en subdominios (origen=marketplace): {subs}")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[1])
    ap.add_argument("--programa", type=int, help="solo un programa (id de la BD)")
    ap.add_argument("--sin-httpx", action="store_true", help="resuelve y persiste, sin sondear hosts")
    ap.add_argument("--reindexar", action="store_true", help="fuerza reconstruir el índice del Marketplace")
    ap.add_argument("--refrescar", action="store_true", help="re-resuelve todas las apps aunque ya estén en la BD")
    ap.add_argument("--estado", action="store_true", help="qué hay resuelto, sin tocar nada")
    ap.add_argument("--simular", action="store_true", help="qué haría, sin red ni BD")
    args = ap.parse_args()

    con = conectar()
    if args.estado:
        estado(con)
        return 0

    programas = programas_con_marketplace(con, args.programa)
    if not programas:
        print("No hay programas Bugcrowd activos con targets de Marketplace.")
        return 0

    total_ids = {i for _, _, raw in programas for i in _ids_de_scope(raw)}
    print(f"{len(programas)} programa(s) Marketplace, {len(total_ids)} apps únicas a resolver.")
    if args.simular:
        for pid, nom, raw in programas[:20]:
            ids = _ids_de_scope(raw)
            print(f"  [{pid}] {nom[:40]:40} {len(ids)} apps")
        return 0

    idx = cargar_indice(args.reindexar)
    print(f"Índice del Marketplace: {len(idx)} apps.")

    # Reanudación: las apps ya resueltas en la BD no se vuelven a pedir (a menos
    # de `--refrescar`). Así una pasada interrumpida —o el timer— retoma barato,
    # y una app compartida entre programas se resuelve una sola vez. Se cargan al
    # `cache` con lo justo para enlazar y encolar su host.
    cache = {}
    if not args.refrescar:
        for aid, host, res in con.execute(
                "SELECT app_id, host, resuelto FROM apps_marketplace"):
            cache[aid] = {"host": host, "resuelto": res, "_bd": True}

    pares_host = []
    n_res = n_nuevas = 0
    for pid, nom, raw in programas:
        ids = _ids_de_scope(raw)
        for app_id in ids:
            if app_id not in cache:
                fila = resolver_app(app_id, idx)
                guardar_app(con, fila)
                con.commit()                 # commit por app: reanudable y sin bloqueos largos
                cache[app_id] = {"host": fila.get("host"),
                                 "resuelto": fila["resuelto"], "_bd": False}
                n_nuevas += 1
                if fila["resuelto"]:
                    n_res += 1
                if n_nuevas % 25 == 0:
                    print(f"    … {n_nuevas} apps resueltas", flush=True)
            vincular(con, pid, app_id)
            host = cache[app_id].get("host")
            if host:
                pares_host.append((pid, host))
        con.commit()
        print(f"  [{pid}] {nom[:44]:44} {len(ids)} apps", flush=True)

    hosts = encolar_hosts(con, pares_host)
    tot_res = con.execute("SELECT COUNT(*) FROM apps_marketplace WHERE resuelto=1").fetchone()[0]
    print(f"{n_nuevas} apps nuevas esta pasada ({n_res} resueltas); "
          f"{tot_res} resueltas en total; {len(hosts)} hosts de vendor al recon.")

    if hosts and not args.sin_httpx:
        print(f"Caracterizando {len(hosts)} hosts con httpx…", flush=True)
        n = caracterizar_hosts(con, hosts)
        print(f"  {n} hosts con respuesta.")

    print("Recuerda publicar: python3 export_json.py --deploy")
    return 0


if __name__ == "__main__":
    sys.exit(main())
