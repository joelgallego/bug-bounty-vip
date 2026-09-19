#!/usr/bin/env python3
"""
recon_pipeline.py — recon de superficie de un programa (capas 0 a 3).

Hay UN solo pipeline para todos los disparadores. Lo único que cambia entre
`programa_nuevo`, `scope_ampliado` y `periodico` es la lista de raíces que
recibe; las capas que corren después son idénticas.

  Capa 0 — pasivo, consulta fuentes públicas sin contactar al objetivo:
           subfinder + crt.sh + gau.
  Capa 1 — activo sobre DNS: permutaciones (gotator) y bruteforce de wordlist,
           resueltos con puredns. El filtrado de wildcard va SIEMPRE activo:
           es lo que evita meter miles de subdominios falsos.
  Capa 2 — httpx sobre lo vivo e in-scope → servicios web.
  Capa 3 — naabu top-100 + nmap -sV sobre los puertos ya abiertos.

La capa 4 (nuclei) queda deliberadamente fuera: es la que más carga genera en
el objetivo, así que se lanza a mano sobre el subconjunto que interese.

Los hallazgos no se calculan comparando listas: `subdominios.subdominio` es
UNIQUE, así que una fila que entra es, por definición, un descubrimiento. El
pipeline devuelve lo que ha sido alta real para que el worker lo funda en el
informe del asunto.

Uso CLI:
    python3 recon_pipeline.py <programa_id> [--capas 0|01] [--dry-run]
"""
import argparse
import ipaddress
import json
import random
import logging
import shutil
import sqlite3
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

import threading

import recon_scope

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE      = Path(__file__).resolve().parent
DB_PATH   = str(BASE / "programas.db")
RECON_DIR = BASE / "recon"
ASSETS    = BASE / "recon_assets"
GOBIN     = Path.home() / "go" / "bin"

# Rutas absolutas a propósito: en el PATH, `httpx` es el cliente de Python y
# `gau` un alias de git — llamarlos por nombre ejecuta la herramienta
# equivocada (ver docs/recon.md → "Perfil de límites v1").
BIN = {
    "subfinder": "/usr/bin/subfinder",
    "gau":       str(GOBIN / "gau"),
    "gotator":   str(GOBIN / "gotator"),
    "puredns":   str(GOBIN / "puredns"),
    "massdns":   str(GOBIN / "massdns"),
    "dnsx":      str(GOBIN / "dnsx"),
    "httpx":     str(GOBIN / "httpx"),
    "naabu":     str(GOBIN / "naabu"),
}

RESOLVERS         = str(ASSETS / "resolvers.txt")
RESOLVERS_TRUSTED = str(ASSETS / "resolvers_trusted.txt")
WORDLIST          = str(ASSETS / "dns_wordlist.txt")

# Perfil de límites v1 (docs/recon.md). Son por job: con el pool del worker la
# carga agregada es N veces esto.
RATE_PUBLICO   = 1500
RATE_TRUSTED   = 500
GAU_THREADS    = 5
DNSX_THREADS   = 50
# Umbral a partir del cual que dnsx no resuelva NADA es sospechoso (ver
# `resolver()`): con pocos nombres, un cero es la respuesta correcta.
CERO_DNS_SOSPECHOSO = 10
HTTPX_RATE     = 50      # default de httpx es 150: se baja a propósito
HTTPX_THREADS  = 25
NAABU_RATE     = 300
# Un host que abre más puertos que esto (de los 100 que sondea naabu) no tiene
# esos servicios: es un firewall/IPS que responde SYN-ACK a todo. Se descarta.
NAABU_MAX_PUERTOS = 15
# La wordlist completa son 500k palabras. Contra un programa con 30 raíces eso
# son 15M de consultas (~3 h al ritmo de arriba), demasiado para un disparo
# reactivo que debe durar minutos. Se recorta por defecto y se sube a mano
# cuando un objetivo concreto lo merezca.
MAX_PALABRAS   = 25_000
TIMEOUT_TOOL   = 1800
# Suelo de tiempo para dnsx/httpx aunque el presupuesto del pase esté agotado
# (ver `_timeout_de_herramienta`). Medido: dnsx resuelve 38 nombres en ~5 s y
# httpx sondea 4 hosts en ~1 s; 240 s dan margen de sobra para los cientos de
# un pase normal sin que un pase rápido se alargue de forma apreciable.
SUELO_CARACTERIZACION = 240

# Contexto por hilo: el worker corre varios jobs a la vez y cada uno tiene su
# propio plazo. Una global se pisaría entre hilos.
_ctx = threading.local()


def _registrar_error(cod, **args):
    """
    Anota un error del pase para que llegue al informe (`datos_json.errores`),
    que el frontend pinta en rojo. Los errores viven en `_ctx` (threadlocal),
    junto al deadline: `correr()` inicializa la lista por job y la devuelve.

    NO se anota una frase, sino un código + sus datos (`{"cod": "tool_plazo",
    "tool": "gau"}`): la web tiene informe en 9 idiomas y una frase escrita
    aquí saldría en español en todos ellos. La redacción vive en `i18n/*.json`
    bajo la clave `error_<cod>`; los campos del dict son sus variables.

    Seguro fuera de un `correr()`: si nadie inicializó la lista, no hace nada.
    Deduplica: el mismo fallo no se lista dos veces.
    """
    errs = getattr(_ctx, "errores", None)
    err = dict(args, cod=cod)
    if errs is not None and err not in errs:
        errs.append(err)


def _timeout_de_herramienta(esencial=False):
    """
    Techo de tiempo duro de una herramienta. Ya NO recorta por deadline.

    HISTÓRICO (2026-08-17): antes esto devolvía el residuo de un `deadline` de
    pase (300 s del rápido), y `ejecutar()` lo pasaba como `timeout` a
    `subprocess.run` — es decir, MATABA la herramienta al agotarse el plazo. Con
    subfinder eso era destructivo: no vuelca su `-o` hasta terminar, así que un
    corte a media dejaba el fichero vacío (`subfinder_cero`) y se perdía toda la
    fuente pasiva principal, sin recuperación (el profundo no re-corría capa 0).
    Medido: Threema perdió ≥129 objetivos in-scope así. Ver docs/recon.md → "Orquestación:
    cola, worker y fases".

    El modelo nuevo no corta nada: el pase se trocea en fases (rapido→pasivo→
    profundo) y cada herramienta corre hasta terminar. La rapidez del preliminar
    la da el REPARTO por fases, no un cronómetro que mata. `TIMEOUT_TOOL` queda
    solo como red de seguridad contra un cuelgue infinito. `esencial` se
    conserva por firma pero ya no cambia el resultado.
    """
    return TIMEOUT_TOOL

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(message)s",
    datefmt="%H:%M:%S",
    handlers=[logging.StreamHandler()],
)
log = logging.getLogger(__name__)


def ahora():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


# ── Ejecución de herramientas ────────────────────────────────────────────────

def ejecutar(con, programa_id, herramienta, fase, cmd, salida, entrada=None,
             esencial=False, n_entrada=None):
    """
    Corre una herramienta, deja el output crudo en disco y registra la
    ejecución en `recon_ejecuciones`.

    Devuelve la lista de líneas del output (vacía si la herramienta falló: un
    fallo de una fuente no debe tumbar el job entero, solo empobrecer el
    resultado, y queda constancia con estado='error').

    `esencial` → suelo de tiempo propio (ver `_timeout_de_herramienta`).
    `n_entrada` → cuántos objetivos se le dieron. Con eso, devolver CERO deja de
    ser ambiguo: si le entraron 38 nombres y no sale ninguno, no es que no haya
    nada, es que la herramienta no hizo su trabajo, y eso tiene que constar en
    el informe (caso medido: httpx devolvió 0 sobre 4 hosts vivos que a mano
    responden con título y tech).
    """
    salida.parent.mkdir(parents=True, exist_ok=True)
    hs = getattr(_ctx, "herramientas", None)
    if hs is not None:
        hs.add(herramienta)          # corrió: sus errores viejos caducan (ver fusionar)
    estado, lineas, err = "ok", [], None
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=_timeout_de_herramienta(esencial), input=entrada,
        )
        # Varias de estas tools escriben a fichero (-o/-w) en vez de a stdout.
        if salida.exists() and salida.stat().st_size:
            lineas = [l.strip() for l in salida.read_text().splitlines() if l.strip()]
        else:
            lineas = [l.strip() for l in proc.stdout.splitlines() if l.strip()]
            if lineas:
                salida.write_text("\n".join(lineas) + "\n")
        if proc.returncode != 0 and not lineas:
            estado = "error"
            err = ("tool_fallo", {"tool": herramienta, "rc": proc.returncode})
            log.warning(f"[{herramienta}] rc={proc.returncode}: {proc.stderr.strip()[:200]}")
        elif not lineas:
            # Salió bien y no devolvió nada. Puede ser cierto, pero también un
            # throttling de las fuentes (visto en subfinder). Se marca aparte
            # de "ok" para que el monitor pueda distinguir "no hay nada" de
            # "esta pasada no vio nada", que en un diff periódico se leería
            # como una desaparición masiva.
            estado = "vacio"
            log.warning(f"[{herramienta}] 0 resultados con rc=0 — ¿fuente limitada?")
            # Con objetivos concretos a la entrada, el cero deja de ser una
            # lectura posible del mundo y pasa a ser un fallo mudo: se avisa en
            # el informe. Sin `n_entrada` (fuentes de descubrimiento como gau o
            # subfinder, donde cero es un resultado legítimo) no se avisa aquí:
            # quien llama decide (capa0 lo hace para subfinder).
            if n_entrada:
                err = ("tool_vacio", {"tool": herramienta, "n": n_entrada})
    except subprocess.TimeoutExpired:
        estado = "error"
        err = ("tool_plazo", {"tool": herramienta})
        log.warning(f"[{herramienta}] cortado por plazo tras {_timeout_de_herramienta(esencial)}s")
    except FileNotFoundError:
        estado = "error"
        err = ("tool_binario", {"tool": herramienta, "bin": cmd[0]})
        log.warning(f"[{herramienta}] binario no encontrado: {cmd[0]}")
    if err:
        _registrar_error(err[0], **err[1])

    con.execute(
        """INSERT INTO recon_ejecuciones
           (programa_id, herramienta, fase, comando, ruta, fecha, n_resultados, estado)
           VALUES (?,?,?,?,?,?,?,?)""",
        (programa_id, herramienta, fase, " ".join(cmd), str(salida),
         ahora(), len(lineas), estado),
    )
    con.commit()
    log.info(f"[{herramienta}] {len(lineas)} líneas ({estado})")
    return lineas


def _host_de_url(url):
    """Hostname de una URL de gau, sin puerto. '' si no se puede."""
    try:
        resto = url.split("://", 1)[1] if "://" in url else url
        return resto.split("/", 1)[0].split(":", 1)[0].lower().strip()
    except (IndexError, AttributeError):
        return ""


# ── Certificate Transparency (dos proveedores del mismo dato) ────────────────

def _json_http(url, timeout=45, intentos=2):
    """GET de JSON con un reintento: estos servicios dan 502 con frecuencia."""
    ultimo = None
    for i in range(intentos):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "bugbounty-recon"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return json.load(r)
        except Exception as e:
            ultimo = e
            if i + 1 < intentos:
                time.sleep(3)
    raise ultimo


def _ct_crtsh(raiz, timeout=45, intentos=2):
    datos = _json_http(f"https://crt.sh/?q=%25.{raiz}&output=json",
                       timeout=timeout, intentos=intentos)
    nombres = []
    for fila in datos:
        for n in (fila.get("name_value") or "").splitlines():
            n = n.strip().lower().lstrip("*.")
            if n.endswith(raiz):
                nombres.append(n)
    return nombres


def _ct_certspotter(raiz):
    """
    Alternativa a crt.sh (sslmate). Sin API key va limitada, pero responde en
    1-2 s cuando crt.sh lleva días devolviendo 502.
    """
    datos = _json_http(
        f"https://api.certspotter.com/v1/issuances?domain={raiz}"
        f"&include_subdomains=true&expand=dns_names")
    if isinstance(datos, dict):            # {"message": "rate limit"} y similares
        raise RuntimeError(str(datos.get("message") or datos)[:120])
    nombres = []
    for cert in datos:
        for n in (cert.get("dns_names") or []):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(raiz):
                nombres.append(n)
    return nombres


# ── Capa 0: descubrimiento pasivo ────────────────────────────────────────────

# Fuentes de subfinder que cuelgan o no aportan, medido 2026-08-17 en threema.ch
# (ver docs/recon.md → "Orquestación: cola, worker y fases"): `crtsh` da 502 y
# además ya lo consulta `capa0_ct` por su cuenta; `digitorus` responde 403 con un
# challenge de Cloudflare (descarga un HTML enorme); `driftnet`/`leakix`/`reconeer`
# dan 401 sin API key. `github` va aparte en el profundo (capa_github). Excluirlas
# evita que subfinder se eternice (>300 s) por fuentes que no van a dar nada.
SUBFINDER_FUENTES_FUERA  = "github,crtsh,digitorus,driftnet,leakix,reconeer"
SUBFINDER_TIMEOUT_FUENTE = 30    # segundos por fuente, para que ninguna lo cuelgue


def _consultar_ct(con, programa_id, raices, wdir, fuente, consulta, encontrados):
    """
    Consulta UNA fuente de Certificate Transparency sobre las raíces, guarda el
    crudo, registra la ejecución y mete los nombres en `encontrados` (respetando
    el origen ya presente). Devuelve True si la fuente respondió (no cayó en
    TODAS las raíces).
    """
    salida = wdir / f"{fuente}.txt"
    hs = getattr(_ctx, "herramientas", None)
    if hs is not None:
        hs.add(fuente)               # crtsh/certspotter corrieron: caduca su error viejo
    nombres, fallos = [], []
    for raiz in sorted(raices):
        try:
            nombres += consulta(raiz)
        except Exception as e:
            fallos.append(f"{raiz}: {e}")
            log.warning(f"[{fuente}] {raiz}: {e}")
    cayo = bool(fallos) and len(fallos) == len(raices)
    unicos = sorted(set(nombres))
    if unicos:
        salida.write_text("\n".join(unicos) + "\n")
    con.execute(
        """INSERT INTO recon_ejecuciones
           (programa_id, herramienta, fase, comando, ruta, fecha, n_resultados, estado)
           VALUES (?,?,?,?,?,?,?,?)""",
        (programa_id, fuente, 0, f"{fuente}(<raiz>)  " + "; ".join(fallos),
         str(salida), ahora(), len(unicos), "error" if cayo else "ok"),
    )
    con.commit()
    log.info(f"[{fuente}] {len(unicos)} nombres"
             + (f" ({len(fallos)} raíz/raíces fallaron)" if fallos else ""))
    for n in unicos:
        encontrados.setdefault(n, fuente)
    return not cayo


def capa0_ct(con, programa_id, raices, wdir):
    """
    Certificate Transparency para el pase RÁPIDO. Dos proveedores del mismo dato:
    certspotter (fiable, ~1 s) + crt.sh con reintentos CORTOS (2 intentos, 3 s de
    timeout). crt.sh da 502 de forma constante; aquí no se le espera más de ~6 s
    para no lastrar el preliminar. Si en el rápido no respondió, `capa0_pasivo`
    lo reintenta con el timeout normal como red de seguridad (idempotente si el
    rápido ya lo trajo). Devuelve {subdominio: fuente}.
    """
    encontrados = {}
    cs_ok  = _consultar_ct(con, programa_id, raices, wdir,
                           "certspotter", _ct_certspotter, encontrados)
    crt_ok = _consultar_ct(con, programa_id, raices, wdir, "crtsh",
                           lambda r: _ct_crtsh(r, timeout=3, intentos=2), encontrados)
    # Si una cae pero la otra responde, es degradación (se avisa). Si caen las
    # dos, hay un hueco real — pero crt.sh aún tiene otra oportunidad en pasivo,
    # así que su caída aquí no se grita como "ct_caido" salvo que certspotter
    # también falle.
    if not cs_ok and not crt_ok:
        _registrar_error("ct_caido")
    elif not crt_ok:
        _registrar_error("ct_degradado", fuente="crtsh", vivas="certspotter")
    elif not cs_ok:
        _registrar_error("ct_degradado", fuente="certspotter", vivas="crtsh")
    return encontrados


def capa0_pasivo(con, programa_id, raices, wdir):
    """
    Fuentes pasivas LENTAS: subfinder (todas sus APIs menos las rotas) + gau
    (wayback/commoncrawl/otx). Nada toca al target.

    Va en el pase PASIVO, después del preliminar, y SIN corte de tiempo: subfinder
    no vuelca su `-o` hasta terminar, así que matarlo a media pierde todo (medido:
    Threema, ≥129 objetivos in-scope perdidos; ver docs/recon.md). La rapidez del
    preliminar la da el reparto por fases, no un cronómetro que mata.

    Devuelve {subdominio: origen}, origen = primera fuente que lo vio (subfinder
    antes que gau: lo más común primero).
    """
    encontrados = {}
    lista_raices = wdir / "raices.txt"
    lista_raices.parent.mkdir(parents=True, exist_ok=True)
    lista_raices.write_text("\n".join(sorted(raices)) + "\n")

    salida = wdir / "subfinder.txt"
    subs = ejecutar(
        con, programa_id, "subfinder", 0,
        [BIN["subfinder"], "-dL", str(lista_raices), "-all",
         "-es", SUBFINDER_FUENTES_FUERA,
         "-timeout", str(SUBFINDER_TIMEOUT_FUENTE),
         "-silent", "-o", str(salida)],
        salida,
    )
    for sub in subs:
        encontrados.setdefault(sub.lower(), "subfinder")
    # subfinder es la fuente principal: que devuelva 0 casi siempre es un límite
    # de la fuente, no un dominio de verdad sin subdominios. Se avisa.
    if not subs:
        _registrar_error("subfinder_cero", n=len(raices))

    # gau: URLs archivadas (wayback/commoncrawl/otx). Pega a los archivos, no
    # al target. De ahí salen hosts que no aparecen en ninguna fuente de DNS.
    for raiz in sorted(raices):
        salida = wdir / f"gau_{raiz}.txt"
        urls = ejecutar(
            con, programa_id, "gau", 0,
            [BIN["gau"], "--subs", "--threads", str(GAU_THREADS), "--o", str(salida), raiz],
            salida,
        )
        for u in urls:
            h = _host_de_url(u)
            if h.endswith(raiz):
                encontrados.setdefault(h, "gau")

    # crt.sh de nuevo, ahora SIN prisa (timeout normal, 2 intentos): red de
    # seguridad para cuando el rápido no lo pilló (502 en ese momento). Es
    # idempotente si el rápido ya lo trajo. certspotter no se repite: ya lo
    # cubrió el rápido con holgura.
    _consultar_ct(con, programa_id, raices, wdir, "crtsh", _ct_crtsh, encontrados)

    return encontrados


def capa0(con, programa_id, raices, wdir):
    """
    Capa 0 completa = pasivo (subfinder/gau/crt.sh) + certspotter. Se conserva
    para el uso CLI/manual y el disparo `periodico`, donde el pase no se trocea
    en fases. El worker por fases llama a `capa0_ct` y `capa0_pasivo` por
    separado.

    Orden de origen: subfinder gana sobre gau/CT (lo más común primero). crt.sh
    ya lo hace `capa0_pasivo`; aquí solo falta certspotter, así que cada fuente
    corre una vez.
    """
    encontrados = dict(capa0_pasivo(con, programa_id, raices, wdir))
    _consultar_ct(con, programa_id, raices, wdir, "certspotter", _ct_certspotter, encontrados)
    return encontrados


def capa_github(con, programa_id, raices, wdir):
    """
    subfinder restringido a la fuente github, aparte de capa0 y solo en el pase
    profundo. La GitHub search API tiene un rate-limit tan agresivo que dispara
    subfinder de ~30 s a ~180 s (medido) para un puñado de nombres extra: no
    vale la espera en el pase rápido, que debe publicar en minutos. Pero esos
    nombres —subdominios que solo asoman en código público, a menudo de
    entornos internos— son datos valiosos cuando no hay prisa.

    Devuelve la lista de subdominios; el `origen` lo decide `correr()` (será
    "github" solo para los que ninguna fuente previa tenía).
    """
    lista_raices = wdir / "raices.txt"
    if not lista_raices.exists():
        lista_raices.parent.mkdir(parents=True, exist_ok=True)
        lista_raices.write_text("\n".join(sorted(raices)) + "\n")
    salida = wdir / "subfinder_github.txt"
    subs = ejecutar(
        con, programa_id, "subfinder-github", 1,
        [BIN["subfinder"], "-dL", str(lista_raices), "-s", "github",
         "-silent", "-o", str(salida)],
        salida,
    )
    return [s.lower() for s in subs]


# ── Capa 1: descubrimiento activo sobre DNS ──────────────────────────────────

def _resolver_candidatos(con, programa_id, candidatos, wdir, etiqueta):
    """
    Pasa una lista de candidatos por puredns (massdns + validación + filtrado
    de wildcard) y devuelve los que resuelven de verdad.

    Nunca se usa --skip-validation ni --skip-wildcard-filter: son justo las
    dos cosas que convertirían esto en una fábrica de falsos positivos.
    """
    if not candidatos:
        return []
    entrada = wdir / f"{etiqueta}_candidatos.txt"
    entrada.write_text("\n".join(sorted(candidatos)) + "\n")
    salida = wdir / f"{etiqueta}_resueltos.txt"
    return ejecutar(
        con, programa_id, f"puredns/{etiqueta}", 1,
        [BIN["puredns"], "resolve", str(entrada),
         "-b", BIN["massdns"],
         "-r", RESOLVERS, "--resolvers-trusted", RESOLVERS_TRUSTED,
         "-l", str(RATE_PUBLICO), "--rate-limit-trusted", str(RATE_TRUSTED),
         "-w", str(salida), "-q"],
        salida,
    )


def capa1(con, programa_id, raices, conocidos, wdir, max_palabras=MAX_PALABRAS):
    """
    Permutaciones sobre lo ya conocido + bruteforce de wordlist.

    Es la vía que da el delta sobre subfinder — lo que ninguna fuente pasiva
    publica y, por tanto, lo que la competencia no tiene. Marca `origen`
    como `permutacion` o `bruteforce`, que es lo que alimenta el filtro de
    rarezas del frontend.
    """
    encontrados = {}

    # Permutaciones: gotator necesita una lista de subdominios de partida, así
    # que sin capa 0 previa no hay nada que permutar.
    if conocidos:
        sub_txt  = wdir / "gotator_sub.txt"
        perm_txt = wdir / "gotator_perm.txt"
        sub_txt.write_text("\n".join(sorted(conocidos)) + "\n")
        palabras = Path(WORDLIST).read_text().splitlines()[:2000]
        perm_txt.write_text("\n".join(palabras) + "\n")

        salida = wdir / "gotator.txt"
        candidatos = ejecutar(
            con, programa_id, "gotator", 1,
            [BIN["gotator"], "-sub", str(sub_txt), "-perm", str(perm_txt),
             "-depth", "1", "-numbers", "3", "-mindup", "-adv", "-md", "-silent"],
            salida,
        )
        for s in _resolver_candidatos(con, programa_id, candidatos, wdir, "permutacion"):
            encontrados.setdefault(s.lower(), "permutacion")

    # Bruteforce: wordlist × raíces.
    palabras = Path(WORDLIST).read_text().splitlines()[:max_palabras]
    candidatos = [f"{p.strip()}.{r}" for r in sorted(raices) for p in palabras if p.strip()]
    log.info(f"[bruteforce] {len(candidatos)} candidatos ({len(palabras)} palabras × {len(raices)} raíces)")
    for s in _resolver_candidatos(con, programa_id, candidatos, wdir, "bruteforce"):
        encontrados.setdefault(s.lower(), "bruteforce")

    return encontrados


# ── Resolución (ip / cname / vivo) ───────────────────────────────────────────

def resolver(con, programa_id, subs, wdir):
    """
    dnsx sobre los subdominios: devuelve {sub: {"ip":…, "cname":…}}.

    Un dominio con comodín DNS responde que SÍ a cualquier nombre inventado, así
    que sin filtro entra como superficie viva todo lo que las fuentes pasivas
    escupan, se sondea con httpx y se publica. Medido en la BD: `emarketer.com`
    respondía a todo con 8.8.8.8 —el DNS público de Google— y dejó 499 hosts
    falsos en el informe de Axel Springer, cada uno con un "servicio" que era la
    página de Google; `*.yellow-fellow.moonpay.com` metió 4.437 en MoonPay. El
    bruteforce ya estaba protegido (puredns filtra comodines siempre); esta vía
    no lo estaba, y por eso se filtra aquí con `_comodines()`.

    NO se usa `dnsx -auto-wildcard`: decide por frecuencia (umbral de respuestas
    iguales, `-wt 5` por defecto), así que un objetivo con cientos de subdominios
    tras el mismo CDN se le parece a un comodín. `_comodines()` no cuenta: sondea
    con un nombre inventado y solo descarta lo que resuelva a las IPs con las que
    contesta ese comodín, que es la única prueba de que el nombre no existe.

    Lo filtrado no aparece en la salida, así que queda como `vivo=0`: un nombre
    que solo existe porque el comodín contesta no resuelve de verdad.
    """
    if not subs:
        return {}
    entrada = wdir / "resolver_in.txt"
    entrada.write_text("\n".join(sorted(subs)) + "\n")
    salida = wdir / "dnsx.jsonl"
    lineas = ejecutar(
        con, programa_id, "dnsx", 1,
        [BIN["dnsx"], "-l", str(entrada), "-a", "-cname", "-json", "-silent",
         "-t", str(DNSX_THREADS), "-o", str(salida)],
        salida, esencial=True,
        # `n_entrada` activa el aviso "0 resultados sobre N objetivos". Con dnsx
        # solo tiene sentido cuando la lista es grande: su cometido ES decidir
        # si un nombre existe, así que un 0 sobre unos pocos nombres es la
        # respuesta correcta, no un fallo. Sin este corte, el informe de
        # Infomaniak salía con un error rojo ("no es un resultado fiable")
        # porque el único candidato, `www.manager.infomaniak.com`, no existe
        # —comprobado: NXDOMAIN—. Con muchos nombres a la entrada, en cambio,
        # que NINGUNO resuelva sí apunta a resolvers caídos o rate limit.
        n_entrada=len(subs) if len(subs) >= CERO_DNS_SOSPECHOSO else 0,
    )
    out = {}
    for l in lineas:
        try:
            d = json.loads(l)
        except json.JSONDecodeError:
            continue
        host = (d.get("host") or "").lower()
        if not host:
            continue
        out[host] = {
            "ip":    (d.get("a") or [None])[0],
            "cname": (d.get("cname") or [None])[0],
        }

    comodines = _comodines(con, programa_id, out, wdir)
    if comodines:
        antes = len(out)
        out = {h: d for h, d in out.items()
               if not _bajo_comodin(h, d, comodines)}
        n = antes - len(out)
        log.warning("[dns] %d hosts descartados por comodín DNS en %d rama(s): %s",
                    n, len(comodines), ", ".join(sorted(comodines))[:200])
        _registrar_error("comodin_dns", tool="dnsx", n=n,
                         ramas=", ".join(sorted(comodines))[:120])
    return out


def _rama(host):
    """Lo que cuelga por encima del host: `a.b.c.com` → `b.c.com`."""
    partes = host.split(".", 1)
    return partes[1] if len(partes) == 2 else host


def _comodines(con, programa_id, resueltos, wdir):
    """
    Ramas que responden a CUALQUIER nombre → {rama: {ips del comodín}}.

    Se pregunta por dos nombres inventados de cada rama con al menos tres hijos
    resueltos. Si contestan, esa rama tiene comodín y sus IPs son las que hay
    que descartar: lo que resuelva ahí no existe, solo lo dice el comodín.
    """
    ramas = {}
    for h in resueltos:
        ramas.setdefault(_rama(h), 0)
        ramas[_rama(h)] += 1
    candidatas = [r for r, n in ramas.items() if n >= 3]
    if not candidatas:
        return {}

    sondas = {}
    for r in candidatas:
        for i in range(2):
            sondas[f"zzq{random.randrange(10**8, 10**9)}x{i}.{r}"] = r

    entrada = wdir / "comodin_in.txt"
    entrada.write_text("\n".join(sondas) + "\n")
    salida = wdir / "comodin.jsonl"
    lineas = ejecutar(
        con, programa_id, "dnsx", 1,
        [BIN["dnsx"], "-l", str(entrada), "-a", "-json", "-silent",
         "-t", str(DNSX_THREADS), "-o", str(salida)],
        # SIN `n_entrada`: aquí un cero es el resultado DESEADO, no un fallo. La
        # sonda pregunta por nombres inventados (`zzq…`); que dnsx no resuelva
        # NINGUNO es justo la prueba de que la rama no tiene comodín. Con
        # `n_entrada` se registraba `tool_vacio` y el informe pintaba en rojo
        # "resultado no fiable" en todo programa sano sin comodín (medido: SBB
        # informe 93 salió con `{"tool":"dnsx","n":10,"cod":"tool_vacio"}`).
        salida, esencial=False,
    )
    fuera = {}
    for l in lineas:
        try:
            d = json.loads(l)
        except json.JSONDecodeError:
            continue
        rama = sondas.get((d.get("host") or "").lower())
        if rama:
            fuera.setdefault(rama, set()).update(d.get("a") or [])
    return fuera


def _bajo_comodin(host, datos, comodines):
    """Cierto si el host solo existe porque el comodín de su rama contesta."""
    ips = comodines.get(_rama(host))
    return bool(ips) and (datos or {}).get("ip") in ips


# ── Capa 2: sondeo HTTP ──────────────────────────────────────────────────────

def capa2(con, programa_id, vivos, wdir):
    """
    httpx sobre los subdominios que resuelven → servicios web.

    Solo se sondea lo que está vivo: lanzar httpx contra nombres muertos es
    gastar peticiones contra el target para nada.
    """
    if not vivos:
        return []
    entrada = wdir / "httpx_in.txt"
    entrada.write_text("\n".join(sorted(vivos)) + "\n")
    salida = wdir / "httpx.jsonl"
    lineas = ejecutar(
        con, programa_id, "httpx", 2,
        [BIN["httpx"], "-l", str(entrada), "-json", "-silent",
         "-sc", "-title", "-td", "-server", "-fr", "-cdn",
         "-rl", str(HTTPX_RATE), "-threads", str(HTTPX_THREADS), "-o", str(salida)],
        salida, esencial=True, n_entrada=len(vivos),
    )
    servicios = []
    for l in lineas:
        try:
            d = json.loads(l)
        except json.JSONDecodeError:
            continue
        host = (d.get("input") or d.get("host") or "").split(":")[0].lower()
        if not host:
            continue
        esquema = (d.get("scheme") or "https").lower()
        # WAF/CDN por host, no por programa: lo que importa es si el activo
        # concreto que se va a tocar está detrás de uno. `cdn_type` distingue
        # waf/cdn/cloud, que no es lo mismo a la hora de atacarlo.
        cdn = None
        if d.get("cdn") and d.get("cdn_name"):
            cdn = f"{d['cdn_name']}/{d.get('cdn_type') or 'cdn'}"
        servicios.append({
            "host":     host,
            "puerto":   int(d.get("port") or (443 if esquema == "https" else 80)),
            "protocolo": "tcp",
            "servicio": esquema,
            "version":  None,
            "status":   d.get("status_code"),
            "title":    d.get("title"),
            "tech":     ",".join(d.get("tech") or []) or None,
            "server":   d.get("webserver"),
            "cdn":      cdn,
        })
    return servicios


# ── Capa 3: puertos ──────────────────────────────────────────────────────────

def capa3(con, programa_id, vivos, wdir):
    """
    naabu (top-100) sobre lo vivo y, solo sobre los puertos que ya sabemos
    abiertos, nmap -sV para averiguar qué corre ahí.

    Es la capa que más carga pone en el objetivo, de ahí el ritmo contenido y
    que nmap no barra puertos por su cuenta: se limita a identificar lo que
    naabu ya encontró, para no repetir trabajo sobre el servidor ajeno.
    """
    if not vivos:
        return []
    entrada = wdir / "naabu_in.txt"
    entrada.write_text("\n".join(sorted(vivos)) + "\n")
    salida = wdir / "naabu.txt"
    lineas = ejecutar(
        con, programa_id, "naabu", 3,
        [BIN["naabu"], "-l", str(entrada), "-top-ports", "100",
         "-rate", str(NAABU_RATE), "-silent", "-o", str(salida)],
        salida,
    )

    # naabu escribe "host:puerto"
    abiertos = {}
    for l in lineas:
        if ":" not in l:
            continue
        host, _, puerto = l.rpartition(":")
        if puerto.isdigit():
            abiertos.setdefault(host.lower(), set()).add(int(puerto))
    if not abiertos:
        return []

    # Un host que abre muchísimos puertos no tiene esos servicios: es un
    # firewall/IPS que responde SYN-ACK a todo. Sus puertos son fantasmas, así
    # que se descarta el host entero (ni se sondea con nmap) y consta el porqué.
    respondones = {h: len(p) for h, p in abiertos.items() if len(p) > NAABU_MAX_PUERTOS}
    for h, n in sorted(respondones.items()):
        _registrar_error("naabu_respondon", host=h, n=n)
        del abiertos[h]
    if not abiertos:
        return []

    servicios = []
    for host, puertos in sorted(abiertos.items()):
        lista = ",".join(str(p) for p in sorted(puertos))
        salida_nmap = wdir / f"nmap_{host}.txt"
        for l in ejecutar(
            con, programa_id, "nmap", 3,
            ["nmap", "-sV", "-T3", "-Pn", "-p", lista, "-oG", str(salida_nmap), host],
            salida_nmap,
        ):
            # Formato grepable: "Host: ... Ports: 443/open/tcp//https//nginx 1.25/"
            if "Ports:" not in l:
                continue
            for campo in l.split("Ports:", 1)[1].split(","):
                partes = [p.strip() for p in campo.strip().split("/")]
                if len(partes) < 5 or partes[1] != "open":
                    continue
                servicios.append({
                    "host":      host,
                    "puerto":    int(partes[0]),
                    "protocolo": partes[2] or "tcp",
                    "servicio":  partes[4] or None,
                    "version":   (partes[6] if len(partes) > 6 else None) or None,
                    "status":    None, "title": None, "tech": None, "server": None,
                    "cdn":       None,
                })
    return servicios


# ── Persistencia ─────────────────────────────────────────────────────────────

def persistir(con, programa_id, cls, descubiertos, resueltos):
    """
    Vuelca a `subdominios` + `programa_subdominio` y devuelve los hallazgos.

    Idempotente: un subdominio ya conocido no se duplica ni cambia de `origen`
    (gana quien lo descubrió primero, que es lo que hace fiable la señal de
    rareza). Repetir la misma ejecución no produce hallazgos nuevos.
    """
    hallazgos = {"subdominios_nuevos": [], "takeovers": [], "revividos": []}
    ts = ahora()

    for sub, origen in sorted(descubiertos.items()):
        datos = resueltos.get(sub, {})
        ip, cname = datos.get("ip"), datos.get("cname")
        vivo = 1 if datos else 0

        fila = con.execute(
            "SELECT id, vivo, cname FROM subdominios WHERE subdominio=?", (sub,)
        ).fetchone()

        if fila is None:
            cur = con.execute(
                """INSERT INTO subdominios
                   (subdominio, raiz, origen, vivo, ip, cname,
                    fecha_descubierto, fecha_ultima_vivo)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (sub, recon_scope._apex(sub), origen, vivo, ip, cname,
                 ts, ts if vivo else None),
            )
            sub_id = cur.lastrowid
            hallazgos["subdominios_nuevos"].append(
                {"subdominio": sub, "origen": origen, "ip": ip, "cname": cname, "vivo": vivo}
            )
        else:
            sub_id, vivo_antes, cname_antes = fila
            con.execute(
                """UPDATE subdominios SET vivo=?, ip=?, cname=?,
                   fecha_ultima_vivo=COALESCE(?, fecha_ultima_vivo)
                   WHERE id=?""",
                (vivo, ip, cname, ts if vivo else None, sub_id),
            )
            # Un subdominio que deja de resolver pero conserva su CNAME es la
            # firma clásica de un takeover disponible.
            if vivo_antes == 1 and vivo == 0 and (cname or cname_antes):
                hallazgos["takeovers"].append(
                    {"subdominio": sub, "cname": cname or cname_antes}
                )
            elif vivo_antes == 0 and vivo == 1:
                hallazgos["revividos"].append({"subdominio": sub, "ip": ip})

        in_scope, motivo = recon_scope.clasificar_sub(sub, cls)
        con.execute(
            """INSERT INTO programa_subdominio (programa_id, subdominio_id, in_scope, scope_motivo)
               VALUES (?,?,?,?)
               ON CONFLICT(programa_id, subdominio_id)
               DO UPDATE SET in_scope=excluded.in_scope, scope_motivo=excluded.scope_motivo""",
            (programa_id, sub_id, in_scope, motivo),
        )

    con.commit()
    return hallazgos


def persistir_servicios(con, servicios):
    """
    Vuelca a `servicios`. Un servicio es nuevo si no había fila para ese
    (subdominio, puerto, protocolo) — el UNIQUE de la tabla es quien decide,
    igual que con los subdominios.

    Devuelve la lista de servicios que han sido alta real.
    """
    nuevos = []
    ts = ahora()
    for s in servicios:
        fila = con.execute(
            "SELECT id FROM subdominios WHERE subdominio=?", (s["host"],)
        ).fetchone()
        if not fila:
            continue          # servicio de un host que no está en la tabla: se ignora
        sub_id = fila[0]

        ya = con.execute(
            "SELECT id FROM servicios WHERE subdominio_id=? AND puerto=? AND protocolo=?",
            (sub_id, s["puerto"], s["protocolo"]),
        ).fetchone()

        if ya:
            con.execute(
                """UPDATE servicios SET servicio=COALESCE(?,servicio), version=COALESCE(?,version),
                   status=COALESCE(?,status), title=COALESCE(?,title), tech=COALESCE(?,tech),
                   server=COALESCE(?,server), cdn=COALESCE(?,cdn), fecha_analisis=?
                   WHERE id=?""",
                (s["servicio"], s["version"], s["status"], s["title"],
                 s["tech"], s["server"], s.get("cdn"), ts, ya[0]),
            )
        else:
            con.execute(
                """INSERT INTO servicios
                   (subdominio_id, puerto, protocolo, servicio, version,
                    status, title, tech, server, cdn, fecha_analisis)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (sub_id, s["puerto"], s["protocolo"], s["servicio"], s["version"],
                 s["status"], s["title"], s["tech"], s["server"], s.get("cdn"), ts),
            )
            nuevos.append(s)
    con.commit()
    return nuevos


# ── Orquestación de un job ───────────────────────────────────────────────────

def _bajo(host, ramas):
    """¿`host` cuelga de alguna de `ramas` (o es una de ellas)?"""
    h = (host or "").lower()
    return any(h == r or h.endswith("." + r) for r in ramas)


def _alcanzable(ip):
    """
    ¿Esa IP se puede tocar desde aquí?

    Un subdominio público que resuelve a 10.x/192.168.x es DNS interno filtrado:
    existe y se guarda —la fuga de direccionamiento interno es un hallazgo en sí
    mismo—, pero no hay nada que sondear desde fuera y cada uno cuesta el
    timeout completo de httpx. Medido el 2026-08-19: **797 subdominios vivos de
    la BD apuntan a IP privada y los 797 están sin un solo servicio**; 73 de
    ellos tuvieron a httpx nueve minutos sin devolver una sola respuesta.

    Sin IP (resuelve solo por CNAME) devuelve True: que lo decida el sondeo.
    """
    if not ip:
        return True
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)


def correr(programa_id, raices=None, capas="0123", max_palabras=MAX_PALABRAS,
           directos=None, deadline=None):
    """
    Ejecuta el pipeline sobre un programa.

    `raices=None` significa "todas las del scope" (disparo `programa_nuevo` o
    `periodico`). El disparo `scope_ampliado` pasa solo las del delta.

    `directos` son hosts que ya sabemos cuáles son: entran directamente a
    resolución y sondeo, sin pasar por descubrimiento. Es el camino rápido
    para un asset nuevo concreto — segundos en vez de horas.

    `deadline` (epoch) acota el pase: al agotarse se deja de descubrir y se
    publica lo que haya. Más vale un informe incompleto a tiempo que uno
    completo cuando la ventana ya se cerró.
    """
    _ctx.deadline = deadline
    _ctx.errores = []          # se rellena durante el pase; se devuelve al final
    _ctx.herramientas = set()  # qué herramientas corrieron: para caducar errores viejos
    con = sqlite3.connect(DB_PATH, timeout=30)
    try:
        plat, nombre, sin_, sout = recon_scope.cargar_programa(programa_id)
        cls = recon_scope.clasificar(sin_, sout, plat)
        objetivo = set(raices) if raices is not None else cls["raices"]
        directos = set(directos or [])
        if not objetivo and not directos:
            log.warning(f"[{programa_id}] {nombre}: sin raíces que enumerar")
            return {"subdominios_nuevos": [], "takeovers": [], "revividos": []}

        marca = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        wdir  = RECON_DIR / str(programa_id) / marca
        wdir.mkdir(parents=True, exist_ok=True)
        log.info(f"[{programa_id}] {nombre} ({plat}) — {len(objetivo)} raíces, capas {capas}")
        log.info(f"[{programa_id}] output crudo en {wdir}")

        descubiertos = {}
        # Los hosts que ya vienen dados no se descubren, se dan por descubiertos.
        for h in directos:
            descubiertos[h] = "scope"
        if directos:
            log.info(f"[{programa_id}] {len(directos)} host(s) directo(s) del scope, sin enumerar")

        # Tokens de capa (el worker por fases usa subconjuntos):
        #   c = capa0_ct (CT, rápido)   s = capa0_pasivo (subfinder/gau, lento)
        #   0 = capa 0 completa (CLI/periódico)   1 = bruteforce+github
        #   2 = httpx   3 = puertos
        # Ya no hay corte por plazo: cada herramienta corre hasta terminar, y la
        # rapidez del preliminar la da el reparto por fases (ver docs/recon.md).
        if objetivo and "c" in capas:
            for s, o in capa0_ct(con, programa_id, objetivo, wdir).items():
                descubiertos.setdefault(s, o)
            log.info(f"[capa0-ct] {len(descubiertos)} subdominios únicos")
        if objetivo and "s" in capas:
            for s, o in capa0_pasivo(con, programa_id, objetivo, wdir).items():
                descubiertos.setdefault(s, o)
            log.info(f"[capa0-pasivo] {len(descubiertos)} subdominios únicos")
        if objetivo and "0" in capas:
            for s, o in capa0(con, programa_id, objetivo, wdir).items():
                descubiertos.setdefault(s, o)
            log.info(f"[capa0] {len(descubiertos)} subdominios únicos")
        if objetivo and "1" in capas:
            nuevos = capa1(con, programa_id, objetivo, set(descubiertos), wdir, max_palabras)
            for s, o in nuevos.items():
                descubiertos.setdefault(s, o)
            log.info(f"[capa1] +{len(nuevos)} candidatos resueltos")
            # github va con las capas activas (profundo), no con la 0 (rápido):
            # es pasivo pero lento. Solo aporta origen "github" lo que ninguna
            # fuente anterior tenía.
            antes = len(descubiertos)
            for s in capa_github(con, programa_id, objetivo, wdir):
                descubiertos.setdefault(s, "github")
            log.info(f"[github] +{len(descubiertos) - antes} nuevos")

        resueltos = resolver(con, programa_id, set(descubiertos), wdir)
        log.info(f"[dns] {len(resueltos)}/{len(descubiertos)} resuelven")

        hallazgos = persistir(con, programa_id, cls, descubiertos, resueltos)

        # Capas 2 y 3 solo sobre lo que resuelve y está in-scope: son las que
        # tocan al target, así que no se gastan en colaterales ni en muertos.
        #
        # "In-scope" se decide con el scope de AHORA y sobre TODO lo vivo que
        # cae bajo el alcance del job, no solo sobre lo que este pase acaba de
        # descubrir (criterio del usuario, 2026-08-19). La diferencia importa
        # cuando el asset nuevo es un wildcard: convierte en objetivo a hosts
        # que ya teníamos guardados como colaterales, y esos no tienen por qué
        # reaparecer en el descubrimiento de este pase — sin esto se quedaban
        # sin caracterizar. El alcance (raíces + directos del job) es lo que
        # impide que un asset nuevo acabe sondeando el programa entero.
        alcance = objetivo | directos
        candidatos = {
            s: (d or {}).get("ip") for s, d in resueltos.items()
            if recon_scope.clasificar_sub(s, cls)[0] == 1
        }
        for sub, ip in con.execute(
            """SELECT s.subdominio, s.ip FROM subdominios s
               JOIN programa_subdominio ps ON ps.subdominio_id = s.id
               WHERE ps.programa_id=? AND s.vivo=1""",
            (programa_id,),
        ):
            if (sub not in candidatos and _bajo(sub, alcance)
                    and recon_scope.clasificar_sub(sub, cls)[0] == 1):
                candidatos[sub] = ip
        vivos_in_scope = sorted(s for s, ip in candidatos.items() if _alcanzable(ip))
        n_internos = len(candidatos) - len(vivos_in_scope)
        log.info(f"[capas 2-3] {len(vivos_in_scope)} hosts vivos in-scope bajo el alcance "
                 f"({len(resueltos)} de este pase + guardados; "
                 f"{n_internos} descartados por IP interna)")
        servicios = []
        if "2" in capas:
            servicios += capa2(con, programa_id, vivos_in_scope, wdir)
        if "3" in capas:
            servicios += capa3(con, programa_id, vivos_in_scope, wdir)
        hallazgos["servicios_nuevos"] = persistir_servicios(con, servicios)

        hallazgos["raices"] = sorted(objetivo | directos)
        hallazgos["total_vistos"] = len(descubiertos)
        hallazgos["errores"] = list(_ctx.errores)
        hallazgos["herramientas"] = sorted(_ctx.herramientas)
        log.info(
            f"[{programa_id}] hallazgos: {len(hallazgos['subdominios_nuevos'])} subdominios, "
            f"{len(hallazgos['servicios_nuevos'])} servicios, "
            f"{len(hallazgos['takeovers'])} posibles takeover"
        )
        return hallazgos
    finally:
        con.close()


def main():
    ap = argparse.ArgumentParser(description="Recon de subdominios, capas 0 y 1")
    ap.add_argument("programa_id", type=int)
    ap.add_argument("--capas", default="0123",
                    help="0=pasivo, 1=activo DNS, 2=httpx, 3=puertos (default: 0123)")
    ap.add_argument("--raices", help="lista separada por comas; por defecto, todas las del scope")
    ap.add_argument("--max-palabras", type=int, default=MAX_PALABRAS)
    args = ap.parse_args()

    faltan = [n for n, ruta in BIN.items() if not shutil.which(ruta)]
    if faltan:
        sys.exit(f"faltan herramientas: {', '.join(faltan)}")

    raices = [r.strip() for r in args.raices.split(",")] if args.raices else None
    hallazgos = correr(args.programa_id, raices, args.capas, args.max_palabras)
    print(json.dumps(hallazgos, indent=2, ensure_ascii=False)[:4000])


if __name__ == "__main__":
    main()
