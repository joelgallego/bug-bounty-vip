#!/usr/bin/env python3
"""
recon_scope.py — Parseo de scope para el recon (fase 0).

Dado el scope de un programa, produce:
  - raices: apex a enumerar con subfinder (ámbito B = wildcards + hosts/url).
  - matchers para clasificar un subdominio DESCUBIERTO en (in_scope, scope_motivo).

Normaliza las siete plataformas (claves y vocabulario de tipos distintos).
Apex vía Public Suffix List (tldextract) para acertar con TLDs compuestos
(anext.com.sg -> anext.com.sg, no com.sg) y wildcards raros (*-vpn.8x8.com -> 8x8.com).

Uso CLI (prueba):  python3 recon_scope.py <programa_id>
"""
import json
import sqlite3
import sys
from fnmatch import fnmatchcase
from pathlib import Path

import tldextract

# El directorio de este fichero: las rutas cuelgan de donde vive el proyecto,
# no de una ruta absoluta de una máquina concreta.
BASE = Path(__file__).resolve().parent

DB_PATH = str(BASE / "programas.db")
_EXT = tldextract.TLDExtract()

# (clave identificador, clave tipo) por plataforma
KEYS = {
    "hackerone": ("asset_identifier", "asset_type"),
    "intigriti": ("endpoint", "type"),
    "yeswehack": ("target", "type"),
    "bugcrowd":  ("target", "type"),
    # Federacy (añadida 2026-08-16) usa el mismo par que YesWeHack/Bugcrowd.
    # Sus tipos son `website`, `api`, `mobile` y `desktop`: los dos primeros
    # entran por TIPOS_HOST y los otros dos se ignoran, como el resto de
    # assets que no son DNS.
    "federacy":  ("target", "type"),
    # GObugfree (añadida 2026-08-16, feed propio de `fetch_gobugfree.py`) usa el
    # mismo par. Sus tipos son `website`, `android`, `ios`, `source_code` y
    # `other`: el primero entra por TIPOS_HOST, los wildcards (`*.swissbankers.ch`,
    # `g-*.0.threema.ch`) los detecta `_wildcard_de_host` por el patrón, y el
    # resto se ignora. OJO: esta plataforma no publica out-of-scope, así que sus
    # programas nunca traen exclusiones — es un hueco de la fuente, no del parser.
    "gobugfree": ("target", "type"),
    # Standoff 365 (añadida 2026-08-19, feed propio de `fetch_standoff.py`) usa
    # el mismo par. Sus tipos ya vienen traducidos a este vocabulario por el
    # fetcher: `website`, `wildcard`, `cidr`, `ip_address`, `android`, `ios` y
    # `other`. OJO: como GObugfree, tampoco publica out-of-scope, así que sus
    # programas nunca traen exclusiones — hueco de la fuente, no del parser.
    "standoff":  ("target", "type"),
}

# Bugcrowd no tiene tipo `wildcard`: sus wildcards viajan dentro de `website`
# como `*.x.com`, así que aquí el tipo no basta y manda el patrón del
# identificador (la comprobación `ident.startswith("*")` de abajo).
TIPOS_WILDCARD = {"wildcard"}
TIPOS_HOST     = {"url", "web-application", "api", "application", "website"}
TIPOS_IP       = {"cidr", "iprange", "ip_address", "network"}   # fuera de v1 (recon por ASN/reverse-DNS)
TIPOS_OTHER    = {"other"}
# el resto (android, ios, source_code, hardware, smart_contract, iot, ...) se ignora

# Dominios que ALOJAN assets de otros: el programa pone ahí su repo, su
# extensión, su app o su plugin, pero el dominio no es suyo. Enumerarlos
# significaría lanzar el recon contra GitHub, Google o Apple por un asset que
# solo está hospedado allí — fuera de scope y contra los ToS de todas las
# plataformas.
#
# Medido el 2026-08-10: en la BD viva `github.com` ya figuraba como raíz de 11
# programas activos (y `google.com`, `amazonaws.com`, `apple.com`...). No había
# llegado a enumerarse ninguno (0 filas en `subdominios` con esas raíces), así
# que esto tapa un agujero latente, no repara un escaneo ya hecho.
#
# Solo bloquea la ENUMERACIÓN del apex. El asset concreto que sí está listado
# (`marketplace.atlassian.com`) sigue siendo in-scope por `hosts`: no se deja de
# mirar nada que el programa haya puesto en su scope, se deja de adivinar
# hermanos suyos en casa ajena.
TERCEROS = {
    # código y paquetes
    "github.com", "github.io", "gitlab.com", "bitbucket.org", "npmjs.com",
    "pypi.org", "rubygems.org", "packagist.org", "hub.docker.com", "gcr.io",
    # tiendas y marketplaces
    "apple.com", "google.com", "microsoft.com", "atlassian.com", "atlassian.net",
    "shopify.com", "salesforce.com", "wordpress.com", "wordpress.org",
    # nube y SaaS donde cualquiera tiene un subdominio
    "amazonaws.com", "googleapis.com", "azurewebsites.net", "herokuapp.com",
    "cloudfront.net", "firebaseapp.com", "web.app", "netlify.app", "vercel.app",
    "pages.dev", "workers.dev", "zendesk.com", "sendgrid.net", "auth0.com",
    "apigee.net", "facebook.com", "trello.com",
}


def _host_bruto(ident):
    """
    La parte de host del identificador: sin esquema, credenciales, puerto ni
    ruta, en minúsculas. A diferencia de `_host()`, NO pasa por tldextract, así
    que conserva los comodines — que es justo lo que hay que mirar para saber
    si un asset es un wildcard.
    """
    s = ident.strip().split("://", 1)[-1]     # fuera el esquema
    s = s.split("/", 1)[0].split("?", 1)[0]   # fuera la ruta
    s = s.split("@")[-1]                      # fuera user:pass@
    cabeza, sep, cola = s.rpartition(":")     # fuera el puerto
    if sep and cola.isdigit():
        s = cabeza
    return s.lower().strip(". ")


def _wildcard_de_host(ident):
    """
    ¿El comodín está en el nombre de host, o en la ruta?

    `*.acme.com` dice "todo subdominio de acme.com es mío". `github.com/acme/*`
    dice justo lo contrario: que solo esa carpeta lo es. Distinguirlos importa
    por dos motivos: un wildcard de host es la prueba de propiedad que exime de
    TERCEROS (caso real: Uphold lista `github.com/uphold/*` y sin esto reabría
    GitHub entero a la enumeración), y es también lo que decide si un asset
    entra como patrón wildcard o como host suelto.

    Mira el HOST, no la cadena cruda: los scopes escriben el comodín detrás del
    esquema (`https://*.uscc.com`) y en medio de la etiqueta (`static*.twilio.com`,
    `*dev*.arlo.com`). Medido el 2026-08-11: 216 wildcards en 69 programas
    activos se estaban clasificando como hosts concretos por comprobar
    `startswith("*")` sobre el identificador entero — 125 de ellos en HackerOne.
    """
    return "*" in _host_bruto(ident)


def _norm(item, plat):
    kid, ktype = KEYS[plat]
    ident = (item.get(kid) or "").strip()
    tipo  = (item.get(ktype) or "").strip().lower()
    return ident, tipo


def _host(ident):
    """hostname limpio (sin esquema/ruta); '' si no parseable como dominio."""
    return _EXT(ident).fqdn


def _apex(ident):
    """registrable domain (eTLD+1) vía PSL; '' si no aplica."""
    return _EXT(ident).top_domain_under_public_suffix


def clasificar(scope_in_raw, scope_out_raw, plat):
    """Devuelve dict con raices + matchers de in-scope/exclusión."""
    items_in  = json.loads(scope_in_raw)  if scope_in_raw  else []
    items_out = json.loads(scope_out_raw) if scope_out_raw else []

    raices, wildcards, hosts, indeterminados = set(), set(), set(), set()
    wild_apex = set()          # apex pelado de cada wildcard in-scope (*.x.com -> x.com in-scope)
    dominio_propio = set()     # apex con wildcard DE HOST: prueba de propiedad (ver TERCEROS)
    excl_wild, excl_host = set(), set()

    for item in items_in:
        ident, tipo = _norm(item, plat)
        if not ident:
            continue
        if item.get("eligible_for_submission") is False:   # flag hackerone
            continue

        if tipo in TIPOS_WILDCARD or _wildcard_de_host(ident):
            # El patrón se guarda normalizado (sin esquema ni ruta): es lo que
            # se compara luego con un hostname en `clasificar_sub`, y
            # `https://*.uscc.com` no casa jamás contra `foo.uscc.com`.
            patron = _host_bruto(ident)
            wildcards.add(patron)
            if (ap := _apex(ident)):
                # El apex solo entra in-scope cuando el patrón es exactamente
                # `*.<apex>`, que es el que dice "cualquier cosa bajo este
                # dominio, incluido él". `*.dev.acme.com` no pone `acme.com`
                # en scope, y `bugcrowd-*your-own-instance*.cloud.mattermost.com`
                # (caso real, Mattermost) menos aún: ahí lo in-scope son las
                # instancias que crea el propio investigador, no el sitio.
                if patron == f"*.{ap}":
                    wild_apex.add(ap)
                # Un comodín dentro del propio dominio registrable
                # (`api-*exoscale.com`) no da una raíz enumerable: no hay
                # dominio que pasarle a subfinder.
                if "*" not in ap:
                    raices.add(ap)
                    if _wildcard_de_host(ident):
                        dominio_propio.add(ap)
        elif tipo in TIPOS_HOST:
            if (h := _host(ident)):
                hosts.add(h.lower())
                if (ap := _apex(ident)):        # ámbito B: enumeramos el apex por hermanos
                    raices.add(ap)
        elif tipo in TIPOS_OTHER:
            if (h := _host(ident)):
                indeterminados.add(h.lower())
                if (ap := _apex(ident)):
                    raices.add(ap)
        # TIPOS_IP y demás: ignorados en v1

    # Casa ajena fuera de la enumeración, salvo que el programa demuestre ser
    # el dueño: un `*.atlassian.com` in-scope es Atlassian: enumerar es lo
    # correcto. Una URL suelta a `marketplace.atlassian.com` es un plugin de
    # otro alojado allí, y ahí no se enumera nada.
    raices -= (TERCEROS - dominio_propio)

    for item in items_out:
        ident, tipo = _norm(item, plat)
        if not ident:
            continue
        # Misma normalización que in-scope: una exclusión escrita
        # `https://*.dev.acme.com` tiene que excluir de verdad.
        if tipo in TIPOS_WILDCARD or _wildcard_de_host(ident):
            excl_wild.add(_host_bruto(ident))
        elif (h := _host(ident)):
            excl_host.add(h.lower())

    return {
        "raices": raices, "wildcards": wildcards, "wild_apex": wild_apex, "hosts": hosts,
        "excl_wild": excl_wild, "excl_host": excl_host,
        "indeterminados": indeterminados,
    }


def clasificar_sub(sub, cls):
    """(in_scope, scope_motivo) para un subdominio descubierto."""
    s = sub.lower()
    if s in cls["excl_host"] or any(fnmatchcase(s, w) for w in cls["excl_wild"]):
        return 0, "exclusion"
    if s in cls["hosts"]:
        return 1, "listado"
    if s in cls["wild_apex"] or any(fnmatchcase(s, w) for w in cls["wildcards"]):
        return 1, "wildcard"
    if s in cls["indeterminados"]:
        return 0, "indeterminado"
    return 0, "colateral"


def cargar_programa(programa_id):
    con = sqlite3.connect(DB_PATH)
    row = con.execute(
        "SELECT plataforma, nombre, scope_raw_in, scope_raw_out FROM programas WHERE id=?",
        (programa_id,),
    ).fetchone()
    con.close()
    if not row:
        sys.exit(f"programa {programa_id} no existe")
    return row


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("uso: python3 recon_scope.py <programa_id>")
    pid = int(sys.argv[1])
    plat, nombre, sin, sout = cargar_programa(pid)
    cls = clasificar(sin, sout, plat)
    print(f"[{pid}] {nombre} ({plat})")
    print(f"  raíces a enumerar ({len(cls['raices'])}): {sorted(cls['raices'])[:15]}")
    print(f"  wildcards in-scope ({len(cls['wildcards'])}): {sorted(cls['wildcards'])[:8]}")
    print(f"  hosts listados ({len(cls['hosts'])}): {sorted(cls['hosts'])[:8]}")
    print(f"  exclusiones: {len(cls['excl_wild'])} wild + {len(cls['excl_host'])} host")
    print(f"  indeterminados: {len(cls['indeterminados'])}")
    # prueba de clasificación con ejemplos sintéticos sobre la primera raíz
    if cls["raices"]:
        r = sorted(cls["raices"])[0]
        for ej in (f"api.{r}", f"dev-staging.{r}", r):
            print(f"    clasificar_sub({ej!r}) -> {clasificar_sub(ej, cls)}")
