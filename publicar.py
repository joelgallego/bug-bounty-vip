#!/usr/bin/env python3
"""
publicar.py — publica la web (export_json.py --deploy) automáticamente y
coordinado entre procesos (sync y worker).

Antes NADIE publicaba: sync y el worker escribían informes en la BD, pero solo
un `export_json.py --deploy` a mano los subía. Un evento fresco podía tardar
horas (o no salir nunca) sin intervención. Aquí está el disparador que faltaba.

Contrato:
  publicar(forzar=True)  — publica YA. Para eventos de sync: el valor del
                           proyecto es llegar pronto, no puede esperar.
  publicar(forzar=False) — respeta un debounce (DEBOUNCE_S): como mucho un
                           deploy por ventana. Para el goteo del worker durante
                           una tanda, que si no encadenaría un deploy por job.
  conciliar()            — red de seguridad periódica: comprueba si producción
                           refleja la BD y publica solo si no. Ver abajo.

Un lock de fichero impide que dos procesos publiquen a la vez (dos deploys
concurrentes se pisarían). El "estado final" de una tanda lo garantiza quien
llame con forzar=True al vaciarse la cola (ver recon_worker.vaciar_cola).

POR QUÉ HACE FALTA `conciliar` (2026-08-15). Los disparos de arriba son todos
reactivos: publican en el momento en que pasa algo. Si ese único intento falla,
no lo reintenta nadie y la web se queda atrás indefinidamente. Ocurrió: el
2026-08-12 a las 14:02 el pase profundo de Klarna terminó, marcó su informe
como definitivo en la BD... y los dos deploys siguientes fallaron con
`Temporary failure in name resolution` (la máquina se quedó sin red justo
entonces). Producción siguió TRES DÍAS anunciando ese informe como preliminar,
con la BD correcta y sin que nada lo señalara: no hubo más eventos que
dispararan otra publicación, y el reinicio del 14 tampoco ayudó porque el
worker solo publica si procesó algún job.

La respuesta es una comprobación periódica que no depende de que haya pasado
nada: regenerar los JSON (0,14 s, y el export es determinista — medido) y
comparar la huella de `web/` con la de lo último publicado CON ÉXITO. Si
coinciden no se toca nada; si no, se publica. Así el sistema se repara solo en
cuanto vuelva la red, sobreviva un apagón o un reinicio, y da igual cuál de los
disparos reactivos fallara.

Corolario: `.publicar.stamp` y `.publicar.huella` se escriben SOLO si el deploy
salió bien. Antes el stamp se escribía siempre, así que un deploy fallido se
apuntaba como bueno y encima bloqueaba el debounce de los 90 s siguientes.
"""
import argparse
import fcntl
import hashlib
import logging
import subprocess
import sys
import time
from pathlib import Path

BASE = Path(__file__).resolve().parent
WEB_DIR = BASE.parent / "web"
LOCK = BASE / ".publicar.lock"
STAMP = BASE / ".publicar.stamp"      # epoch del último deploy CON ÉXITO
HUELLA = BASE / ".publicar.huella"    # huella de web/ tal y como se publicó
DEBOUNCE_S = 90
# Mismo criterio de exclusión que deploy.py: lo que no sube, no cuenta para
# decidir si hay que subir.
EXCLUIDOS = {"deploy.py"}


def _huella_web():
    """
    Huella del contenido de `web/`: qué se publicaría ahora mismo.

    Cubre el árbol entero, no solo los JSON: un retoque en `index.html` o en un
    fichero de i18n también es algo que producción no tiene todavía.
    """
    h = hashlib.sha256()
    for ruta in sorted(WEB_DIR.rglob("*")):
        if not ruta.is_file() or ruta.name in EXCLUIDOS:
            continue
        h.update(str(ruta.relative_to(WEB_DIR)).encode())
        h.update(hashlib.sha256(ruta.read_bytes()).digest())
    return h.hexdigest()


def _huella_publicada():
    try:
        return HUELLA.read_text().strip()
    except OSError:
        return ""


def _ultimo_deploy():
    try:
        return float(STAMP.read_text())
    except (OSError, ValueError):
        return 0.0


def _deploy(log=None):
    r = subprocess.run(
        [sys.executable, str(BASE / "export_json.py"), "--deploy"],
        capture_output=True, text=True,
    )
    ok = r.returncode == 0
    if ok:
        # Solo tras un deploy bueno: si falló, ni el reloj ni la huella pueden
        # decir que producción está al día, porque no lo está.
        STAMP.write_text(str(time.time()))
        HUELLA.write_text(_huella_web())
    if log:
        msg = "web publicada" if ok else f"deploy falló: {(r.stderr or r.stdout)[-300:]}"
        (log.info if ok else log.warning)(msg)
    return ok


def publicar(forzar=False, log=None):
    """Publica con lock + debounce. Devuelve True si publicó en esta llamada."""
    f = open(LOCK, "w")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False        # otro proceso está publicando; su deploy cubre
        if forzar or (time.time() - _ultimo_deploy() >= DEBOUNCE_S):
            return _deploy(log)
        return False
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        except OSError:
            pass
        f.close()


def conciliar(log=None):
    """
    ¿Refleja producción lo que hay en la BD? Si no, lo publica.

    Regenera los JSON desde la BD y compara la huella de `web/` con la de lo
    último publicado con éxito. Idempotente y barata: si no hay nada que hacer
    no toca la red.

    Devuelve si producción queda al día (ya lo estaba o se ha publicado), no si
    ha publicado: así el que la llama —el timer— falla solo cuando la web sigue
    desfasada, que es lo único que merece verse en rojo.

    No llama a `publicar()` a propósito: ya sostiene el lock, y flock bloquea
    también entre dos descriptores del mismo proceso.
    """
    f = open(LOCK, "w")
    try:
        try:
            fcntl.flock(f, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            # Hay un deploy en curso: ese deja la web al día. Y si fallara, el
            # siguiente tick del timer lo recoge.
            if log:
                log.info("conciliar: otro proceso está publicando, se deja estar")
            return True

        r = subprocess.run(
            [sys.executable, str(BASE / "export_json.py")],
            capture_output=True, text=True,
        )
        if r.returncode != 0:
            if log:
                log.warning(f"conciliar: el export falló: {(r.stderr or r.stdout)[-300:]}")
            return False

        if _huella_web() == _huella_publicada():
            if log:
                log.info("conciliar: producción al día, no se publica")
            return True

        if log:
            log.warning("conciliar: producción NO refleja la BD "
                        "(deploy fallido, reinicio o apagón) — publicando")
        return _deploy(log)
    finally:
        try:
            fcntl.flock(f, fcntl.LOCK_UN)
        except OSError:
            pass
        f.close()


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Publica la web en Cloudflare")
    ap.add_argument("--conciliar", action="store_true",
                    help="publicar solo si producción no refleja ya la BD")
    args = ap.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(message)s")
    log = logging.getLogger("publicar")
    # Uso manual sin flags: fuerza una publicación.
    ok = conciliar(log=log) if args.conciliar else publicar(forzar=True, log=log)
    sys.exit(0 if ok else 1)
