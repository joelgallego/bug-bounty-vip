# vendor/bounty-targets — copia local del crawler de arkadiyt

Copia de [`arkadiyt/bounty-targets`](https://github.com/arkadiyt/bounty-targets)
(**licencia MIT**, ver `LICENSE.md`), usada como **respaldo** cuando la fuente
primaria `bounty-targets-data` deja de publicar. Ver `PROGRAMAS.md` →
"Respaldo local de la fuente".

- **Vendorizado el**: 2026-08-15
- **Commit de origen**: `a5e8635e5bd56550be6d61616c213ba623ba2462` (2026-08-15, resincronizado el 2026-08-16)
- **Solo `lib/`**: no se copia `bin/bounty-targets` ni se usa `CLI#run!`, que
  clona el repo del autor y hace push con sus claves SSH. Aquí se llama
  directamente a `<Plataforma>#scan`, que no necesita git ni credenciales.

Se copia en vez de clonar a propósito: así un cambio suyo no puede alterar lo
que ejecutamos sin que nos enteremos. La contrapartida es que hay que
resincronizar a mano de vez en cuando, comprobando si los parches locales
(hoy ninguno) siguen haciendo falta.

## Parches locales: ninguno (desde 2026-08-16)

**Hubo uno**, entre el 15 y el 16 de agosto: Bugcrowd cambió `briefUrl` de URL
absoluta a ruta relativa (`/engagements/nubank`) alrededor del 2026-08-12 12:34
UTC, y como `parse_program` usaba `uri.host` para pedir el brief, `SsrfFilter`
lanzaba `InvalidUriScheme: URI scheme ''`. Al unir el upstream sus hilos con
`flat_map(&:value)`, esa excepción abortaba el barrido de las CUATRO
plataformas: es lo que tuvo su fuente parada 3,5 días.

**Ya no hace falta**: el autor lo arregló en `Fix bugcrowd (#209)`
(2026-08-15 23:51 UTC) y esta copia se resincronizó con su versión, que además
trae dos mejoras que nuestro parche no tenía — `.compact` en `scan` y
`return if response.code == '403'` en `parse_program`, para saltar engagements
que responden 403 en vez de reventar. Verificado tras resincronizar: 250
programas en 387 s.

Si vuelve a hacer falta parchear algo, **anótalo aquí**: la gracia de vendorizar
es saber exactamente en qué nos separamos del upstream.

## Dependencias

Gems: `ssrf_filter`, `nokogiri`, `twingly-url`, `kramdown`, `base64`. La última
ya no viene por defecto desde Ruby 3.4 (aquí corre 3.4.10; el proyecto declara
3.2.0 en `.ruby-version`, pero funciona). Instaladas con `gem install --user-install`.
`sentry-raven` NO hace falta: solo lo usa `bin/bounty-targets`, que no usamos.
