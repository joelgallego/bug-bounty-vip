#!/usr/bin/env ruby
# frozen_string_literal: true

#
# generar_feeds.rb — genera los feeds de scopes en local, con el crawler del
# autor de bounty-targets (ver vendor/bounty-targets/README-LOCAL.md).
#
# Es el motor del modo respaldo: cuando la fuente primaria deja de publicar,
# esto produce los mismos `<plataforma>_data.json` que descargaríamos de
# GitHub, para que `sync.py` siga detectando eventos sin enterarse del cambio.
# Quien decide cuándo llamarlo, valida el resultado y lo promueve es
# `respaldo.py`; aquí solo se scrapea.
#
# Uso:
#   ruby generar_feeds.rb <directorio_salida> [plataforma1,plataforma2,...]
#
# Escribe un resumen JSON por STDOUT (lo lee respaldo.py):
#   {"resultados": {"hackerone": {"ok": true, "programas": 451, "segundos": 533.0},
#                   "bugcrowd":  {"ok": false, "error": "..."}}}
#
# DOS DIFERENCIAS DELIBERADAS con el `CLI#scan!` del upstream:
#
# 1. AISLAMIENTO. Él une los hilos con `flat_map(&:value)`, así que la excepción
#    de una plataforma se propaga y aborta el barrido de todas — por eso su
#    fuente lleva días parada por un fallo que solo afecta a Bugcrowd. Aquí cada
#    plataforma se captura por separado: las que funcionan entregan su feed.
#
# 2. SIN `uris`/`domains.txt`. Su `scan!` además agrega dominios y wildcards a
#    ficheros aparte y aborta si una plataforma no devuelve ninguno. Nosotros no
#    consumimos esos ficheros (el scope lo parsea `recon_scope.py` desde el JSON),
#    así que no se generan.
#
# El paralelismo es UN HILO POR PLATAFORMA, nunca dentro de una: el rate limit
# es por host, así que lanzarlas juntas no aprieta más a ninguna, mientras que
# paralelizar las ~450 consultas de HackerOne sería la mejor forma de ganarse un
# bloqueo (ya se le nota freno progresivo: 8,9 min medidos, el doble de lo que
# anticipaba una muestra de 8 programas).
#

$LOAD_PATH.unshift(File.expand_path('vendor/bounty-targets/lib', __dir__))

require 'json'
require 'bounty-targets'

PLATAFORMAS = {
  'hackerone' => -> { BountyTargets::Hackerone.new },
  'bugcrowd'  => -> { BountyTargets::Bugcrowd.new },
  'intigriti' => -> { BountyTargets::Intigriti.new },
  'yeswehack' => -> { BountyTargets::YesWeHack.new },
  'federacy'  => -> { BountyTargets::Federacy.new }
}.freeze

salida = ARGV[0] or abort('uso: generar_feeds.rb <directorio_salida> [plataformas]')
pedidas = ARGV[1] ? ARGV[1].split(',') : PLATAFORMAS.keys
desconocidas = pedidas - PLATAFORMAS.keys
abort("plataformas desconocidas: #{desconocidas.join(', ')}") unless desconocidas.empty?

require 'fileutils'
FileUtils.mkdir_p(salida)

resultados = {}
mutex = Mutex.new

hilos = pedidas.map do |nombre|
  Thread.new do
    t0 = Time.now
    begin
      datos = PLATAFORMAS[nombre].call.scan
      # El fichero se escribe entero o no se escribe: un JSON a medias es peor
      # que ninguno, porque parece bueno.
      tmp = File.join(salida, "#{nombre}_data.json.tmp")
      File.write(tmp, JSON.pretty_generate(datos))
      File.rename(tmp, File.join(salida, "#{nombre}_data.json"))
      mutex.synchronize do
        resultados[nombre] = { ok: true, programas: datos.length,
                               segundos: (Time.now - t0).round(1) }
      end
    rescue StandardError => e
      # Capturar aquí es la razón de ser de este script: que Bugcrowd esté roto
      # no puede dejarnos sin HackerOne, Intigriti y YesWeHack.
      mutex.synchronize do
        resultados[nombre] = { ok: false, error: "#{e.class}: #{e.message}"[0, 300],
                               segundos: (Time.now - t0).round(1) }
      end
    end
  end
end
hilos.each(&:join)

puts JSON.generate(resultados: resultados)
