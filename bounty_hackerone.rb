#!/usr/bin/env ruby
# frozen_string_literal: true

#
# bounty_hackerone.rb — importes de recompensa por programa, sin sesión iniciada.
#
# El feed de bounty-targets-data NO publica importes de HackerOne (sus claves por
# programa son `offers_bounties`, tiempos medios y `response_efficiency_percentage`),
# así que `max_bounty` estaba a NULL en los 226 programas activos de la plataforma
# mientras las otras cinco lo tenían al 100%. El GraphQL público sí los da: es el
# mismo cliente anónimo que usa `logos_hackerone.rb` (ver su cabecera).
#
# Campos que se leen del tipo Team:
#   maximum_bounty_table_value / minimum_bounty_table_value — techo y suelo de la
#     tabla de recompensas. El techo es lo que HackerOne enseña como "hasta X"
#     (comprobado: amazonvrp-devices → 30000, que es lo que muestra su web).
#   hide_bounty_amounts — se lee pero NO se usa para descartar. Comprobado el
#     2026-08-19 renderizando cinco páginas públicas sin sesión (vodafone_oman,
#     varonis, adobe, nintendo, robinhood, los cinco con el flag a true): las
#     cinco muestran su tabla de recompensas, y su techo coincide con
#     `maximum_bounty_table_value` (adobe $2.500-$15.000, nintendo hasta
#     $50.000...). Lo que el flag gobierna es el TOTAL REPARTIDO, no la tabla:
#     comparado el mismo elemento (`spec-bounties-paid-l90d`) con el flag a
#     false y a true, amazonvrp-devices publica la cifra exacta ($191.152) y
#     varonis/adobe la difuminan en un rango ($1-$5.000, $290.000-$295.000).
#     Descartar por este flag dejaba 49 de 226 programas sin importe.
#   currency — la BD tiene columna `moneda`; se guarda tal cual, sin convertir.
#
# Uso:
#   ruby bounty_hackerone.rb handle1 handle2 ...     # o por stdin, uno por línea
# Salida por STDOUT: {"handle": {"max": 30000, "min": 200, "moneda": "USD",
#                                "oculta": false}, ...}
#

$LOAD_PATH.unshift(File.expand_path('vendor/bounty-targets/lib', __dir__))

require 'json'
require 'bounty-targets'

TAMANO_LOTE = 80   # `teams` acepta 100; 80 deja margen de tamaño de respuesta

CONSULTA = <<~GQL
  query($h: [String!]) {
    teams(first: 100, where: { handle: { _in: $h } }) {
      edges { node { handle currency hide_bounty_amounts
                     maximum_bounty_table_value minimum_bounty_table_value } }
    }
  }
GQL

handles = ARGV.empty? ? $stdin.read.split(/\s+/) : ARGV
handles = handles.map(&:strip).reject(&:empty?).uniq
abort('uso: bounty_hackerone.rb <handle> [handle...]  (o por stdin)') if handles.empty?

cliente = BountyTargets::Hackerone.new
mapa = {}

handles.each_slice(TAMANO_LOTE) do |lote|
  respuesta = cliente.send(:graphql_query, CONSULTA, h: lote)
  nodos = respuesta.dig('data', 'teams', 'edges') || []
  nodos.each do |edge|
    n = edge['node']
    next unless n && n['handle']

    mapa[n['handle']] = {
      'max' => n['maximum_bounty_table_value'],
      'min' => n['minimum_bounty_table_value'],
      'moneda' => n['currency']&.upcase,
      'oculta' => n['hide_bounty_amounts'] ? true : false,
    }
  end
  warn "lote de #{lote.length} handles -> #{nodos.length} respuestas"
end

faltan = handles - mapa.keys
warn "sin respuesta para #{faltan.length} handle(s): #{faltan.first(5).join(', ')}" unless faltan.empty?

puts JSON.generate(mapa)
