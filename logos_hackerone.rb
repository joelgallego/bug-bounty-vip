#!/usr/bin/env ruby
# frozen_string_literal: true

#
# logos_hackerone.rb — mapa handle -> URL del logo, sin sesión iniciada.
#
# Sustituye al paso manual que documentaba `fetch_iconos_hackerone.py`: pegar
# una query en la consola del navegador con sesión abierta, en lotes de 80, y
# guardar el resultado a mano. Ese script daba por hecho que el GraphQL de
# HackerOne exige el CSRF de una sesión con login, y **no es así**: el token
# que sirve la página pública del directorio vale igual. Es el mismo truco con
# el que el crawler de bounty-targets lee los scopes sin credenciales, así que
# aquí solo se reutiliza su cliente (ver vendor/bounty-targets/README-LOCAL.md).
#
# Comprobado el 2026-08-16 con `security`, `gitlab` y `coinbase`: devuelve las
# URLs de profile-photos.hackerone-user-content.com y de S3 sin una cookie de
# sesión.
#
# Uso:
#   ruby logos_hackerone.rb handle1 handle2 ...     # handles por argumentos
#   echo "h1\nh2" | ruby logos_hackerone.rb         # o por stdin, uno por línea
#
# Salida por STDOUT, en el formato que espera `fetch_iconos_hackerone.py --json`:
#   {"security": {"profile_picture": "https://..."}, ...}
#

$LOAD_PATH.unshift(File.expand_path('vendor/bounty-targets/lib', __dir__))

require 'json'
require 'bounty-targets'

# `teams` acepta hasta 100 por página; 80 deja margen para que la respuesta no
# se acerque a ningún límite de tamaño y sigue siendo pocas peticiones (225
# programas = 3 lotes).
TAMANO_LOTE = 80

CONSULTA = <<~GQL
  query($h: [String!]) {
    teams(first: 100, where: { handle: { _in: $h } }) {
      edges { node { handle name profile_picture(size: xtralarge) } }
    }
  }
GQL

handles = ARGV.empty? ? $stdin.read.split(/\s+/) : ARGV
handles = handles.map(&:strip).reject(&:empty?).uniq
abort('uso: logos_hackerone.rb <handle> [handle...]  (o por stdin)') if handles.empty?

cliente = BountyTargets::Hackerone.new    # aquí obtiene cookie + CSRF anónimos
mapa = {}

handles.each_slice(TAMANO_LOTE) do |lote|
  respuesta = cliente.send(:graphql_query, CONSULTA, h: lote)
  nodos = respuesta.dig('data', 'teams', 'edges') || []
  nodos.each do |edge|
    nodo = edge['node']
    next unless nodo && nodo['handle']

    mapa[nodo['handle']] = {
      'name' => nodo['name'],
      'profile_picture' => nodo['profile_picture'],
    }
  end
  # Un aviso por STDERR para no ensuciar el JSON de STDOUT.
  warn "lote de #{lote.length} handles -> #{nodos.length} respuestas"
end

faltan = handles - mapa.keys
warn "sin respuesta para #{faltan.length} handle(s): #{faltan.first(5).join(', ')}" unless faltan.empty?

puts JSON.generate(mapa)
