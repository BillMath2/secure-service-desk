#!/bin/sh
set -eu
[ "$#" -eq 0 ] || exit 1
# No model request is accepted before the namespace policy is installed.
/usr/sbin/nft -f - <<'POLICY'
add table inet service_desk_model
delete table inet service_desk_model
table inet service_desk_model {
 chain output {
  type filter hook output priority -150; policy drop;
  ct direction reply ct state established tcp sport 11434 accept
  # Ollama communicates with its local inference runner over IPv4 loopback.
  ip daddr 127.0.0.1 oifname "lo" meta l4proto tcp accept
 }
}
POLICY
exec /usr/bin/setpriv --reuid=65532 --regid=65532 --clear-groups \
  --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
  /bin/ollama serve
