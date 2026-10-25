#!/usr/bin/env bash
# Runs the post-quantum hybrid TLS handshake matrix between a JDK 27 and an older JDK,
# and writes raw logs plus a summary table into results/.
#
# Usage: ./run-matrix.sh <JDK 27 home> <older JDK home> [output dir]
# Example:
#   ./run-matrix.sh /Library/Java/JavaVirtualMachines/jdk-27.jdk/Contents/Home \
#                   /Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home
set -u

if [ $# -lt 2 ]; then
  sed -n '2,8p' "$0"
  exit 2
fi

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$HERE
JDK_NEW=$1
JDK_OLD=$2
SERVER_PORT=${SERVER_PORT:-18443}
PROXY_PORT=${PROXY_PORT:-19443}
PASS=changeit # throwaway password for a localhost-only test keystore

feature_version() {
  "$1/bin/java" -XshowSettings:properties -version 2>&1 | awk -F'= ' '/java.specification.version/ {print $2}'
}
full_version() { # exact runtime version, e.g. 25.0.5
  "$1/bin/java" -XshowSettings:properties -version 2>&1 |
    awk -F' = ' '{ key = $1; gsub(/^[[:space:]]+/, "", key) } key == "java.version" { print $2 }'
}
NEW_VER=$(feature_version "$JDK_NEW")
OLD_VER=$(feature_version "$JDK_OLD")
if [ -z "$NEW_VER" ] || [ -z "$OLD_VER" ]; then
  echo "Could not run bin/java from both JDK homes."
  exit 2
fi
NEW_FULL=$(full_version "$JDK_NEW")
OLD_FULL=$(full_version "$JDK_OLD")
if [ "$NEW_VER" -lt 27 ]; then
  echo "Note: the first JDK is $NEW_FULL. Hybrid groups (JEP 527) need JDK 27 or a backport such as 25.0.5; builds without them just negotiate classical groups."
fi

# Case names use the feature version ("27", "21") unless both JDKs share it; then the exact version.
NEW_LABEL=$NEW_VER
OLD_LABEL=$OLD_VER
if [ "$NEW_VER" = "$OLD_VER" ]; then
  NEW_LABEL=$NEW_FULL
  OLD_LABEL=$OLD_FULL
fi
if [ "$NEW_LABEL" = "$OLD_LABEL" ]; then
  NEW_LABEL=new
  OLD_LABEL=old
fi

OUT=${3:-$HERE/results/$(date +%F)-pq-tls-jdk$NEW_FULL-vs-jdk$OLD_FULL}
if [ -e "$OUT" ] && [ -n "$(ls -A "$OUT" 2>/dev/null)" ]; then
  echo "$OUT already has files. Pass a different output dir; evidence is never overwritten."
  exit 2
fi
WORK=$HERE/work
mkdir -p "$OUT" "$WORK"

# Self-signed EC certificate for localhost, plus a trust store holding it.
if [ ! -f "$WORK/server.p12" ]; then
  "$JDK_OLD/bin/keytool" -genkeypair -alias server -keyalg EC -groupname secp256r1 \
    -dname CN=localhost -ext SAN=dns:localhost,ip:127.0.0.1 -validity 365 \
    -keystore "$WORK/server.p12" -storetype PKCS12 -storepass "$PASS" >/dev/null 2>&1
  "$JDK_OLD/bin/keytool" -exportcert -alias server -keystore "$WORK/server.p12" \
    -storepass "$PASS" -file "$WORK/server.cer" >/dev/null 2>&1
  "$JDK_OLD/bin/keytool" -importcert -noprompt -alias server -file "$WORK/server.cer" \
    -keystore "$WORK/trust.p12" -storetype PKCS12 -storepass "$PASS" >/dev/null 2>&1
fi

# Machine details only; no hostname or username, so the folder is safe to quote from.
{
  echo "date: $(date '+%F %T %Z')"
  if command -v sw_vers >/dev/null 2>&1; then
    echo "os: $(sw_vers -productName) $(sw_vers -productVersion) ($(uname -m))"
    echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null)"
  else
    echo "os: $(uname -sr) ($(uname -m))"
  fi
  echo "network: loopback only (client -> byte-counting proxy -> server on 127.0.0.1)"
  echo
  echo "new JDK ($NEW_FULL):"; "$JDK_NEW/bin/java" -version 2>&1
  echo
  echo "old JDK ($OLD_FULL):"; "$JDK_OLD/bin/java" -version 2>&1
} >"$OUT/env.txt"

wait_for_listening() { # until the log says LISTENING (max ~10 s)
  for _ in $(seq 1 50); do
    grep -q LISTENING "$1" 2>/dev/null && return 0
    sleep 0.2
  done
  return 1
}

# Prints "client shares|chosen group|HelloRetryRequest group" parsed from a client debug log.
parse_client_log() {
  awk '
    function value(line) { sub(/.*"(named|selected) group": */, "", line); gsub(/[[:space:],]+$/, "", line); return line }
    /"client_shares"/ && !cs_done { in_cs = 1; next }
    in_cs && (/^[[:space:]]*\]/ || /"server_share"/) { in_cs = 0; cs_done = 1 }
    in_cs && /"named group"/ { shares = shares (shares ? ", " : "") value($0) }
    /"server_share"/ && !chosen { want = 1; next }
    want && /"named group"/ { chosen = value($0); want = 0 }
    /"selected group"/ && !hrr { hrr = value($0) }
    END { print shares "|" chosen "|" hrr }
  ' "$1"
}

record_size() { # "<length> (<record type>)" from a proxy log line
  sed -n "s/^$1: first TLS record type=[0-9]* (\([a-z_]*\)) length=\([0-9]*\).*/\2 (\1)/p" "$2"
}

startup_error() { # root cause of a JVM that died before connecting
  grep -h -m1 '^Caused by' "$1" 2>/dev/null || grep -h -m1 -E 'Exception|Error' "$1" 2>/dev/null
}

fail_reason() { # the HANDSHAKE FAILED message from one side's log, or "–"
  local reason
  reason=$(grep -h -m1 '^HANDSHAKE FAILED' "$1" 2>/dev/null | sed 's/^HANDSHAKE FAILED: //')
  echo "${reason:-–}"
}

summarize() {
  local name=$1 cver=$2 sver=$3 setting=$4
  local clog="$OUT/$name-client.log" slog="$OUT/$name-server.log" plog="$OUT/$name-proxy.log"
  local result parsed shares rest chosen hrr ch sh
  if ! grep -q LISTENING "$slog"; then
    result="server didn't start: $(startup_error "$slog")"
  elif grep -q '^HANDSHAKE OK' "$clog" 2>/dev/null; then
    result=OK
  elif grep -q '^HANDSHAKE FAILED' "$clog" "$slog" 2>/dev/null; then
    # The client often sees only the alert; the server log usually says why it sent it.
    result="FAILED: client: $(fail_reason "$clog"); server: $(fail_reason "$slog")"
  else
    result="client didn't start: $(startup_error "$clog")"
  fi
  parsed=$( [ -f "$clog" ] && parse_client_log "$clog" )
  shares=${parsed%%|*}
  rest=${parsed#*|}
  chosen=${rest%%|*}
  hrr=${rest#*|}
  ch=$( [ -f "$plog" ] && record_size 'client->server' "$plog" )
  sh=$( [ -f "$plog" ] && record_size 'server->client' "$plog" )
  result=$(echo "$result" | tr '|' '/')
  echo "| $name | $cver | $sver | $setting | ${shares:-–} | ${chosen:-–}${hrr:+ (after HelloRetryRequest: $hrr)} | ${ch:-–} | ${sh:-–} | $result |" >>"$OUT/summary.md"
}

# run_case <name> <client JDK> <client -D option or ""> <server JDK> <server -D option or ""> <setting label>
run_case() {
  local name=$1 cjdk=$2 copt=$3 sjdk=$4 sopt=$5 setting=$6
  local clog="$OUT/$name-client.log" slog="$OUT/$name-server.log" plog="$OUT/$name-proxy.log"
  local spid ppid
  echo "== $name"
  # $sopt and $copt are deliberately unquoted: each is empty or a single -D option.
  "$sjdk/bin/java" $sopt -Djavax.net.debug=ssl:handshake "$HERE/Server.java" \
    "$SERVER_PORT" "$WORK/server.p12" "$PASS" >"$slog" 2>&1 &
  spid=$!
  if wait_for_listening "$slog"; then
    "$JDK_OLD/bin/java" "$HERE/Proxy.java" "$PROXY_PORT" 127.0.0.1 "$SERVER_PORT" >"$plog" 2>&1 &
    ppid=$!
    if wait_for_listening "$plog"; then
      "$cjdk/bin/java" $copt -Djavax.net.debug=ssl:handshake "$HERE/Client.java" \
        localhost "$PROXY_PORT" "$WORK/trust.p12" "$PASS" >"$clog" 2>&1
    fi
    # A client that died before connecting would leave the proxy waiting for its accept timeout.
    grep -q '^HANDSHAKE' "$clog" 2>/dev/null || kill "$ppid" 2>/dev/null
    wait "$ppid" 2>/dev/null
  fi
  kill "$spid" 2>/dev/null
  wait "$spid" 2>/dev/null
  summarize "$name" "$(full_version "$cjdk")" "$(full_version "$sjdk")" "$setting"
}

cat >"$OUT/summary.md" <<EOF
# PQ hybrid TLS handshake: JDK $NEW_FULL vs JDK $OLD_FULL

Generated by run-matrix.sh on $(date +%F). Machine and JDK builds: env.txt. Raw logs for each case sit next to this file.

- **client key shares offered**: key shares in the ClientHello (client debug log, "client_shares")
- **group the server chose**: "server_share" in the ServerHello, as seen by the client
- **first record bytes**: length of the first TLS record in each direction, from the byte-counting proxy, excluding the 5-byte record header. Client side = ClientHello; server side = ServerHello (or an alert if the handshake failed).

| case | client JDK | server JDK | named-groups setting | client key shares offered | group the server chose | client first record bytes | server first record bytes | result |
|---|---|---|---|---|---|---|---|---|
EOF

N=$NEW_LABEL
O=$OLD_LABEL
run_case "c$N-s$N-default"            "$JDK_NEW" ""                                       "$JDK_NEW" ""                                     "defaults"
run_case "c$N-s$N-client-x25519-only" "$JDK_NEW" "-Djdk.tls.namedGroups=x25519"           "$JDK_NEW" ""                                     "client: x25519 only"
run_case "c$O-s$N-default"            "$JDK_OLD" ""                                       "$JDK_NEW" ""                                     "defaults"
run_case "c$N-s$O-default"            "$JDK_NEW" ""                                       "$JDK_OLD" ""                                     "defaults"
run_case "c$O-s$N-server-hybrid-only" "$JDK_OLD" ""                                       "$JDK_NEW" "-Djdk.tls.namedGroups=X25519MLKEM768" "server: X25519MLKEM768 only"
run_case "c$N-s$N-client-p256-hybrid" "$JDK_NEW" "-Djdk.tls.namedGroups=SecP256r1MLKEM768" "$JDK_NEW" ""                                     "client: SecP256r1MLKEM768 only"

echo
cat "$OUT/summary.md"
echo
echo "Evidence written to: ${OUT#"$ROOT"/}"
