#!/bin/zsh
# End-to-end verification for fx: round-trip, resume, identity checks, edges.
#
#   scripts/test.sh              # release binary
#   FX_BIN=./target/debug/fx scripts/test.sh
#   scripts/test.sh 512          # size in MiB for the resume test (default 512)
set -uo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
FX="${FX_BIN:-$ROOT/target/release/fx}"
SIZE_MB=${1:-512}

if [ ! -x "$FX" ]; then
  echo "no binary at $FX — run: cargo build --release" >&2
  exit 1
fi

zmodload zsh/datetime 2>/dev/null || true
T=$(mktemp -d "${TMPDIR:-/tmp}/fxtest.XXXXXX")
# Overridden by the address-family tests; every other test pins loopback so it
# is deterministic and needs no network.
BIND=127.0.0.1:0
SEND_PID=""
cleanup() {
  [ -n "$SEND_PID" ] && kill "$SEND_PID" 2>/dev/null
  rm -rf "$T"
}
trap cleanup EXIT

mkdir -p "$T/src" "$T/dst"
FAILURES=0

pass() { echo "  PASS  $1"; }
fail() { echo "  FAIL  $1"; FAILURES=$((FAILURES + 1)); }

# Start a sender and leave its invite line in $INV (not echoed: this must not
# run in a subshell, or SEND_PID would be lost to the caller).
start_sender() {
  local src="$1"; shift
  "$FX" send "$src" --bind "$BIND" --no-stun "$@" > "$T/send.log" 2>&1 &
  SEND_PID=$!
  local i
  for i in $(seq 1 400); do
    grep -q 'fx recv' "$T/send.log" 2>/dev/null && break
    sleep 0.05
  done
  INV=$(grep -o 'fx recv [^ ]* --code [^ ]* --token [^ ]*' "$T/send.log" | head -1)
}

stop_sender() {
  [ -n "$SEND_PID" ] || return 0
  kill "$SEND_PID" 2>/dev/null
  wait "$SEND_PID" 2>/dev/null
  SEND_PID=""
}

parse_invite() { # $1 = invite line
  ADDR=$(echo "$1" | awk '{print $3}')
  CODE=$(echo "$1" | sed -E 's/.*--code ([^ ]*).*/\1/')
  TOKEN=$(echo "$1" | sed -E 's/.*--token ([^ ]*).*/\1/')
}

echo "### round trip"
head -c 67108864 /dev/urandom > "$T/src/blob.bin"
SRC=$(shasum -a 256 "$T/src/blob.bin" | cut -d' ' -f1)
start_sender "$T/src/blob.bin"
if [ -z "$INV" ]; then
  fail "sender produced no invite"; cat "$T/send.log"
else
  parse_invite "$INV"
  RC=0
  "$FX" recv "$ADDR" --code "$CODE" --token "$TOKEN" --out "$T/dst" > "$T/recv.log" 2>&1 || RC=$?
  stop_sender
  DST=$(shasum -a 256 "$T/dst/blob.bin" 2>/dev/null | cut -d' ' -f1)
  if [ "$RC" -eq 0 ] && [ "$SRC" = "$DST" ]; then
    pass "64 MiB transferred, checksums match"
  else
    fail "round trip (rc=$RC)"; cat "$T/recv.log"
  fi
fi

echo "### resume after interruption"
head -c $((SIZE_MB * 1024 * 1024)) /dev/urandom > "$T/src/big.bin"
SRC=$(shasum -a 256 "$T/src/big.bin" | cut -d' ' -f1)
rm -rf "$T/dst"; mkdir -p "$T/dst"

start_sender "$T/src/big.bin"
parse_invite "$INV"
"$FX" recv "$ADDR" --code "$CODE" --token "$TOKEN" --out "$T/dst" > "$T/recv1.log" 2>&1 &
RECV_PID=$!
PART="$T/dst/.big.bin.fxpart"
TOTAL_BYTES=$(stat -f%z "$T/src/big.bin")
# Interrupt once a meaningful amount is on disk but the file is not finished,
# rather than after a fixed delay that a fast transfer could beat.
TARGET=$(( TOTAL_BYTES / 4 ))
[ "$TARGET" -lt 1 ] && TARGET=1
WRITTEN=0
for i in $(seq 1 600); do
  WRITTEN=$(( $(stat -f%b "$PART" 2>/dev/null || echo 0) * 512 ))
  [ "$WRITTEN" -ge "$TARGET" ] && break
  sleep 0.05
done
kill -9 "$RECV_PID" 2>/dev/null
wait "$RECV_PID" 2>/dev/null
stop_sender

# set_len makes the partial file logically full-size, so count written blocks.
if [ -f "$PART" ] && [ "$WRITTEN" -gt 0 ] && [ "$WRITTEN" -lt "$TOTAL_BYTES" ]; then
  pass "interrupted at $WRITTEN of $TOTAL_BYTES bytes actually written"
else
  fail "interruption did not leave a usable partial (wrote $WRITTEN of $TOTAL_BYTES)"
fi

start_sender "$T/src/big.bin"
parse_invite "$INV"
RC=0
"$FX" recv "$ADDR" --code "$CODE" --token "$TOKEN" --out "$T/dst" > "$T/recv2.log" 2>&1 || RC=$?
stop_sender
MISSING=$(grep -o 'transferring big.bin: [0-9][0-9]* of' "$T/recv2.log" | grep -o '[0-9][0-9]*' | head -1)
CHUNKS=$(grep -o 'of [0-9][0-9]* chunks' "$T/recv2.log" | grep -o '[0-9][0-9]*' | head -1)
DST=$(shasum -a 256 "$T/dst/big.bin" 2>/dev/null | cut -d' ' -f1)
if [ "$RC" -ne 0 ]; then
  fail "resume run exited $RC"; cat "$T/recv2.log"
elif [ -z "$MISSING" ] || [ "$MISSING" -ge "${CHUNKS:-0}" ]; then
  fail "resume re-sent everything (${MISSING:-?} of ${CHUNKS:-?})"
elif [ "$SRC" != "$DST" ]; then
  fail "resumed file does not match source"
else
  pass "resume fetched only $MISSING of $CHUNKS chunks, checksum matches"
fi

echo "### identity checks"
head -c 8388608 /dev/urandom > "$T/src/sec.bin"

start_sender "$T/src/sec.bin"
parse_invite "$INV"
RC=0
"$FX" recv "$ADDR" --code 0000-0000-0000-0000 --token "$TOKEN" --out "$T/dst2" > "$T/badcode.log" 2>&1 || RC=$?
stop_sender
if [ "$RC" -ne 0 ] && grep -q 'verify code mismatch' "$T/badcode.log" && [ ! -f "$T/dst2/sec.bin" ]; then
  pass "wrong verify code aborted before any data was written"
else
  fail "wrong verify code was not rejected cleanly"; cat "$T/badcode.log"
fi

start_sender "$T/src/sec.bin"
parse_invite "$INV"
RC=0
"$FX" recv "$ADDR" --code "$CODE" --token deadbeef --out "$T/dst3" > "$T/badtoken.log" 2>&1 || RC=$?
for i in $(seq 1 50); do grep -q 'token mismatch' "$T/send.log" 2>/dev/null && break; sleep 0.1; done
SENDSAW=$(grep -c 'token mismatch' "$T/send.log" 2>/dev/null || echo 0)
stop_sender
if [ "$RC" -ne 0 ] && [ "$SENDSAW" -gt 0 ]; then
  pass "wrong token rejected by the sender"
else
  fail "wrong token was not rejected (rc=$RC, sender saw it: $SENDSAW)"
fi

echo "### edge cases"
roundtrip_edge() {
  local name="$1"; shift
  local -a sargs=("$@")
  local src="$T/src/$name"
  local src_hash dst_hash
  src_hash=$(shasum -a 256 "$src" | cut -d' ' -f1)

  rm -rf "$T/dst"; mkdir -p "$T/dst"
  start_sender "$src" ${sargs[@]+"${sargs[@]}"}
  if [ -z "$INV" ]; then fail "$name: no invite"; cat "$T/send.log"; return; fi
  parse_invite "$INV"

  # --streams applies to both ends; --chunk is a sender-side knob.
  local -a rx=()
  local j
  for (( j = 1; j <= ${#sargs}; j++ )); do
    if [[ "${sargs[j]}" == "--streams" ]]; then rx+=(--streams "${sargs[j+1]}"); fi
  done

  local rc=0
  "$FX" recv "$ADDR" --code "$CODE" --token "$TOKEN" --out "$T/dst" ${rx[@]+"${rx[@]}"} > "$T/recv.log" 2>&1 || rc=$?
  stop_sender

  dst_hash=$(shasum -a 256 "$T/dst/$name" 2>/dev/null | cut -d' ' -f1)
  if [ "$rc" -eq 0 ] && [ "$src_hash" = "$dst_hash" ]; then
    pass "$name ($(stat -f%z "$src") B) ${sargs[*]:-defaults}"
  else
    fail "$name (rc=$rc)"; cat "$T/recv.log"
  fi
}

: > "$T/src/empty.bin"
printf 'x' > "$T/src/one.bin"
printf 'hello, world' > "$T/src/hello world.txt"
head -c 100000 /dev/urandom > "$T/src/small.bin"
printf 'héllo wörld — 日本語' > "$T/src/ünïcødé.txt"
head -c 300 /dev/urandom > "$T/src/odd.bin"
head -c 5000000 /dev/urandom > "$T/src/chunky.bin"

roundtrip_edge "empty.bin"
roundtrip_edge "one.bin"
roundtrip_edge "hello world.txt"
roundtrip_edge "ünïcødé.txt"
roundtrip_edge "odd.bin"     --chunk 7 --streams 4
roundtrip_edge "small.bin"   --chunk 1024 --streams 1
roundtrip_edge "chunky.bin"  --chunk 65536 --streams 16

echo "### address families and candidate racing"
# IPv6 end to end: bind an explicit v6 address and transfer over it.
HAS_V6=0
if ifconfig lo0 2>/dev/null | grep -q 'inet6 ::1'; then
  HAS_V6=1
elif ip -6 addr show lo0 2>/dev/null | grep -q '::1'; then
  HAS_V6=1
fi
if [ "$HAS_V6" -eq 1 ]; then
  BIND='[::1]:0'
  roundtrip_edge "small.bin"
  if [ -n "$INV" ] && [[ "$ADDR" == \[* ]]; then
    pass "IPv6 round trip over $ADDR"
  else
    fail "IPv6 round trip (invite was: ${INV:-none})"
  fi
  BIND=127.0.0.1:0
else
  echo "  SKIP  IPv6 round trip (this host has no loopback v6)"
fi

# The sender may print several addresses; the receiver races them and keeps
# whichever answers. Dead candidates must cost nothing but a failed attempt.
head -c 8388608 /dev/urandom > "$T/src/race.bin"
RACE_SRC=$(shasum -a 256 "$T/src/race.bin" | cut -d' ' -f1)
rm -rf "$T/dst"; mkdir -p "$T/dst"
start_sender "$T/src/race.bin"
if [ -z "$INV" ]; then
  fail "racing: no invite"; cat "$T/send.log"
else
  parse_invite "$INV"
  DEAD1=203.0.113.1:9
  DEAD2=192.0.2.55:12345
  RC=0
  RACE_START=$(date +%s)
  "$FX" recv "$DEAD1,$DEAD2,$ADDR" --code "$CODE" --token "$TOKEN" --out "$T/dst" --timeout 10 > "$T/recv.log" 2>&1 || RC=$?
  RACE_END=$(date +%s)
  stop_sender
  RACE_DST=$(shasum -a 256 "$T/dst/race.bin" 2>/dev/null | cut -d' ' -f1)
  RACE_VIA=$(grep -o 'connected to .*' "$T/recv.log" | head -1)
  if [ "$RC" -eq 0 ] && [ "$RACE_SRC" = "$RACE_DST" ]; then
    pass "2 dead candidates ignored, ${RACE_VIA:-?}, took $((RACE_END - RACE_START))s"
  else
    fail "racing (rc=$RC)"; cat "$T/recv.log"; cat "$T/send.log"
  fi
fi

echo
if [ "$FAILURES" -eq 0 ]; then
  echo "ALL PASS"
else
  echo "$FAILURES FAILURE(S)"
  exit 1
fi
