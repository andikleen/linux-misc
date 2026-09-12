#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# run_ptw.sh - ptwrite uprobes selftests.
# Root + tracefs + an x86-64 CPU with PTWRITE required
DIR=$(dirname "$(readlink -f "$0")")
BIN="$DIR/ptw_probe"
TR=/sys/kernel/tracing
EV="$TR/uprobe_events"
PTW=/sys/devices/intel_pt/format/ptw

cleanup() {
	if [ -e "$TR/events/uprobes/pw/enable" ]; then
		echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null
	fi
	echo "-:pw" >> "$EV" 2>/dev/null
	echo "-:bad" >> "$EV" 2>/dev/null
}

if [ ! -e "$PTW" ]; then
	echo "1..0 # SKIP PTWRITE unavailable"
	exit 0
fi
if [ ! -e "$EV" ] || [ "$(id -u)" != 0 ] || [ ! -x "$BIN" ] ||
	! command -v objdump >/dev/null 2>&1 ||
	! command -v readelf >/dev/null 2>&1; then
	echo "1..0 # SKIP missing tracefs, root, ptw_probe, objdump, or readelf"
	exit 0
fi
trap cleanup EXIT

# the probe sites: the entry instructions
elf_off() {
	local v=$1
	local base=$(readelf -l "$BIN" 2>/dev/null |
		awk '/LOAD/{if ($1=="LOAD") {print $3; exit}}')
	[ -n "$base" ] && printf "0x%x" $((v - base))
}

PUN_V=$(objdump -d "$BIN" | awk '/^[0-9a-f]+ <punfn>:/{print $1;exit}' | tr -d ':')
JCC_V=$(objdump -d "$BIN" |
	awk '/^[0-9a-f]+ <jcc8>:/ {f=1; next} f&&/jne/{print $1; exit}' |
	tr -d ':')
NOP_V=$(objdump -d "$BIN" | awk '/^[0-9a-f]+ <nopfn_site>:/{print $1;exit}' | tr -d ':')
NOP5_V=$(objdump -d "$BIN" | awk '/^[0-9a-f]+ <nop5>:/{print $1;exit}' | tr -d ':')
UNOP_V=$(objdump -d "$BIN" |
	awk '/^[0-9a-f]+ <nopfn_unaligned_site>:/{print $1;exit}' | tr -d ':')
RZ_V=$(objdump -d "$BIN" | awk '/^[0-9a-f]+ <rz_probe_site>:/{print $1;exit}' | tr -d ':')
if [ -z "$PUN_V" ] || [ -z "$JCC_V" ] || [ -z "$FLT_V" ] ||
   [ -z "$NOP_V" ] || [ -z "$NOP5_V" ] || [ -z "$UNOP_V" ] ||
   [ -z "$RZ_V" ]; then
	echo "1..0 # SKIP unable to resolve ptw_probe symbols"
	exit 0
fi
PUN_OFF=$(elf_off 0x$PUN_V)
JCC_OFF=$(elf_off 0x$JCC_V)
NOP_OFF=$(elf_off 0x$NOP_V)
NOP5_OFF=$(elf_off 0x$NOP5_V)
UNOP_OFF=$(elf_off 0x$UNOP_V)
RZ_OFF=$(elf_off 0x$RZ_V)

echo "1..10"
failures=0

# baseline (unprobed)
base_out=$("$BIN"); base_rc=$?
base=$(printf '%s' "$base_out" | sed -n 's/.*acc=\([0-9a-f]*\).*/\1/p')
base_sites=$(printf '%s' "$base_out" | grep '^SITE ')
[ -z "$base" ] && base=0

# run one probed invocation: $run_rc = exit code, $probe = the acc
run_one() {
	out=$("$BIN")
	run_rc=$?
	probe=$(printf '%s' "$out" | sed -n 's/.*acc=\([0-9a-f]*\).*/\1/p')
}

# the site bytes of a fresh invocation must equal the baseline
sites_match() {
	[ "$(printf '%s' "$base_sites")" = \
	  "$("$BIN" | grep '^SITE ')" ]
}

# emit the TAP line and count failures (tap <num> <ok|not|skip> <desc>)
tap() {
	if [ "$2" = ok ]; then
		echo "ok $1 - $3"
	elif [ "$2" = skip ]; then
		echo "ok $1 - $3 # SKIP"
	else
		echo "not ok $1 - $3"
		failures=$((failures + 1))
	fi
}

# Install a probe at the site, run the probed binary once, and check the
# run against the baseline (acc, exit, restored site bytes). A
# create/enable failure is fatal.
# Usage: probe_run <num> <offset> <args> <desc>
probe_run() {
	local num=$1 off=$2 args=$3 desc=$4

	if ! echo "ptw:pw $BIN:$off $args" >> "$EV" 2>/dev/null; then
		tap "$num" not "$desc (probe create failed)"
		exit 1
	fi
	if ! echo 1 > "$TR/events/uprobes/pw/enable" 2>/dev/null; then
		tap "$num" not "$desc (probe enable failed)"
		exit 1
	fi
	run_one
	echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null
	echo "-:pw" >> "$EV" 2>/dev/null
	if [ "$probe" = "$base" ] && [ "$run_rc" -eq 0 ] && sites_match; then
		tap "$num" ok "$desc"
	else
		tap "$num" not "$desc (base $base probed $probe rc $run_rc)"
	fi
}

# 1: pun out-of-line execution preserves the site instruction's effect
probe_run 1 $PUN_OFF "%di %si" \
	"pun out-of-line execution preserves the instruction effect"

# 2: a relative branch site must be refused at enable
if ! echo "ptw:pw $BIN:$JCC_OFF %di %si" >> "$EV" 2>/dev/null; then
	tap 2 ok "rel8 jcc site rejected at create"
else
	if echo 1 > "$TR/events/uprobes/pw/enable" 2>/dev/null; then
		echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null
		tap 2 not "rel8 jcc site enabled (expected rejection)"
	else
		tap 2 ok "rel8 jcc site rejected (no re-encode)"
	fi
	echo "-:pw" >> "$EV" 2>/dev/null
fi


# 3: mini-stress (50 fork/execs survive)
if ! echo "ptw:pw $BIN:$PUN_OFF %di %si" >> "$EV" 2>/dev/null ||
   ! echo 1 > "$TR/events/uprobes/pw/enable" 2>/dev/null; then
	tap 3 not "churn mini-stress setup failed"
else
	fails=0
	for i in $(seq 1 50); do
		"$BIN" >/dev/null 2>&1 || fails=$((fails + 1))
	done
	echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null
	if [ "$fails" -eq 0 ] && sites_match; then
		tap 3 ok "churn mini-stress (50 execs, 0 failures)"
	else
		tap 3 not "churn mini-stress ($fails/50 failed)"
	fi
fi
echo "-:pw" >> "$EV" 2>/dev/null

# 4: an aligned 5x1-byte NOP run takes the atomic patch path
probe_run 4 "${NOP_OFF}%multinop" "%di %si" \
	"aligned NOP-composition install (probe fires, target valid, site restored)"

# 5: the single 5-byte NOP keeps the classic 3-phase poke
probe_run 5 $NOP5_OFF "%di %si" \
	"single 5-byte-NOP 3-phase install (probe fires, target valid, site restored)"

# 6: enable/disable flip loop (50 re-installs stay correct)
if ! echo "ptw:pw $BIN:$NOP5_OFF %di %si" >> "$EV" 2>/dev/null ||
   [ ! -e "$TR/events/uprobes/pw/enable" ]; then
	tap 6 not "flip loop setup failed"
else
	fails=0
	for i in $(seq 1 50); do
		echo 1 > "$TR/events/uprobes/pw/enable" 2>/dev/null ||
			fails=$((fails + 1))
		"$BIN" >/dev/null 2>&1 || fails=$((fails + 1))
		echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null ||
			fails=$((fails + 1))
	done
	if [ "$fails" -eq 0 ] && sites_match; then
		tap 6 ok "enable/disable flip loop (50 flips, 0 failures, site restored)"
	else
		tap 6 not "flip loop ($fails failures)"
	fi
fi
echo "-:pw" >> "$EV" 2>/dev/null

# 7: a 4-arg paced probe at a site with a stack-local sentinel
probe_run 7 $RZ_OFF "%di %si %dx %r8" \
	"4-arg paced probe"

# 8: %nopace attached to the offset remains accepted
probe_run 8 "${PUN_OFF}%nopace" "%di %si" \
	"%nopace offset suffix is accepted"

# 9: %nopace as a separate option remains accepted
probe_run 9 "$PUN_OFF" "%nopace %di %si" \
	"%nopace separate option is accepted"

# 10: unknown ptwrite options must be rejected by tracefs
if echo "ptw:bad $BIN:${PUN_OFF}%unknown %di %si" >> "$EV" 2>/dev/null; then
	echo "-:bad" >> "$EV" 2>/dev/null
	tap 10 not "unknown ptwrite option accepted"
else
	tap 10 ok "unknown ptwrite option rejected"
fi

# 11: an unaligned 5x1-byte NOP run cannot use the atomic patch path
if ! echo "ptw:pw $BIN:${UNOP_OFF}%multinop %di %si" >> "$EV" 2>/dev/null; then
	tap 11 ok "unaligned NOP-composition site rejected at create"
else
	if echo 1 > "$TR/events/uprobes/pw/enable" 2>/dev/null; then
		echo 0 > "$TR/events/uprobes/pw/enable" 2>/dev/null
		tap 11 not "unaligned NOP-composition site enabled"
	else
		tap 11 ok "unaligned NOP-composition site rejected at enable"
	fi
	echo "-:pw" >> "$EV" 2>/dev/null
fi

# the kselftest runner uses only the exit code
[ "$failures" -eq 0 ] || exit 1
