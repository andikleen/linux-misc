#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# run_decode.sh - ptwrite decoder selftests.
# Exercises the decoder CLI and PT/perf integration.
set -u
DIR=$(dirname "$(readlink -f "$0")")
SRC=${1:-"$DIR/manual_ptw.c"}
DEC=${2:-}
if [ -z "$DEC" ]; then
	for candidate in \
		"$DIR/uprobe-ptwrite-decode.py" \
		"$DIR/../../../../tools/perf/scripts/python/uprobe-ptwrite-decode.py" \
		"/usr/lib/linux-tools/$(uname -r)/scripts/python/uprobe-ptwrite-decode.py" \
		"/usr/share/linux-tools/scripts/python/uprobe-ptwrite-decode.py"; do
		if [ -f "$candidate" ]; then
			DEC=$candidate
			break
		fi
	done
fi
TR=/sys/kernel/tracing
EV="$TR/uprobe_events"
TMP=$(mktemp -d "${TMPDIR:-/tmp}/uprobe-ptwrite.XXXXXX") || {
	echo "1..0 # SKIP unable to create temporary directory"
	exit 0
}
BIN="$TMP/manual_ptw"
fails=0

t() { # t <num> <ok|not> <msg>
	if [ "$2" = ok ]; then echo "ok $1 - $3"
	else echo "not ok $1 - $3"; fails=$((fails + 1)); fi
}

cleanup() {
	{ echo 0 > "$TR/events/uprobes/e/enable"; } 2>/dev/null
	{ echo "-:e" > "$EV"; } 2>/dev/null
	{ echo "-:classic" > "$EV"; } 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

if [ ! -e /sys/devices/intel_pt/format/ptw ]; then
	echo "1..0 # SKIP PTWRITE unavailable"
	exit 0
fi

if [ "$(id -u)" != 0 ] || [ ! -f "$SRC" ] || [ ! -f "$DEC" ] ||
	! command -v perf >/dev/null 2>&1 ||
	! command -v gcc >/dev/null 2>&1 ||
	! command -v python3 >/dev/null 2>&1 ||
	! command -v objdump >/dev/null 2>&1 ||
	! command -v readelf >/dev/null 2>&1; then
	echo "1..0 # SKIP missing root, input, or required tool"
	exit 0
fi

if ! gcc -O2 -no-pie -o "$BIN" "$SRC" 2>/dev/null; then
	echo "1..0 # SKIP test program build failed"
	exit 0
fi

TV=$(objdump -t "$BIN" 2>/dev/null |
	awk '$NF=="target_site" {print $1;exit}')
LV=$(readelf -l "$BIN" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $3; exit}}' | sed 's/^0x//')
LO=$(readelf -l "$BIN" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $2; exit}}' | sed 's/^0x//')
OFF=$((0x$TV - 0x$LV + 0x$LO))
echo "1..6"

# 1: malformed options and changing header nargs must fail cleanly
cli_ok=1
python3 "$DEC" --words --event-id >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || cli_ok=0
python3 "$DEC" --words --types >/dev/null 2>&1
rc=$?
[ "$rc" -eq 2 ] || cli_ok=0
if [ "$cli_ok" -eq 1 ]; then
	t 1 ok "decoder option validation"
else
	t 1 not "decoder option validation"
fi

# 2: manual ptwrites only (no probe): every payload must print as a
# manual ptwrite line, and no false records may appear
perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o "$TMP/m.data" \
	"$BIN" >/dev/null 2>&1
out=$(perf script --itrace=qwe -s "$DEC" -i "$TMP/m.data" 2>/dev/null)
manual=$(printf '%s' "$out" | grep -c "manual ptwrite:")
recs=$(printf '%s' "$out" | grep -c "^record ")
if [ "$manual" -ge 100 ] && [ "$recs" -eq 0 ]; then
	t 2 ok "manual ptwrites detected ($manual payloads, 0 records)"
else
	t 2 not "manual ptwrites: $manual manual, $recs records"
fi

# 3: probe + manual payloads in one stream
if ! echo "ptw:e $BIN:$OFF %di %si" > "$EV" 2>/dev/null ||
   ! echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
	t 3 not "probe create/enable failed (setup)"
else
	perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o "$TMP/x.data" \
		"$BIN" >/dev/null 2>&1
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	out=$(perf script --itrace=qwe -s "$DEC" -i "$TMP/x.data" 2>/dev/null)
	recs=$(printf '%s' "$out" | grep -c "^record ")
	manual=$(printf '%s' "$out" | grep -c "manual ptwrite:")
	if [ "$recs" -eq 100 ] && [ "$manual" -ge 100 ]; then
		t 3 ok "probe records + manual payloads mixed ($recs records, $manual manual)"
	else
		t 3 not "mixed stream: $recs records, $manual manual"
	fi
	echo "-:e" > "$EV" 2>/dev/null
fi

# 4: branches: with 'b' in --itrace the decoder prints the decoded
# branch stream interleaved with the records
if ! echo "ptw:e $BIN:$OFF %di %si" > "$EV" 2>/dev/null ||
   ! echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
	t 4 not "probe create/enable failed (setup)"
else
	perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o "$TMP/b.data" \
		"$BIN" >/dev/null 2>&1
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	out=$(perf script --itrace=qweb -s "$DEC" -i "$TMP/b.data" 2>/dev/null)
	br=$(printf '%s' "$out" | grep -c "^branch:")
	recs=$(printf '%s' "$out" | grep -c "^record ")
	if [ "$br" -ge 100 ] && [ "$recs" -ge 100 ]; then
		t 4 ok "branches + records interleaved ($br branches, $recs records)"
	else
		t 4 not "branch stream: $br branches, $recs records"
	fi
	echo "-:e" > "$EV" 2>/dev/null
fi

# 5: other event classes
if ! echo "ptw:e $BIN:$OFF %di %si" > "$EV" 2>/dev/null ||
   ! echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null ||
   ! echo "p:classic $BIN:$((OFF+5)) %di %si" >> "$EV" 2>/dev/null; then
	t 5 not "mixed-class probe create failed (setup)"
else
	perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -e uprobes:classic \
		-e sched:sched_process_exec -o "$TMP/c.data" "$BIN" >/dev/null 2>&1
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	out=$(perf script --itrace=qwe -s "$DEC" -i "$TMP/c.data" 2>/dev/null)
	recs=$(printf '%s' "$out" | grep -c "^record ")
	manual=$(printf '%s' "$out" | grep -c "manual ptwrite:")
	cl=$(printf '%s' "$out" | grep -c "^event:.*uprobes:classic")
	tp=$(printf '%s' "$out" | grep -c "^event:.*sched:sched_process_exec")
	if [ "$recs" -ge 100 ] && [ "$manual" -ge 100 ] && \
	   [ "$cl" -ge 100 ] && [ "$tp" -ge 1 ]; then
		t 5 ok "classic uprobe + tracepoint interleaved \
($recs recs, $manual manual, $cl classic, $tp exec)"
	else
		t 5 not "mixed classes: $recs recs, $manual manual, $cl classic, $tp exec"
	fi
	echo "-:e" > "$EV" 2>/dev/null
	echo "-:classic" > "$EV" 2>/dev/null
fi

# 6: --no-branches suppresses the branch stream
if ! echo "ptw:e $BIN:$OFF %di %si" > "$EV" 2>/dev/null ||
   ! echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
	t 6 not "probe create/enable failed (setup)"
else
	perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o "$TMP/n.data" \
		"$BIN" >/dev/null 2>&1
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	out=$(perf script --itrace=qweb -s "$DEC" -i "$TMP/n.data" \
		-- --no-branches 2>/dev/null)
	br=$(printf '%s' "$out" | grep -c "^branch:")
	recs=$(printf '%s' "$out" | grep -c "^record ")
	if [ "$br" -eq 0 ] && [ "$recs" -ge 100 ]; then
		t 6 ok "--no-branches suppresses branches ($br branches, $recs records)"
	else
		t 6 not "--no-branches: $br branches, $recs records"
	fi
	echo "-:e" > "$EV" 2>/dev/null
fi

[ $fails -eq 0 ] || exit 1
