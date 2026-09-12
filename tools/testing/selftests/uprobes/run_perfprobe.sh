#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# run_perfprobe.sh - uprobes ptwrite selftest.
set -u
DIR=$(dirname "$(readlink -f "$0")")
SAMPLES="$DIR/../../../../samples/uprobe-ptwrite"
SRC=${1:-"$DIR/test_prog.c"}
if [ "$#" -lt 1 ] && [ ! -f "$SRC" ]; then
	SRC="$SAMPLES/test_prog.c"
fi
TMP=$(mktemp -d "${TMPDIR:-/tmp}/uprobe-ptwrite.XXXXXX") || {
	echo "1..0 # SKIP unable to create temporary directory"
	exit 0
}
OWNED_PROBES="$TMP/owned-probes"
OWNED_EVENTS="$TMP/owned-events"
PROG="$TMP/tp"
TR=/sys/kernel/tracing
EV="$TR/uprobe_events"
fails=0

t() { # t <num> <ok|not> <msg>
	if [ "$2" = ok ]; then echo "ok $1 - $3"
	else echo "not ok $1 - $3"; fails=$((fails + 1)); fi
}

# split a "group:event" name into the tracefs group dir + event dir
grp() { echo "${1%%:*}"; }
evn() { echo "${1#*:}"; }

# set a tracefs event's enable file (returns the write's status)
ev_set() { # <event> <0|1>
	local enable="$TR/events/$(grp "$1")/$(evn "$1")/enable"

	[ -e "$enable" ] || return 1
	echo "$2" > "$enable" 2>/dev/null
}

# add a perf probe on the given symbol of $PROG. It echoes the tracefs
# event name ("group:event"), or nothing if the add failed
perf_add() { # <symbol>
	if ! perf probe -x "$PROG" --add "$1" >/dev/null 2>&1; then
		return 1
	fi
	local event

	event=$(perf probe -l 2>/dev/null | awk -v s="$1" '$0 ~ s {print $1; exit}')
	if [ -z "$event" ]; then
		# Do not leave an auto-named probe behind if listing failed.
		perf probe -d "$1" >/dev/null 2>&1 || true
		return 1
	fi
	printf '%s\n' "$event" >> "$OWNED_PROBES"
	printf '%s\n' "$event"
}

# disable the perf probe's tracefs event and remove the probe
perf_del() { # <event>
	[ -n "$1" ] || return
	ev_set "$1" 0
	perf probe -d "$1" >/dev/null 2>&1
}

ptw_event_add() { # <command>
	if ! { echo "$1" >> "$EV"; } 2>/dev/null; then
		return 1
	fi
	printf '%s\n' uprobes:e >> "$OWNED_EVENTS"
}

cleanup() {
	if [ -f "$OWNED_EVENTS" ]; then
		while IFS= read -r event; do
			[ -n "$event" ] || continue
			ev_set "$event" 0
			if [ "$event" = uprobes:e ]; then
				echo "-:e" >> "$EV" 2>/dev/null
			fi
		done < "$OWNED_EVENTS"
	fi
	if [ -f "$OWNED_PROBES" ]; then
		while IFS= read -r probe; do
			[ -n "$probe" ] || continue
			perf probe -d "$probe" >/dev/null 2>&1
		done < "$OWNED_PROBES"
	fi
	rm -rf "$TMP"
}
trap cleanup EXIT

if [ ! -e /sys/devices/intel_pt/format/ptw ]; then
	echo "1..0 # SKIP PTWRITE unavailable"
	exit 0
fi

# prerequisites
if [ "$(id -u)" != 0 ] || [ ! -f "$SRC" ] ||
	! command -v perf >/dev/null || ! command -v gcc >/dev/null ||
	! command -v objdump >/dev/null || ! command -v readelf >/dev/null; then
	echo "1..0 # SKIP missing root, source, or required tool"
	exit 0
fi

if ! gcc -O2 -no-pie -o "$PROG" "$SRC" 2>/dev/null; then
	echo "1..0 # SKIP test program build failed"
	exit 0
fi

TV=$(objdump -d "$PROG" 2>/dev/null |
	awk '/^[0-9a-f]+ <target>:/{print $1;exit}' | tr -d ':')
LV=$(readelf -l "$PROG" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $3; exit}}' | sed 's/^0x//')
LO=$(readelf -l "$PROG" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $2; exit}}' | sed 's/^0x//')
OFF=$((0x$TV - 0x$LV + 0x$LO))
echo "1..4"

# 1: a classic perf uprobe fires on the test binary
if ! EVT=$(perf_add target); then
	t 1 not "perf probe add failed"
else
	perf record -e "$EVT" -o "$TMP/ev.data" "$PROG" >/dev/null 2>&1
	rc=$?
	n=$(perf script -i "$TMP/ev.data" 2>/dev/null | wc -l)
	perf_del "$EVT"
	if [ $rc -eq 0 ] && [ "$n" -gt 0 ]; then
		t 1 ok "classic perf uprobe fires ($n samples via $EVT)"
	else
		t 1 not "perf record rc=$rc samples=$n"
	fi
fi

# 2: a ptwrite probe cannot become live at the perf-occupied site
if ! EVT=$(perf_add target); then
	t 2 not "perf probe add failed (setup)"
else
	ev_set "$EVT" 1				# hold the uprobe live
	rejected=1
	if ( ptw_event_add "ptw:e $PROG:$OFF %di" ); then
		# the create succeeded. The enable must fail (-EBUSY)
		if echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
			rejected=0
			echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
		fi
		echo "-:e" >> "$EV" 2>/dev/null
	fi
	perf_del "$EVT"
	if [ $rejected -eq 1 ]; then
		t 2 ok "ptwrite probe rejected at the perf-occupied site (-EBUSY)"
	else
		t 2 not "ptwrite probe became live at the perf-occupied site"
	fi
fi

# 3: a perf probe cannot enable at the ptwrite-occupied site
if ptw_event_add "ptw:e $PROG:$OFF %di" &&
   echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
	if ! EVT=$(perf_add target); then
		t 3 not "perf probe add failed (setup)"
	else
		if ev_set "$EVT" 1; then
			ev_set "$EVT" 0
			t 3 not "perf probe enabled at the ptwrite-occupied site"
		else
			t 3 ok "perf probe rejected at the ptwrite-occupied site (-EBUSY)"
		fi
		perf_del "$EVT"
	fi
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	echo "-:e" >> "$EV" 2>/dev/null
else
	t 3 not "ptwrite enable failed (setup)"
	echo "-:e" >> "$EV" 2>/dev/null
fi

# 4: coexistence -- a classic perf probe at main + the ptwrite probe at
# target's entry both live and firing
if ptw_event_add "ptw:e $PROG:$OFF %di" &&
   echo 1 > "$TR/events/uprobes/e/enable" 2>/dev/null; then
	if ! EVT=$(perf_add main); then
		t 4 not "perf probe add main failed"
	else
		perf record -e "$EVT" -o "$TMP/co.data" "$PROG" >/dev/null 2>&1
		rc=$?
		n=$(perf script -i "$TMP/co.data" 2>/dev/null | wc -l)
		perf_del "$EVT"
		if [ $rc -eq 0 ] && [ "$n" -gt 0 ]; then
			t 4 ok "classic perf probe at main + ptwrite at target coexist ($n samples)"
		else
			t 4 not "coexistence run rc=$rc samples=$n"
		fi
	fi
	echo 0 > "$TR/events/uprobes/e/enable" 2>/dev/null
	echo "-:e" >> "$EV" 2>/dev/null
else
	t 4 not "ptwrite enable failed (setup)"
	echo "-:e" >> "$EV" 2>/dev/null
fi

[ $fails -eq 0 ] || exit 1
