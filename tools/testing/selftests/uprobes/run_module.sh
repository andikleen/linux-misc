#!/bin/bash
# SPDX-License-Identifier: GPL-2.0
# run_module.sh - uprobes ptwrite sample-module selftest.
# Loads samples/uprobe-ptwrite/uprobe_ptwrite_test.ko
set -u
DIR=$(dirname "$(readlink -f "$0")")
SAMPLES="$DIR/../../../../samples/uprobe-ptwrite"
KO=${1:-"$DIR/uprobe_ptwrite_test.ko"}
SRC=${2:-"$DIR/test_prog.c"}
DEC=${3:-"$DIR/uprobe-ptwrite-decode.py"}
if [ "$#" -lt 1 ] && [ ! -f "$KO" ]; then
	KO="$SAMPLES/uprobe_ptwrite_test.ko"
fi
if [ "$#" -lt 2 ] && [ ! -f "$SRC" ]; then
	SRC="$SAMPLES/test_prog.c"
fi
if [ "$#" -lt 3 ] && [ ! -f "$DEC" ]; then
	DEC="$DIR/../../../../tools/perf/scripts/python/uprobe-ptwrite-decode.py"
fi
TMP=$(mktemp -d "${TMPDIR:-/tmp}/uprobe-ptwrite.XXXXXX") || {
	echo "1..0 # SKIP unable to create temporary directory"
	exit 0
}
PROG="$TMP/test_prog"
MOD=uprobe_ptwrite_test
fails=0

t() { # t <num> <ok|not|skip> <msg>
	if [ "$2" = ok ]; then
		echo "ok $1 - $3"
	elif [ "$2" = skip ]; then
		echo "ok $1 - $3 # SKIP"
	else
		echo "not ok $1 - $3"
		fails=$((fails + 1))
	fi
}

# Load the module against the probed program with the given args
# 0 = the probed run survived, 1 = the run failed, 2 = the module did not load.
mod_run() { # <args>
	if ! insmod "$KO" path="$PROG" offset=$OFF args="$1" \
	     event_id=0x1234 2>/dev/null; then
		return 2
	fi
	"$PROG" >/dev/null 2>&1
	local rc=$?
	rmmod $MOD 2>/dev/null
	return $rc
}

cleanup() {
	rmmod $MOD 2>/dev/null
	rm -rf "$TMP"
}
trap cleanup EXIT

if [ ! -e /sys/devices/intel_pt/format/ptw ]; then
	echo "1..0 # SKIP PTWRITE unavailable"
	exit 0
fi

if [ "$(id -u)" != 0 ] || [ ! -f "$KO" ] || [ ! -f "$SRC" ] ||
	! command -v gcc >/dev/null || ! command -v python3 >/dev/null ||
	! command -v objdump >/dev/null || ! command -v readelf >/dev/null; then
	echo "1..0 # SKIP missing root, input, or required tool"
	exit 0
fi

# build test_prog and derive the NOP site's FILE offset
if ! gcc -O2 -no-pie -o "$PROG" "$SRC" 2>/dev/null; then
	echo "1..0 # SKIP test program build failed"
	exit 0
fi

TV=$(objdump -t "$PROG" 2>/dev/null |
	awk '$NF=="target_site" {print $1;exit}')
LV=$(readelf -l "$PROG" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $3; exit}}' | sed 's/^0x//')
LO=$(readelf -l "$PROG" 2>/dev/null |
	awk '/LOAD/{if ($1=="LOAD") {print $2; exit}}' | sed 's/^0x//')
OFF=$((0x$TV - 0x$LV + 0x$LO))
echo "1..5"

# 1: REG + IMM + MEM registration + a probed run
mod_run "r0,i0x42,m1"; rc=$?
if [ $rc -eq 0 ]; then
	t 1 ok "REG+IMM+MEM registration, probed run survives (mem fault fixup)"
elif [ $rc -eq 2 ]; then
	t 1 not "insmod with REG+IMM+MEM args failed"
else
	t 1 not "probed run failed (rc=$rc)"
fi

# 2: the paced 4-arg probe
mod_run "r0,i0x42,m1,r7"; rc=$?
if [ $rc -eq 0 ]; then
	t 2 ok "paced 4-arg probe (stack-free stub), run survives"
elif [ $rc -eq 2 ]; then
	t 2 not "insmod with the paced 4-arg set failed"
else
	t 2 not "paced run failed (rc=$rc)"
fi

# 3: the ptwrite payload emission + decode.  The standalone module event_id
# is not registered in tracefs, so extract the raw payloads and pass its ID
# and argument types explicitly to the decoder.
if ! command -v perf >/dev/null 2>&1 || [ ! -f "$DEC" ]; then
	t 3 skip "ptwrite decode (no perf/decoder)"
elif ! insmod "$KO" path="$PROG" offset=$OFF args="r0,i0x42,m1" \
       event_id=0x1234 2>/dev/null; then
	t 3 not "insmod for the decode run failed"
else
	perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o "$TMP/mod.data" \
		"$PROG" >/dev/null 2>&1
	rmmod $MOD 2>/dev/null
	perf script --itrace=we -i "$TMP/mod.data" 2>/dev/null |
		awk '/payload: 0x/ {
			for (i = 1; i <= NF; i++)
				if ($i == "payload:") print $(i + 1)
		}' > "$TMP/words.txt"
	python3 "$DEC" --words "$TMP/words.txt" \
		--event-id 0x1234 --types u64,u64,u64 2>/dev/null |
		grep '^record ' > "$TMP/records.txt"
	n=$(wc -l < "$TMP/records.txt")
	if [ "$n" -gt 0 ]; then
		t 3 ok "ptwrite records decoded ($n)"
	else
		t 3 not "no decoded ptwrite records"
	fi
fi

# 4: re-registration after uninstall (the site was restored)
if insmod "$KO" path="$PROG" offset=$OFF args="r0" event_id=0x1234 \
   2>/dev/null && rmmod $MOD 2>/dev/null &&
   insmod "$KO" path="$PROG" offset=$OFF args="r0" event_id=0x1234 \
   2>/dev/null; then
	rmmod $MOD 2>/dev/null
	t 4 ok "re-registration after uninstall"
else
	t 4 not "re-registration failed"
fi

# 5: the module's parser rejects a bad arg set
if insmod "$KO" path="$PROG" offset=$OFF args="r0,z1" \
   event_id=0x1234 2>/dev/null; then
	rmmod $MOD 2>/dev/null
	t 5 not "bad arg set accepted"
else
	t 5 ok "bad arg set rejected"
fi

[ $fails -eq 0 ] || exit 1
