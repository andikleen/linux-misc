#!/bin/bash
# SPDX-License-Identifier: GPL-2.0-only
# Host-side PT checks: T1 idle trace, T3 trace while a guest traces,
# T5 hotplug the last E-core during a guest stress run (root only).
# SKIPs (exit 4) when there's no intel_pt PMU, perf, or built guest test.
set -u

KSFT_SKIP=4

[ -d /sys/bus/event_source/devices/intel_pt ] || exit $KSFT_SKIP
command -v perf >/dev/null 2>&1 || { echo "pt_host_pt: perf not found"; exit $KSFT_SKIP; }

DIR=$(dirname "$0")
TST=$DIR/pt_guest_trace_test
[ -x "$TST" ] || { echo "pt_host_pt: $TST not built"; exit $KSFT_SKIP; }

if [ "$(id -u)" -ne 0 ] &&
   [ "$(cat /proc/sys/kernel/perf_event_paranoid 2>/dev/null || echo 2)" -ge 0 ]; then
	echo "pt_host_pt: insufficient perf_event permissions"
	exit $KSFT_SKIP
fi

fail=0
DATA1=$(mktemp /tmp/pt_host_t1.XXXXXX.data)
DATA3=$(mktemp /tmp/pt_host_t3.XXXXXX.data)
trap 'rm -f "$DATA1" "$DATA3"' EXIT

echo "T1: host PT trace (idle)"
if perf record -e intel_pt// -a -o "$DATA1" -- sleep 3 2>/dev/null \
   && perf script -i "$DATA1" --itrace=i0ns -F comm,event 2>/dev/null \
	| grep -q instructions; then
	echo "ok 1 T1"
else
	echo "not ok 1 T1"; fail=1
fi

echo "T3: host PT while guest traces"
perf record -e intel_pt// -a -o "$DATA3" -- sleep 15 2>/dev/null &
HPID=$!
sleep 1
"$TST"
GRC=$?
wait $HPID
if [ $GRC -eq 4 ]; then
	echo "ok 2 T3 # SKIP (guest test skipped: pt_mode != 1?)"
elif [ $GRC -eq 0 ] \
   && perf script -i "$DATA3" --itrace=i0ns -F comm,event 2>/dev/null \
	| grep -q instructions; then
	echo "ok 2 T3"
else
	echo "not ok 2 T3"; fail=1
fi

E_LAST=
if [ -f /sys/bus/event_source/devices/cpu_atom/cpus ]; then
	E_LAST=$(sed 's/.*[-,]//' /sys/bus/event_source/devices/cpu_atom/cpus)
fi
if [ "$(id -u)" = 0 ] && [ -n "$E_LAST" ] \
   && [ -w /sys/devices/system/cpu/cpu${E_LAST}/online ]; then
	echo "T5: hotplug during guest trace stress"
	"$TST" --stress 12 &
	TPID=$!
	sleep 4
	echo 0 > /sys/devices/system/cpu/cpu${E_LAST}/online
	sleep 3
    echo 1 > "/sys/devices/system/cpu/cpu${E_LAST}/online"
    if wait "$TPID"; then
		echo "ok 3 T5"
	else
		echo "not ok 3 T5"; fail=1
	fi
else
	echo "ok 3 T5 # SKIP (needs root + hybrid host)"
fi

exit $fail
