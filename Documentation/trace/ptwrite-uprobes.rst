.. SPDX-License-Identifier: GPL-2.0

===============
ptwrite uprobes
===============

.. contents:: :local:

Introduction
============

A classic uprobe enters the kernel for each probe. That causes overhead
when the probe is executed frequently.

ptwrite uprobes instead rely on hardware tracing that doesn't enter
the kernel. It uses the ``PTWRITE`` instruction available on modern
Intel CPUs to log data to the Processor Trace buffer. Processor
Trace is configured and recorded by Linux perf.

There are some limitations of the scheme (see below)
but it is a lot faster than classic uprobes.

Performance
===========

Measured on the development kernel in a KVM guest (2 vCPUs) running
on a AlderLake laptop with a probe on a hot function called in a
tight loop.

    +---------------------------------------+----------------------+--------------------+------------------------+
    | mode (2-arg probe)                    | PT off (% of classic)| full (% of classic)| snapshot (% of classic)|
    +=======================================+======================+====================+========================+
    | classic uprobe (tracefs)              | 100%                 | 100%               | 100%                   |
    | classic uprobe (perf probe, trace r.) | 104%                 |                    |                        |
    | classic uprobe (perf probe, perf ring)|                      | 156%               |                        |
    | ptwrite %nopace                       | 2%                   | 2%                 | 8%                     |
    | ptwrite default                       | 7%                   | 7%                 | 11%                    |
    | perf probe ``--ptwrite``              | 7%                   | 7%                 | 12%                    |
    +---------------------------------------+----------------------+--------------------+------------------------+

The percentages are normalized to the classic tracefs uprobe in each
recording mode; lower values represent lower cost per hit.

A ``%nopace`` probe costs roughly **2%** as much as a classic uprobe
with PT off (about 98% less). The default pacing (on unless ``%nopace``
is given) costs roughly 7% as much (about 93% less) in the same mode.
The default pacing slows down the probes to avoid data loss when they are
too tightly spaced.

``snapshot`` refers to ``perf record`` snapshot mode (``-S``) which doesn't
save the PT ring buffer constantly.


Requirements
============

- An Intel CPU with Intel PT and PTWRITE. When running as a guest Intel PT
  needs to be exposed to the guest.
  PT/PTWRITE are available when ``/sys/devices/intel_pt/format/ptw`` exists.
- A kernel with ``CONFIG_UPROBE_EVENTS`` enabled.

Quick start (tracefs)
=====================

Pick a probe site, register a probe at its file offset, enable it, run the
program under PT, decode.

Example 1: probe an existing instruction (punning)
----------------------------------------------------

Build a small program and probe the entry of ``main``::

    $ cat > t.c <<'EOF'
    #include <stdio.h>

    __attribute__((noinline, noipa)) static unsigned long
    target(unsigned long a, unsigned long b)
    {
        return a * 31 + b;
    }

    int main(void)
    {
        unsigned long i, acc = 0;
        for (i = 0; i < 100; i++)
            acc += target(i, i + 1);
        printf("acc=%lu\n", acc);
        return 0;
    }
    EOF
    $ gcc -O2 -no-pie -fno-inline -o t t.c

``objdump -F`` prints the file offset of every instruction::

    $ objdump -d -F t | sed -n "/<main> (File Offset/,+1p"
    0000000000401040 <main> (File Offset: 0x1040):
      401040:	55			push   %rbp

``1040`` is the file offset of ``main``'s first instruction, exactly
what the probe line needs. Register the probe there, enable it, run
the program under PT and decode::

    # echo "ptw:e t:0x1040 %di %si" > /sys/kernel/tracing/uprobe_events
    # echo 1 > /sys/kernel/tracing/events/uprobes/e/enable
    # perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o perf.data ./t
    # perf script --itrace=qwe -s uprobe-ptwrite-decode.py -i perf.data
    record 1: event=uprobes/e id=0x6c2 args=[1, 140728356930600]
    summary: records=1 dropped=0 stray=0 unknown=0 errors=0

Since it isn't a nop the instruction is "punned": byte 0 is changed
to a jump to a trampoline that logs the data and returns to the
previous execution.

Punning is a probabilistic method that depends on the existing
instruction bytes and the placement of the executable in memory.
It has a high chance of success on PIE/PIC binaries, but tends
to work poorly on non PIE main executables.

When punning is not possible the probe is rejected at install
time. Options in this case:
- Move the probe site to a different instruction which may work.
- Rebuild with -fPIE if it's a main problem not using PIE.
- Enable or disable /proc/sys/kernel/randomize_va_space. If the
  randomization is enabled it may also just work on a rerun of
  the program.
- Fall back to a classic uprobes
- Insert a 5 byte nop which is always supported (see below)

Example 2: an explicit 5-byte NOP (inline assembly)
---------------------------------------------------

Add a 5-byte NOP at the probe point::

    $ cat > t.c <<'EOF'
    #include <stdio.h>

    __attribute__((noinline)) static unsigned long
    target(unsigned long a, unsigned long b)
    {
        asm volatile(".byte 0x0f, 0x1f, 0x44, 0x00, 0x00"); /* nopl */
        return a * 31 + b;
    }

    int main(void)
    {
        unsigned long i, acc = 0;
        for (i = 0; i < 100; i++)
            acc += target(i, i + 1);
        printf("acc=%lu\n", acc);
        return 0;
    }
    EOF
    $ gcc -O2 -no-pie -o t t.c

    $ objdump -d -F t | sed -n "/<target> (File Offset/,+1p"
    0000000000401170 <target> (File Offset: 0x1170):
      401170:	0f 1f 44 00 00		nopl   0x0(%rax,%rax,1)

Probe it exactly like example 1::

    # echo "ptw:e t:0x1170 %di %si" > /sys/kernel/tracing/uprobe_events
    # echo 1 > /sys/kernel/tracing/events/uprobes/e/enable
    # perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o perf.data ./t
    # perf script --itrace=qwe -s uprobe-ptwrite-decode.py -i perf.data
    record 99: event=uprobes/e id=0x6c2 args=[98, 99]
    record 100: event=uprobes/e id=0x6c2 args=[99, 100]
    summary: records=100 dropped=0 stray=0 unknown=0 errors=0

Configuring ptwrite uprobes
===========================

ptwrite uprobes is configured like normal uprobes by writing
commands to ``/sys/kernel/tracing/uprobe_events``.

  ptw[:[GRP/][EVENT]] PATH:OFFSET [FETCHARGS] : set a ptwrite probe
  -:[GRP/][EVENT]                             : clear a probe

  GRP      : group name. If omitted, "uprobes" is the default (the
             event appears under events/uprobes/).
  EVENT    : event name. If omitted, one is generated from PATH+OFFSET.
  PATH     : path to an executable or a library.
  OFFSET   : file offset of the probe site (0x-prefixed hex, see above).
  FETCHARGS: probe arguments, up to 8 (see "Argument syntax" below).

After creating the ptwrite uprobe it becomes available with its name
in ``/sys/kernel/tracing/uprobe_events``. There it can be enabled
by writing 1 to its enable field. However it only logs data
when a Linux perf PT recording session with ptw=1 is active.

perf probe
----------

``perf probe --ptwrite -x <file>`` creates ptwrite uprobes instead of
the classic trap-based ones. The example below uses SDT probes.

(this requires installing systemtap-devel or an equivalent package)

    $ cat > t.c <<'EOF'
    #include <stdio.h>
    #include <sys/sdt.h>
    __attribute__((noinline, noclone)) static unsigned long
    target(unsigned long a, unsigned long b)
    {
        unsigned long local = a * 2;
        STAP_PROBE1(test, rarg, a);
        STAP_PROBE1(test, carg, 42);
        STAP_PROBE2(test, marg, &local, b);
        return a * 31 + b;
    }
    int main(void)
    {
        unsigned long i, acc = 0;
        for (i = 0; i < 20; i++) {
            acc += target(i, i + 1);
            asm volatile("pause");
        }
        printf("acc=%lu\n", acc);
        return 0;
    }
    EOF
    $ gcc -O2 -no-pie -o t t.c

The first probe point (``rarg``) is a nop 9 bytes into ``target``::

    $ objdump -d t | sed -n "/<target>:/,+3p"
    0000000000401180 <target>:
      401180:	48 8d 04 3f		lea    (%rdi,%rdi,1),%rax
      401184:	48 89 44 24 f8		mov    %rax,-0x8(%rsp)
      401189:	90			nop

Probe it with ``perf probe --ptwrite`` using the function+offset
form, then enable, capture and delete it like any ptwrite probe::

    $ perf probe --ptwrite -x ./t --add "target+9 %di %si"
    Added new event:
      probe_t:target      (on target+9 in ./t with %di %si)

    # the tracefs line it wrote:
    # ptw:probe_t/target ./t:0x1189 arg1=%di arg2=%si

    # echo 1 > /sys/kernel/tracing/events/probe_t/target/enable
    # perf record -e intel_pt/ptw=1,fup_on_ptw=1/u -o perf.data ./t
    # perf script --itrace=qwe -s uprobe-ptwrite-decode.py -i perf.data
    record 1: event=probe_t/target id=0x6a9 args=[0, 1]
    record 20: event=probe_t/target id=0x6a9 args=[19, 20]
    summary: records=20 dropped=0 stray=0 unknown=0 errors=0
    # perf probe -d probe_t:target

A ``nop`` instruction, as used by SDT probes, is not guaranteed to
be ptwrite patchable. It needs a 5-byte NOP, but it can
often be punned. If punning fails, the kernel reports
``failed to install`` and the probe has to be moved to another site.

GCC's ``-fpatchable-function-entry=5`` may emit five one-byte NOPs.
To use that site, add ``%multinop`` to the tracefs probe offset::

    # echo "ptw:e t:0x1170%multinop %di %si" > /sys/kernel/tracing/uprobe_events

The five-byte run must start at an 8-byte-aligned address because it is
patched with an atomic eight-byte store. An unaligned ``%multinop`` site is
rejected; without ``%multinop``, the run is treated as a pun and may not
always succeed.

perf probe uses the standard argument syntax for the ptwrite subset
(registers, ``$stack``/``$stackN``, ``+disp(%reg)`` memory reads, and
``\0x2a``-style constants). Strings, arrays and typed suffixes are not
supported by the ptwrite stub and are rejected by the kernel.
``%return`` is refused (ptwrite probes are entry-only), and the mode
requires ``-x``. The probes are enabled, captured and deleted like
classic probes (``perf probe -l``, ``perf probe -d``).
They carry the default (LFENCE) pacing. ``%nopace`` cannot be selected
through perf probe. Write the tracefs line by hand for that.

Argument syntax
---------------

ptwrite uprobes only support a limited number of argument types
compared to classic uprobes.

``ptw:<name> <path>:<offset> <arg> ... [options]`` where each ``<arg>`` is one
of:

- ``%di``, ``%si``, ``%ax`` ...: a live register.
- ``\IMM``: a fixed constant (stored in the stub), e.g. ``\0x42``.
- ``$stack``: the stack pointer value (never faults).
- ``$stackN``: the Nth stack slot (``[%rsp + 8N]``). ``u64`` uses an
  8-byte load on the fault-fixup path; ``u32``/``s32``/``x32`` use a 4-byte
  load.
- ``+<disp>(%reg)``: read memory at ``[reg + disp]``. ``u64`` uses an
  8-byte load; ``u32``/``s32``/``x32`` use a 4-byte load (``ptwritel``).
  A bad address writes ``0``.

Options
-------

``%nopace`` disables artificial slowdown of the probes. This can cause
data loss when they are tightly spaced or have many arguments, but
speeds up the probes (see the benchmark section above)

``%multinop`` lets users probe a 5-byte nop sequence that is not one
instruction. A program could jump to a later nop, which would break when
the probe rewrites the site.

However there is a common case where gcc's -fpatchable-function-entry=5
generates 5 nops for each function that are convenient points
for patching, and nobody jumps into the middle of them.

The 5-byte single nop sequence must be aligned to 8 bytes.


The encoding format
===================

Each probe writes a header and the arguments to the PT stream.

The header is a 64-bit word. Each argument is one PTWRITE payload exposed by
perf as a ``u64`` value.

    header word:      bits 63..48  event id (matches the tracefs id in sysfs)
                      bits 47..40  number of argument words
                      bits 39..0   fixed magic 0x5054525731 ("PTRW1")
    arguments:        one PTWRITE payload per FETCHARG

If the program itself also executes own ``PTWRITE``, those values mix with the
uprobe output in the stream. The decoder uses the header magic to identify
uprobe records. Other values are printed as ``manual ptwrite:`` lines (with
their IP when ``fup_on_ptw`` is set) and counted in the summary's ``stray``
field.

To also print the decoded branch stream alongside the records, add
``b`` to the itrace options and drop the ``q``

    # ``perf script --itrace=web -s uprobe-ptwrite-decode.py -i perf.data``

Each decoded branch prints as a ``branch:`` line (from => to, with
symbols where resolvable), interleaved with the probe records and any
manual ptwrites in delivery order.

Other events in the recording, including classic uprobes, tracepoints,
and sample events, are printed as ``event:`` lines unless disabled
by the decoder.

Unsupported instructions for probes
===================================

The following instructions are always refused for instrumentation::

- Traps: ``int3``, ``int1``, ``int imm8``, ``into``, ``iret``
  because they save the IP.
- System instructions: ``syscall``, ``sysenter``, ``sysexit``
  for similar reasons.
- Far control flow: ``jmp far``, ``call far``, and the indirect far
  forms (call-far, jmp-far).
- Relative branches: ``jmp rel8/rel32``, ``jcc rel8/rel32``,
  ``loop*``, ``jecxz/jrcxz`` (target-inside-window, see below), and
  ``call rel32`` (its return address would point into the stub).
- Indirect ``call``: the return-address problem applies
  to the register/memory forms too.
- Relative branches (``jmp``/``jcc``/``loop`` with a rel8/rel32
  displacement, and ``call rel32``) are refused because the trampoline
  may not be able to reach the target.
- If the 5 byte area of the instruction crosses a page boundary it
  currently cannot be probed (this applies to nop probes too).

Other restrictions
==================

- Each probe needs 4K of process memory and roughly 1K extra in the kernel.
- The probe pages are currently only freed on process exit.
- Return probes (``%return``/``r:``): ptwrite probes are entry-only
  and ``%return`` is refused.
- The SDT reference counter (``(REF)``).
- EBPF, perf actions, filters, event predicates, histograms, triggers,
  profiling and similar advanced trace features are all not supported
  since they would require a kernel entry. However some basic filtering
  is possible at the perf recording level, for example limit the scope
  to a CPU or to a process. PT also supports address filter ranges
  that allow filtering by IP.
- More than one probe at the same site
- Only 4 and 8 byte memory references are supported.
- Fetch argument variety: classic probes fetch strings
  (``:string``/``:ustring``), arrays, bitfields, nested derefs,
  ``$retval``, ``$comm`` and ``$argN``. Ptwrite probes only take live
  registers, ``\IMM`` constants, ``$stack``/``$stackN`` and
  ``+disp(%reg)`` memory reads. Memory reads are 8-byte words for ``u64``
  and 4-byte words for ``u32``/``s32``/``x32``.
  (some of this could be relaxed, but it would require a writable stack)
- Like normal uprobes one byte of the instruction stream is overwritten
  (or 5 bytes for the nop case). If the program reads its own code
  it might see different values.
