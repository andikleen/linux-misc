#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
"""
uprobe-ptwrite-decode.py - decode ptwrite-uprobe trace events out of
PT logs.

Usage (perf script):
  perf script --itrace=qwe -s uprobe-ptwrite-decode.py -i perf.data \
      -- --event-id 0x1234 --types u64,u64,u64

Usage (raw PTWRITE payloads):
  uprobe-ptwrite-decode.py --words payloads.txt --event-id 0x1234 \
      --types u64,u64,u64
"""
import os
import re
import struct
import sys

TRACEFS = "/sys/kernel/tracing"

# type name -> (size bytes, signed, hex, char)
_TYPES = {
    "u8":  (1, False, False, False),
    "u16": (2, False, False, False),
    "u32": (4, False, False, False),
    "u64": (8, False, False, False),
    "s8":  (1, True, False, False),
    "s16": (2, True, False, False),
    "s32": (4, True, False, False),
    "s64": (8, True, False, False),
    "x8":  (1, False, True, False),
    "x16": (2, False, True, False),
    "x32": (4, False, True, False),
    "x64": (8, False, True, False),
    "char": (1, False, False, True),
}

_FIELD_RE = re.compile(r'^\s*field:(\S+)\s+(arg\d+);')

HDR_MAGIC = 0x5054525731   # "PTRW1"
HDR_MASK = (1 << 40) - 1

def load_events(root=TRACEFS):
    """Scan tracefs for (event_id -> (name, [(arg name, type)]))."""
    events = {}
    try:
        groups = os.listdir(root + "/events")
    except OSError:
        return events
    for g in groups:
        gdir = root + "/events/" + g
        if not os.path.isdir(gdir):
            continue
        for ev in os.listdir(gdir):
            edir = gdir + "/" + ev
            if not os.path.isdir(edir):
                continue
            try:
                with open(edir + "/id") as f:
                    eid = int(f.read().strip())
                with open(edir + "/format") as f:
                    fields = []
                    for line in f:
                        m = _FIELD_RE.match(line)
                        if m:
                            fields.append((m.group(2), m.group(1)))
                events[eid] = (g + "/" + ev, fields)
            except (OSError, ValueError):
                continue
    return events

def type_info(t):
    """('u64', size, signed, hex, char) for a format-file type name."""
    if t in _TYPES:
        return (t,) + _TYPES[t]
    return (t, 8, False, False, False)

def fmt_value(v, t):
    name, size, signed, ishex, ischar = type_info(t)
    mask = (1 << (8 * size)) - 1
    v &= mask
    if ischar:
        return repr(chr(v))
    if signed:
        sign = 1 << (8 * size - 1)
        if v & sign:
            v -= 1 << (8 * size)
    if ishex:
        return "0x%x" % v
    return str(v)

def is_header(word, events):
    if (word & HDR_MASK) != HDR_MAGIC:
        return None
    eid = (word >> 48) & 0xffff
    nargs = (word >> 40) & 0xff
    if not (1 <= nargs <= 8):
        return None
    if events and eid not in events:
        return None
    return (eid, nargs)

def decode_words(words, events):
    """Walk the ptwrite payload stream."""
    records = dropped = stray = unknown = 0
    cur = None      # (event_id, nargs, [args])
    rec_drop = False
    learned = {}
    arg_off = {}
    lines = []
    for w in words:
        if isinstance(w, tuple):
            word, ip, key = (w + (0, 0))[:3] if len(w) < 3 else (w[0], w[1], w[2])
        else:
            word, ip, key = w, 0, 0
        off = (ip & 0xfff) if ip else 0
        hdr = is_header(word, events)
        if hdr is not None:
            if cur is not None:
                dropped += cur[1] - len(cur[2])
            if learned.get(hdr[0]) and len(arg_off.get(hdr[0], ())) != hdr[1]:
                learned.pop(hdr[0], None)
                arg_off.pop(hdr[0], None)
            cur = (hdr[0], hdr[1], [])
            rec_drop = False
            continue
        if cur is None:
            # no record open: this is a raw ptwrite from the program
            lines.append((key, "manual ptwrite: payload=0x%x ip=0x%x"
                          % (word, ip)))
            stray += 1
            continue
        eid, nargs, args = cur
        if len(args) >= nargs:
            cur = None
            lines.append((key, "manual ptwrite: payload=0x%x ip=0x%x"
                          % (word, ip)))
            stray += 1
            continue
        if ip and learned.get(eid):
            offs = arg_off[eid]
            if len(args) >= len(offs):
                unknown += 1
                cur = None
                continue
            expect = offs[len(args)]
            if off != expect:
                j = next((k for k in range(len(args) + 1,
                                           min(nargs, len(offs)))
                          if off == offs[k]), None)
                if j is not None:
                    dropped += j - len(args)
                    args.extend([None] * (j - len(args)))
                    rec_drop = True
                else:
                    unknown += 1
                    continue
        if ip and not learned.get(eid):
            offsets = arg_off.setdefault(eid, set())
            if len(offsets) < nargs:
                offsets.add(off)
        args.append(word)
        if len(args) == nargs:
            if ip and not learned.get(eid):
                offs = sorted(set(arg_off.get(eid, [])))
                if len(offs) == nargs:
                    arg_off[eid] = offs
                    learned[eid] = True
            if not rec_drop:
                ev = (events or {}).get(eid)
                name = ev[0] if ev else "?"
                fields = ev[1] if ev else []
                parts = []
                for i, value in enumerate(args[:nargs]):
                    field_name = None
                    field_type = "u64"
                    if i < len(fields):
                        field_name, field_type = fields[i]
                    text = fmt_value(value, field_type)
                    parts.append("%s=%s" % (field_name, text)
                                 if field_name else text)
                fmt = ", ".join(parts)
                lines.append((key, "record %d: event=%s id=0x%x args=[%s]"
                             % (records + 1, name, eid, fmt)))
            records += 1
            cur = None
    if cur is not None:
        dropped += cur[1] - len(cur[2])

    return records, dropped, stray, unknown, lines

def _emit_record(eid, nargs, args, events, record_drop):
    global _records
    if record_drop:
        return
    ev = (events or {}).get(eid)
    name = ev[0] if ev else "?"
    fields = ev[1] if ev else []
    parts = []
    for i, value in enumerate(args[:nargs]):
        field_name = None
        field_type = "u64"
        if i < len(fields):
            field_name, field_type = fields[i]
        text = fmt_value(value, field_type)
        parts.append("%s=%s" % (field_name, text)
                     if field_name else text)
    fmt = ", ".join(parts)
    print("record %d: event=%s id=0x%x args=[%s]" %
          (_records + 1, name, eid, fmt))

def _decode_stream_word(word, ip, events, stream_key):
    global _records, _dropped, _stray, _unknown
    state = _streams.setdefault(stream_key, {"cur": None, "drop": False})
    off = (ip & 0xfff) if ip else 0
    hdr = is_header(word, events)
    if hdr is not None:
        if state["cur"] is not None:
            _dropped += state["cur"][1] - len(state["cur"][2])
        if _learned.get(hdr[0]) and len(_arg_off.get(hdr[0], ())) != hdr[1]:
            _learned.pop(hdr[0], None)
            _arg_off.pop(hdr[0], None)
        state["cur"] = (hdr[0], hdr[1], [])
        state["drop"] = False
        return
    cur = state["cur"]
    if cur is None:
        print("manual ptwrite: payload=0x%x ip=0x%x" % (word, ip))
        _stray += 1
        return
    eid, nargs, args = cur
    if len(args) >= nargs:
        state["cur"] = None
        print("manual ptwrite: payload=0x%x ip=0x%x" % (word, ip))
        _stray += 1
        return
    if ip and _learned.get(eid):
        offs = _arg_off[eid]
        if len(args) >= len(offs):
            _unknown += 1
            state["cur"] = None
            return
        expect = offs[len(args)]
        if off != expect:
            j = next((k for k in range(len(args) + 1,
                                       min(nargs, len(offs)))
                      if off == offs[k]), None)
            if j is not None:
                _dropped += j - len(args)
                args.extend([None] * (j - len(args)))
                state["drop"] = True
            else:
                _unknown += 1
                return
    if ip and not _learned.get(eid):
        offsets = _arg_off.setdefault(eid, set())
        if len(offsets) < nargs:
            offsets.add(off)
    args.append(word)
    if len(args) == nargs:
        if ip and not _learned.get(eid):
            offs = sorted(set(_arg_off.get(eid, set())))
            if len(offs) == nargs:
                _arg_off[eid] = offs
                _learned[eid] = True
        _emit_record(eid, nargs, args, events, state["drop"])
        _records += 1
        state["cur"] = None

def decode_buf(raw_buf, events, ip=0, key=0, stream_key=None):
    """Decode one 12-byte perf raw sample without retaining prior samples."""
    if len(raw_buf) < 12:
        return
    flags = struct.unpack_from("<I", raw_buf, 0)[0]
    payload = struct.unpack_from("<Q", raw_buf, 4)[0]
    if not flags & 1:
        ip = 0          # no FUP: the IP is not recoverable
    if stream_key is None:
        stream_key = 0
    _decode_stream_word(payload, ip, events, stream_key)

def parse_options(args):
    wordfile = None
    eid_override = None
    types_override = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--words":
            if i + 1 < len(args) and not args[i + 1].startswith("--"):
                wordfile = args[i + 1]
                i += 1
        elif a == "--event-id":
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                return None, None, None, "--event-id requires a value"
            try:
                eid_override = int(args[i + 1], 0)
            except ValueError:
                return None, None, None, "--event-id requires an integer"
            i += 1
        elif a == "--types":
            if i + 1 >= len(args) or args[i + 1].startswith("--"):
                return None, None, None, "--types requires a value"
            types_override = args[i + 1].split(",")
            i += 1
        i += 1
    return wordfile, eid_override, types_override, None

def apply_override(events, eid_override, types_override):
    if eid_override is not None and types_override is not None:
        events[eid_override] = ("override",
                                [(None, t) for t in types_override])
    return events

def cli_overrides():
    _, eid_override, types_override, error = parse_options(sys.argv[1:])
    if error is None:
        return eid_override, types_override
    print("ptwrite-decode: %s" % error, file=sys.stderr)
    return None, None

_event_id_override = None
_types_override = None

_events = {}
_streams = {}
_learned = {}
_arg_off = {}
_records = _dropped = _stray = _unknown = 0
_other_count = 0
_show_branches = "--no-branches" not in sys.argv

def _sample_stream_key(sample):
    if not sample:
        return (None, None, None)
    return (sample.get("cpu"), sample.get("pid"), sample.get("tid"))

def auxtrace_error(*args):
    global _errors
    if len(args) >= 8:
        _errors += 1
        print("ptwrite-decode: error type=%d code=%d cpu=%d pid=%d tid=%d"
              " ip=0x%x msg=%s" % (args[0], args[1], args[2], args[3],
                                   args[4], args[5], args[7]))

def trace_begin():
    global _events, _event_id_override, _types_override
    global _records, _dropped, _stray, _unknown, _errors, _other_count
    if not _events:
        _events = load_events()
    _event_id_override, _types_override = cli_overrides()
    apply_override(_events, _event_id_override, _types_override)
    _streams.clear()
    _learned.clear()
    _arg_off.clear()
    _records = _dropped = _stray = _unknown = 0
    _errors = _other_count = 0

def branch_line(param_dict):
    sample = param_dict.get("sample") or {}
    frm = sample.get("ip") or 0
    to = sample.get("addr") or 0
    frm_sym = param_dict.get("symbol") or "[unknown]"
    to_sym = sample.get("addr_symbol") or "[unknown]"
    frm_off = param_dict.get("symoff") or 0
    to_off = sample.get("addr_symoff") or 0
    frm_dso = param_dict.get("dso") or "[unknown]"
    to_dso = sample.get("addr_dso") or "[unknown]"
    fs = "+0x%x" % frm_off if frm_off else ""
    ts_ = "+0x%x" % to_off if to_off else ""
    return ("branch: 0x%x %s%s (%s) => 0x%x %s%s (%s)"
            % (frm, frm_sym, fs, frm_dso, to, to_sym, ts_, to_dso))

def other_line(name, sample, comm, sym=None, off=0, dso=None):
    """Format a non-ptwrite, non-branch event (classic uprobe,
    tracepoint, sample) for interleaved printing."""
    pid = sample.get("pid")
    tid = sample.get("tid")
    ip = sample.get("ip") or 0
    loc = " %s+0x%x (%s)" % (sym, off, dso) if sym else ""
    return ("event: %s comm=%s pid=%s tid=%s ip=0x%x%s"
            % (name, comm, pid, tid, ip, loc))

def trace_unhandled(handler_name, context, fields, sample=None):
    """Print tracepoint-class events immediately in delivery order."""
    global _other_count
    fields = fields or {}
    name = handler_name.replace("__", ":")
    comm = fields.get("common_comm") or ""
    pid = fields.get("common_pid")
    cpu = fields.get("common_cpu")
    print("event: %s comm=%s pid=%s cpu=%s" %
          (name, comm, pid, cpu))
    _other_count += 1

def process_event(param_dict):
    global _other_count
    sample = param_dict.get("sample") or {}
    name = param_dict.get("ev_name") or ""
    if name == "ptwrite":
        raw = param_dict.get("raw_buf")
        if raw:
            decode_buf(raw, _events, sample.get("ip") or 0,
                       stream_key=_sample_stream_key(sample))
    elif name.startswith("branches"):
        if _show_branches:
            print(branch_line(param_dict))
    else:
        print(other_line(name, sample,
                         param_dict.get("comm") or "",
                         param_dict.get("symbol"),
                         param_dict.get("symoff") or 0,
                         param_dict.get("dso")))
        _other_count += 1

def trace_end():
    global _dropped
    for state in _streams.values():
        cur = state["cur"]
        if cur is not None:
            _dropped += cur[1] - len(cur[2])
    print("summary: records=%d dropped=%d stray=%d unknown=%d errors=%d other=%d"
          % (_records, _dropped, _stray, _unknown, _errors, _other_count))
    _streams.clear()

def main():
    args = sys.argv[1:]
    wordfile, eid_override, types_override, error = parse_options(args)
    if error:
        print(error, file=sys.stderr)
        return 2

    events = apply_override(dict(_events), eid_override, types_override)
    words = []
    if wordfile:
        with open(wordfile) as f:
            for line in f:
                line = line.strip()
                if line.startswith(("0x", "0X")) or line.isdigit():
                    words.append(int(line, 16))
    else:
        for line in sys.stdin:
            line = line.strip()
            if line.startswith(("0x", "0X")) or line.isdigit():
                words.append(int(line, 16))

    records, dropped, stray, unknown, lines = decode_words(words, events)
    for _, text in lines:
        print(text)
    print("summary: records=%d dropped=%d stray=%d unknown=%d"
          % (records, dropped, stray, unknown))
    return 0 if (records > 0 and dropped == 0 and unknown == 0) else 1

if "--words" in sys.argv:
    sys.exit(main())
