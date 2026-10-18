# Copyright 2026 Ryu116
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

# Full Dump - read-only dump of an analyzed program (any x86 game/exe Ghidra can analyze).
# Writes THREE folders under OUTPUT_ROOT (example for FA.EXE):
#   FA.EXE_ASSEMBLY      14_Assembly_dump.txt  every defined instruction, grouped by function (ground truth)
#                        00_summary.txt
#   FA.EXE_C_PSEUDOCODE  13_function_dump.txt (+ "- AI.txt")  Ghidra's decompiled C, per function
#                        decompile_failed.txt  functions with no C (assembly only)
#                        00_summary.txt
#   FA.EXE_INVENTORY     01-12  memory, imports, exports, classes, functions, strings, constants,
#                        variables, string tables, compare chains, structures, enums
#                        dump_index.json, 00_summary.txt (master summary of all three folders)
# Run AFTER auto-analysis (and RecoverClassesFromRTTIScript when the program has RTTI).
# This script never modifies the program (no createData, no renames).
# The function address is the key that links a function across the three folders.
# @category SF2_AI
# @runtime PyGhidra

import json
import math
import os
import re
import time

import jpype
from java.lang import Double as JDouble, Float as JFloat

from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.program.model.data import Enum, Structure, Union
from ghidra.program.model.symbol import SymbolType

# ---------------------------------------------------------------- settings
OUTPUT_ROOT_OVERRIDE = ""    # leave empty = Windows Downloads folder\Ghidra_Dumps; or set your own folder, e.g. r"D:\Dumps"


def downloads_folder():
    """The user's real Downloads folder (works even if it was moved to another drive)."""
    if os.name == "nt":
        try:
            import ctypes
            from ctypes import wintypes
            guid = ctypes.c_byte * 16
            # FOLDERID_Downloads = {374DE290-123F-4565-9164-39C4925E467B}
            fid = (ctypes.c_byte * 16)(*bytearray.fromhex("90E24D373F126545916439C4925E467B"))
            buf = ctypes.c_wchar_p()
            if ctypes.windll.shell32.SHGetKnownFolderPath(ctypes.byref(fid), 0, None, ctypes.byref(buf)) == 0:
                path = buf.value
                ctypes.windll.ole32.CoTaskMemFree(buf)
                if path:
                    return path
        except Exception:
            pass
    return os.path.join(os.path.expanduser("~"), "Downloads")


OUTPUT_ROOT       = OUTPUT_ROOT_OVERRIDE or os.path.join(downloads_folder(), "Ghidra_Dumps")
DECOMPILE_ALL     = True     # False = function dump without decompiled C (much faster)
AI_ADDRESS_LINE   = False    # True = add "// address" above each function in the AI file
AI_KEEP_WARNINGS  = False    # True = keep decompiler /* WARNING */ lines in the AI file
CHARS_PER_TOKEN   = 3.2      # token estimate ratio for code/hex-heavy text (approximate)
ASM_FILENAME      = "14_Assembly_dump.txt"   # assembly dump (set to 15_Assembly_Dump.txt to match old name)
DECOMPILE_TIMEOUT = 60
TABLE_MIN_ENTRIES = 3        # minimum strings in a row to count as a table
TABLE_MAX_STRIDE  = 0x40     # largest entry size considered for tables
RAW_STRING_MAX    = 80       # max length when reading undefined bytes as a string
MAX_LIST          = 12       # max names in "used by" style lists
MAX_FUNC_STRINGS  = 60       # max strings listed per function in the function dump
MAX_TEXT_LEN      = 200

# ---------------------------------------------------------------- globals
prog    = currentProgram
fm      = prog.getFunctionManager()
st      = prog.getSymbolTable()
rm      = prog.getReferenceManager()
listing = prog.getListing()
mem     = prog.getMemory()
dtm     = prog.getDataTypeManager()
space   = prog.getAddressFactory().getDefaultAddressSpace()

_init_blocks = [b for b in mem.getBlocks() if b.isInitialized()]
MEM_LO = min(b.getStart().getOffset() for b in _init_blocks) if _init_blocks else 0
MEM_HI = max(b.getEnd().getOffset() for b in _init_blocks) if _init_blocks else 0

stats         = {}   # inventory / program-wide counts
stats_asm     = {}   # assembly folder counts
stats_c       = {}   # C pseudocode folder counts
dirs          = {}   # "asm" / "c" / "inv" -> folder path
written_files = []   # (folder, file name) written this run, in order
callees_cache = {}   # func key -> [Function]
callers_cache = {}   # func key -> [Function]
direct_cmp    = set()  # func keys that directly call a string-compare function
func_info     = {}   # func key -> {"name", "strings": [(ins_addr, text, raw)], "data": {addr: [r, w, a]}}
data_index    = {}   # addr str -> usage record
tables        = []   # string table records
func_tables   = {}   # func key -> [table id]

SIZE_RX = re.compile(r"\b(byte|word|dword|qword|tword|xmmword|ymmword)\s+ptr\b", re.IGNORECASE)
SIZES   = {"byte": 1, "word": 2, "dword": 4, "qword": 8, "tword": 10, "xmmword": 16, "ymmword": 32}


class Cancelled(Exception):
    pass


# ---------------------------------------------------------------- helpers
def check():
    if monitor.isCancelled():
        raise Cancelled()


def jiter(it):
    while it.hasNext():
        yield it.next()


def clean(value, limit=MAX_TEXT_LEN):
    s = str(value)
    s = s.replace("\\", "\\\\").replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return s if len(s) <= limit else s[:limit] + "..."


def out(folder, name):
    if (folder, name) not in written_files:
        written_files.append((folder, name))
    return open(os.path.join(folder, name), "w", encoding="utf-8", errors="replace", newline="\n")


def short_list(names, limit=MAX_LIST):
    names = list(names)
    s = " | ".join(names[:limit])
    if len(names) > limit:
        s += " | (+%d more)" % (len(names) - limit)
    return s


def fkey(fn):
    return str(fn.getEntryPoint())


def addr_from(value):
    try:
        return space.getAddress(value)
    except Exception:
        return None


def fmt_float(v):
    v = float(v)
    if v != v:
        return "NaN"
    if v in (float("inf"), float("-inf")):
        return str(v)
    return "%.9g" % v


# ---------------------------------------------------------------- read-only memory access
def read_bytes(addr, n):
    blk = mem.getBlock(addr)
    if blk is None or not blk.isInitialized():
        return None
    n = int(min(n, blk.getEnd().subtract(addr) + 1))
    if n <= 0:
        return None
    buf = jpype.JArray(jpype.JByte)(n)
    try:
        got = mem.getBytes(addr, buf)
    except Exception:
        return None
    return [buf[i] & 0xFF for i in range(got)]


def raw_ascii(addr):
    data = read_bytes(addr, RAW_STRING_MAX + 1)
    if not data:
        return None
    chars = []
    for b in data:
        if b == 0:
            break
        if b < 0x20 or b > 0x7E:
            return None
        chars.append(chr(b))
    else:
        return None  # no terminator found
    s = "".join(chars)
    if len(s) < 2 or not re.search(r"[A-Za-z]", s):
        return None
    return s


def raw_utf16(addr):
    data = read_bytes(addr, (RAW_STRING_MAX + 1) * 2)
    if not data or len(data) < 4:
        return None
    chars = []
    for i in range(0, len(data) - 1, 2):
        lo, hi = data[i], data[i + 1]
        if lo == 0 and hi == 0:
            break
        if hi != 0 or lo < 0x20 or lo > 0x7E:
            return None
        chars.append(chr(lo))
    else:
        return None
    s = "".join(chars)
    if len(s) < 2 or not re.search(r"[A-Za-z]", s):
        return None
    return s


def string_at(addr, allow_raw=True):
    """Return a string at addr without modifying the program, else None."""
    data = listing.getDataAt(addr)
    if data is not None and data.isDefined():
        if data.hasStringValue():
            try:
                return str(data.getValue())
            except Exception:
                return None
        return None  # defined as something that is not a string
    if not allow_raw:
        return None
    s = raw_ascii(addr)
    return s if s is not None else raw_utf16(addr)


def describe_pointer(u):
    if u == 0 or u < MEM_LO or u > MEM_HI:
        return ""
    t = addr_from(u)
    if t is None or not mem.contains(t):
        return ""
    f = fm.getFunctionAt(t)
    if f is not None:
        return " -> func " + str(f.getName(True))
    s = string_at(t)
    if s is not None:
        return ' -> "%s"' % clean(s, 60)
    sym = st.getPrimarySymbol(t)
    if sym is not None:
        return " -> " + str(sym.getName(True))
    return " -> " + str(t)


def value_kind(mnemonic, size):
    m = str(mnemonic).upper()
    if m.startswith("FI"):                       # FILD, FIST, FISTP, FIMUL, FIADD, FICOM...
        return "int"
    if m.startswith("F") and m not in ("FLDCW", "FSTCW", "FNSTCW", "FSTSW", "FNSTSW",
                                       "FLDENV", "FSTENV", "FNSTENV", "FSAVE", "FNSAVE",
                                       "FRSTOR", "FXSAVE", "FXRSTOR"):
        return {4: "float", 8: "double", 10: "float80"}.get(size, "int")
    if m.startswith("CVTSI2") or m.startswith("VCVTSI2"):
        return "int"
    if m.startswith("CVTSS") or m.startswith("VCVTSS"):
        return "float"
    if m.startswith("CVTSD") or m.startswith("VCVTSD"):
        return "double"
    if m.endswith("SS") or m.endswith("PS"):
        return "float"
    if m.endswith("SD") or m.endswith("PD"):
        return "double"
    return "int"


def use_label(kind, size):
    if kind == "addr":
        return "addr"
    if kind == "float":
        return "float32" if size == 4 else "float32[%d]" % (size // 4)
    if kind == "double":
        return "double64" if size == 8 else "double64[%d]" % (size // 8)
    if kind == "float80":
        return "float80"
    return "int%d" % (size * 8)


def read_value(addr, kind, size):
    blk = mem.getBlock(addr)
    if blk is None:
        return "(outside memory)"
    if not blk.isInitialized():
        return "(no initial value)"
    try:
        if kind == "float":
            n = max(1, size // 4)
            return ", ".join(fmt_float(JFloat.intBitsToFloat(mem.getInt(addr.add(i * 4)))) for i in range(n))
        if kind == "double":
            n = max(1, size // 8)
            return ", ".join(fmt_float(JDouble.longBitsToDouble(mem.getLong(addr.add(i * 8)))) for i in range(n))
        if size == 1:
            v = mem.getByte(addr) & 0xFF
            return "%d (0x%02X)" % (v, v)
        if size == 2:
            v = mem.getShort(addr)
            return "%d (0x%04X)" % (v, v & 0xFFFF)
        if size == 4:
            v = mem.getInt(addr)
            return "%d (0x%08X)%s" % (v, v & 0xFFFFFFFF, describe_pointer(v & 0xFFFFFFFF))
        if size == 8:
            v = mem.getLong(addr)
            return "%d (0x%016X)" % (v, v & 0xFFFFFFFFFFFFFFFF)
        raw = read_bytes(addr, size)
        return " ".join("%02X" % b for b in raw) if raw else "(unreadable)"
    except Exception:
        return "(unreadable)"


def is_compare_name(name):
    n = str(name).lower()
    return "cmp" in n or "comparestring" in n


def compare_level(key):
    if key in direct_cmp:
        return "direct"
    for c in callees_cache.get(key, []):
        if fkey(c) in direct_cmp:
            return "via helper"
    return ""


def clean_c(text, keep_comments=True):
    """Whitespace-only cleanup of decompiled C. Normalizes line endings, drops blank
    lines and trailing spaces, joins the signature onto one line, and optionally
    removes whole-line comments. Code tokens and inline comments are never changed."""
    text = str(text).replace("\r\n", "\n").replace("\r", "\n")
    items = []          # (is_comment, line)
    in_block = False
    for raw in text.split("\n"):
        ln = raw.rstrip()
        stripped = ln.strip()
        if not stripped:
            continue
        if in_block:
            items.append((True, ln))
            if "*/" in stripped:
                in_block = False
            continue
        if stripped.startswith("//"):
            items.append((True, ln))
            continue
        if stripped.startswith("/*"):
            items.append((True, ln))
            if "*/" not in stripped:
                in_block = True
            continue
        items.append((False, ln))

    if not keep_comments:
        items = [it for it in items if not it[0]]

    brace = None
    for i, (is_comment, ln) in enumerate(items):
        if not is_comment and ln == "{":
            brace = i
            break
    if brace is None:
        return "\n".join(ln for _, ln in items)

    head, sig = [], []
    for is_comment, ln in items[:brace]:
        if is_comment:
            head.append(ln)
        else:
            sig.append(ln.strip())
    if sig:
        head.append(" ".join(sig))
    return "\n".join(head + [ln for _, ln in items[brace:]])


def open_decompiler():
    decomp = DecompInterface()
    opts = DecompileOptions()
    opts.grabFromProgram(prog)
    decomp.setOptions(opts)
    if not decomp.openProgram(prog):
        raise RuntimeError("Decompiler failed: " + str(decomp.getLastMessage()))
    return decomp


# ---------------------------------------------------------------- inventory
def dump_memory(folder):
    monitor.setMessage("Dump: memory blocks")
    with out(folder, "01_memory_blocks.txt") as f:
        f.write("NAME\tSTART\tEND\tSIZE\tPERMS\tINITIALIZED\n")
        n = 0
        for b in mem.getBlocks():
            perms = ("r" if b.isRead() else "-") + ("w" if b.isWrite() else "-") + ("x" if b.isExecute() else "-")
            f.write("%s\t%s\t%s\t0x%x\t%s\t%s\n" % (b.getName(), b.getStart(), b.getEnd(),
                                                    b.getSize(), perms, b.isInitialized()))
            n += 1
    stats["Memory blocks"] = n


def dump_imports(folder):
    monitor.setMessage("Dump: imports")
    rows = []
    for s in jiter(st.getExternalSymbols()):
        check()
        rows.append((str(s.getParentNamespace().getName(True)), str(s.getName()),
                     str(s.getSymbolType()), s.getReferenceCount()))
    rows.sort()
    with out(folder, "02_imports.txt") as f:
        f.write("LIBRARY\tNAME\tTYPE\tREFS\n")
        for r in rows:
            f.write("%s\t%s\t%s\t%d\n" % r)
    stats["Imports"] = len(rows)


def dump_exports(folder):
    monitor.setMessage("Dump: exports")
    n = 0
    with out(folder, "03_exports.txt") as f:
        f.write("ADDRESS\tALL_SYMBOL_NAMES\tSIGNATURE\n")
        for addr in jiter(st.getExternalEntryPointIterator()):
            check()
            names = " / ".join(str(s.getName(True)) for s in st.getSymbols(addr))
            fn = fm.getFunctionAt(addr)
            sig = str(fn.getSignature().getPrototypeString()) if fn else "(data)"
            f.write("%s\t%s\t%s\n" % (addr, names, sig))
            n += 1
    stats["Exports"] = n


def dump_classes(folder):
    monitor.setMessage("Dump: classes")
    classes = sorted(jiter(st.getClassNamespaces()), key=lambda c: str(c.getName(True)))
    total = unnamed = placeholder = 0
    with out(folder, "04_classes.txt") as f:
        for c in classes:
            check()
            methods, others = [], []
            for s in jiter(st.getSymbols(c)):
                (methods if s.getSymbolType() == SymbolType.FUNCTION else others).append(s)
            methods.sort(key=lambda s: s.getAddress().getOffset())
            f.write("CLASS %s   (methods: %d)\n" % (c.getName(True), len(methods)))
            for s in others:
                f.write("  [%s] %s  %s\n" % (s.getSymbolType(), s.getAddress(), s.getName()))
            for s in methods:
                fn = fm.getFunctionAt(s.getAddress())
                sig = str(fn.getSignature().getPrototypeString()) if fn else str(s.getName())
                f.write("  %s  %-12s  %s\n" % (s.getAddress(), s.getSource(), sig))
                total += 1
                mname = str(s.getName())
                if mname.startswith("FUN_"):
                    unnamed += 1
                elif re.match(r"^vfunction\d+$", mname):
                    placeholder += 1
            f.write("\n")
    stats["Classes"] = len(classes)
    stats["Class methods"] = total
    stats["Class methods still FUN_"] = unnamed
    stats["Class methods with placeholder vfunctionN"] = placeholder


def build_call_cache():
    monitor.setMessage("Building call graph")
    for i, fn in enumerate(jiter(fm.getFunctions(True))):
        if i % 200 == 0:
            check()
        k = fkey(fn)
        callees_cache[k] = list(fn.getCalledFunctions(monitor))
        callers_cache[k] = list(fn.getCallingFunctions(monitor))
    for k, callees in callees_cache.items():
        if any(is_compare_name(c.getName()) for c in callees):
            direct_cmp.add(k)
    stats["Functions calling a string compare"] = len(direct_cmp)


def dump_function_list(folder):
    monitor.setMessage("Dump: function list")
    by_source = {}
    total = thunks = 0
    with out(folder, "05_functions.txt") as f:
        f.write("ENTRY\tSIZE\tSOURCE\tTHUNK\tCALLERS\tCALLEES\tCONVENTION\tNAME\tSIGNATURE\n")
        for fn in jiter(fm.getFunctions(True)):
            check()
            k = fkey(fn)
            src = str(fn.getSymbol().getSource())
            by_source[src] = by_source.get(src, 0) + 1
            total += 1
            thunks += 1 if fn.isThunk() else 0
            f.write("%s\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\n" % (
                k, fn.getBody().getNumAddresses(), src, fn.isThunk(),
                len(callers_cache.get(k, [])), len(callees_cache.get(k, [])),
                fn.getCallingConventionName(), fn.getName(True),
                fn.getSignature().getPrototypeString()))
    stats["Functions"] = total
    stats["Thunks"] = thunks
    for k in sorted(by_source):
        stats["Functions named by " + k] = by_source[k]


def dump_strings(folder):
    monitor.setMessage("Dump: strings")
    n = 0
    with out(folder, "06_strings.txt") as f:
        f.write("ADDRESS\tTYPE\tREFS\tUSED_BY_FUNCTIONS\tVALUE\n")
        for i, d in enumerate(jiter(listing.getDefinedData(True))):
            if i % 500 == 0:
                check()
            if not d.hasStringValue():
                continue
            total = 0
            funcs = []
            for ref in jiter(rm.getReferencesTo(d.getAddress())):
                total += 1
                fn = fm.getFunctionContaining(ref.getFromAddress())
                if fn is not None:
                    name = str(fn.getName(True))
                    if name not in funcs:
                        funcs.append(name)
            f.write("%s\t%s\t%d\t%s\t%s\n" % (d.getAddress(), d.getDataType().getName(),
                                              total, short_list(funcs), clean(d.getValue())))
            n += 1
    stats["Defined strings"] = n


# ---------------------------------------------------------------- code scan
def scan_instructions():
    total = fm.getFunctionCount()
    for i, fn in enumerate(jiter(fm.getFunctions(True))):
        if i % 100 == 0:
            check()
            monitor.setMessage("Scanning code %d/%d" % (i + 1, total))
        if fn.isThunk():
            continue
        k = fkey(fn)
        fname = str(fn.getName(True))
        info = {"name": fname, "strings": [], "data": {}}
        func_info[k] = info

        for ins in jiter(listing.getInstructions(fn.getBody(), True)):
            for ref in ins.getReferencesFrom():
                if ref.isExternalReference() or ref.isStackReference():
                    continue
                to = ref.getToAddress()
                if not to.isMemoryAddress():
                    continue
                rt = ref.getReferenceType()
                if rt.isFlow():
                    continue
                blk = mem.getBlock(to)
                if blk is None or blk.isExecute():
                    continue

                op = ref.getOperandIndex()
                rep = str(ins.getDefaultOperandRepresentation(op)) if op >= 0 else ""
                m = SIZE_RX.search(rep)
                size = SIZES[m.group(1).lower()] if m else 0

                data = listing.getDataAt(to)
                defined = data is not None and data.isDefined()
                if defined and data.hasStringValue():
                    info["strings"].append((str(ins.getAddress()), str(data.getValue()), False))
                    continue
                if not defined and size == 0:
                    raw = string_at(to)
                    if raw is not None:
                        info["strings"].append((str(ins.getAddress()), raw, True))
                        continue

                kind = value_kind(ins.getMnemonicString(), size) if size else "addr"
                label = use_label(kind, size)
                t = str(to)
                rec = data_index.get(t)
                if rec is None:
                    rec = {"addr": to, "block": str(blk.getName()), "writable": bool(blk.isWrite()),
                           "initialized": bool(blk.isInitialized()), "uses": {},
                           "reads": 0, "writes": 0, "addrof": 0, "funcs": []}
                    data_index[t] = rec
                use = rec["uses"].setdefault(label, [kind, size, 0])
                use[2] += 1

                counts = info["data"].setdefault(t, [0, 0, 0])
                if kind == "addr":
                    rec["addrof"] += 1
                    counts[2] += 1
                else:
                    if rt.isRead():
                        rec["reads"] += 1
                        counts[0] += 1
                    if rt.isWrite():
                        rec["writes"] += 1
                        counts[1] += 1
                if fname not in rec["funcs"]:
                    rec["funcs"].append(fname)


def describe_values(rec, data):
    parts = []
    for label in sorted(rec["uses"]):
        kind, size, _ = rec["uses"][label]
        if kind == "addr":
            continue
        parts.append("%s=%s" % (label, read_value(rec["addr"], kind, size)))
    if not parts:
        if data is not None and data.isDefined():
            parts.append("%s=%s" % (data.getDataType().getName(),
                                    clean(data.getDefaultValueRepresentation(), 60)))
        elif not rec["initialized"]:
            parts.append("(no initial value)")
        else:
            parts.append("(address taken only)")
    return " | ".join(parts)


def dump_data(folder):
    monitor.setMessage("Dump: constants and variables")
    header = ("ADDRESS\tBLOCK\tSYMBOL\tGHIDRA_TYPE\tUSED_AS\tVALUE\tREADS\tWRITES\t"
              "ADDR_TAKEN\tUSED_BY_FUNCTIONS\n")
    consts, variables = [], []
    conflicts = 0
    for t, rec in data_index.items():
        check()
        to = rec["addr"]
        sym = st.getPrimarySymbol(to)
        name = str(sym.getName(True)) if sym is not None else "(no label)"
        data = listing.getDataAt(to)
        gtype = str(data.getDataType().getName()) if data is not None and data.isDefined() else "undefined"
        kinds = set(u[0] for u in rec["uses"].values() if u[0] != "addr")
        used = ", ".join("%s x%d" % (lbl, u[2]) for lbl, u in sorted(rec["uses"].items()))
        if len(kinds) > 1:
            used += "  !TYPE CONFLICT"
            conflicts += 1
        value = describe_values(rec, data)
        section = "const" if not rec["writable"] else ("var" if rec["initialized"] else "bss")
        rec["summary"] = {"address": t, "block": rec["block"], "section": section, "symbol": name,
                          "ghidra_type": gtype, "used_as": used, "value": value,
                          "reads": rec["reads"], "writes": rec["writes"],
                          "addr_taken": rec["addrof"], "functions": rec["funcs"]}
        line = "%s\t%s\t%s\t%s\t%s\t%s\t%d\t%d\t%d\t%s\n" % (
            t, rec["block"], name, gtype, used, value, rec["reads"], rec["writes"],
            rec["addrof"], short_list(rec["funcs"]))
        (consts if section == "const" else variables).append((to.getOffset(), line))

    for fname, rows in (("07_constants.txt", consts), ("08_variables.txt", variables)):
        rows.sort(key=lambda r: r[0])
        with out(folder, fname) as f:
            f.write(header)
            for _, line in rows:
                f.write(line)
    stats["Constants (read-only data used by code)"] = len(consts)
    stats["Variables (writable data used by code)"] = len(variables)
    stats["Data used as conflicting types"] = conflicts


# ---------------------------------------------------------------- string tables
def group_runs(hits):
    hits.sort(key=lambda h: h[0])
    runs = []
    i, n = 0, len(hits)
    while i < n - 1:
        d = hits[i + 1][0] - hits[i][0]
        if 4 <= d <= TABLE_MAX_STRIDE and d % 4 == 0:
            j = i + 1
            while j + 1 < n and hits[j + 1][0] - hits[j][0] == d:
                j += 1
            if j - i + 1 >= TABLE_MIN_ENTRIES:
                runs.append((d, hits[i:j + 1]))
                i = j + 1
                continue
        i += 1
    return runs


def scan_string_tables(folder):
    monitor.setMessage("Scanning for string tables")
    hits = []
    for b in mem.getBlocks():
        if b.isExecute() or not b.isInitialized():
            continue
        start = b.getStart()
        size = int(b.getSize())
        off = (4 - start.getOffset() % 4) % 4
        steps = 0
        while off + 4 <= size:
            steps += 1
            if steps % 50000 == 0:
                check()
            a = start.add(off)
            try:
                v = mem.getInt(a) & 0xFFFFFFFF
            except Exception:
                off += 4
                continue
            if MEM_LO <= v <= MEM_HI:
                t = addr_from(v)
                if t is not None:
                    tb = mem.getBlock(t)
                    if tb is not None and not tb.isExecute():
                        s = string_at(t)
                        if s is not None:
                            hits.append((a.getOffset(), a, t, s))
            off += 4

    likely = 0
    for tid, (stride, run) in enumerate(group_runs(hits), 1):
        check()
        first, last = run[0][0], run[-1][0]
        entries = []
        for idx, (_, a, t, s) in enumerate(run):
            fields = []
            for fo in range(4, stride, 4):
                try:
                    fv = mem.getInt(a.add(fo))
                    fields.append("+0x%X=%d%s" % (fo, fv, describe_pointer(fv & 0xFFFFFFFF)))
                except Exception:
                    fields.append("+0x%X=?" % fo)
            entries.append({"index": idx, "pointer_at": str(a), "string_at": str(t),
                            "text": s, "fields": fields})

        consumers = {}
        data_refs = []
        for o in range(first - (stride - 4), last + stride, 4):
            ra = addr_from(o)
            if ra is None:
                continue
            for ref in jiter(rm.getReferencesTo(ra)):
                src = ref.getFromAddress()
                fn = fm.getFunctionContaining(src)
                if fn is not None:
                    consumers[fkey(fn)] = str(fn.getName(True))
                elif str(src) not in data_refs:
                    data_refs.append(str(src))

        levels = {k: compare_level(k) for k in consumers}
        if any(levels.values()):
            verdict = "LIKELY ENUM (a consumer compares strings)"
            likely += 1
        elif consumers:
            verdict = "USED BY CODE (check how it is used)"
        elif data_refs:
            verdict = "REFERENCED FROM DATA ONLY"
        else:
            verdict = "NO REFERENCES FOUND (unconfirmed)"

        rec = {"id": tid, "start": str(run[0][1]), "end": str(run[-1][1]), "stride": stride,
               "entries": entries, "verdict": verdict, "data_refs": data_refs,
               "consumers": [{"entry": k, "name": n, "compares": levels[k]} for k, n in consumers.items()]}
        tables.append(rec)
        for k in consumers:
            func_tables.setdefault(k, []).append(tid)

    with out(folder, "09_string_tables.txt") as f:
        f.write("String pointer tables. Entry index is the likely enum value when the verdict is\n")
        f.write("LIKELY ENUM, but confirm in the consumer's decompiled code (13_function_dump.txt).\n")
        f.write("fields = other 4-byte values in each entry (for stride > 4).\n\n")
        for rec in tables:
            f.write("TABLE #%d  %s..%s  stride 0x%X  entries %d\n" % (
                rec["id"], rec["start"], rec["end"], rec["stride"], len(rec["entries"])))
            f.write("  verdict:  %s\n" % rec["verdict"])
            for c in rec["consumers"]:
                f.write("  used by:  %s @ %s%s\n" % (c["name"], c["entry"],
                                                     "  [compares: %s]" % c["compares"] if c["compares"] else ""))
            if rec["data_refs"]:
                f.write("  data refs: %s\n" % short_list(rec["data_refs"]))
            for e in rec["entries"]:
                f.write('  [%2d]  %s  "%s"%s\n' % (e["index"], e["pointer_at"], clean(e["text"], 80),
                                                  ("   " + "  ".join(e["fields"])) if e["fields"] else ""))
            f.write("\n")
    stats["String pointers found"] = len(hits)
    stats["String tables"] = len(tables)
    stats["String tables LIKELY ENUM"] = likely


def dump_compare_chains(folder):
    monitor.setMessage("Dump: compare chains")
    rows = []
    for k, info in func_info.items():
        level = compare_level(k)
        if not level:
            continue
        seen, items = set(), []
        for ins_addr, text, raw in info["strings"]:
            if text not in seen:
                seen.add(text)
                items.append((ins_addr, text, raw))
        if len(items) >= 3:
            try:
                order = int(k, 16)
            except ValueError:
                order = 0
            rows.append((order, k, info["name"], level, items))
    rows.sort(key=lambda r: r[0])
    with out(folder, "10_compare_chains.txt") as f:
        f.write("Functions that compare strings and use 3+ strings: if/else enum parsers are often here.\n")
        f.write("Strings are listed in code order. Confirm values in 13_function_dump.txt.\n\n")
        for _, k, name, level, items in rows:
            f.write("FUNCTION %s @ %s   compares: %s   strings: %d\n" % (name, k, level, len(items)))
            for i, (ins_addr, text, raw) in enumerate(items):
                f.write('  [%2d]  %s  "%s"%s\n' % (i, ins_addr, clean(text, 80), "  (raw)" if raw else ""))
            f.write("\n")
    stats["Compare-chain functions"] = len(rows)


# ---------------------------------------------------------------- data types
def dump_datatypes(folder):
    monitor.setMessage("Dump: data types")
    structs, unions, enums = [], [], []
    for dt in jiter(dtm.getAllDataTypes()):
        check()
        if isinstance(dt, Enum):
            enums.append(dt)
        elif isinstance(dt, Structure):
            structs.append(dt)
        elif isinstance(dt, Union):
            unions.append(dt)
    key = lambda d: str(d.getPathName())

    with out(folder, "11_structures.txt") as f:
        for dt in sorted(structs, key=key):
            comps = list(dt.getDefinedComponents())
            f.write("STRUCT %s   size 0x%x   fields %d\n" % (dt.getPathName(), dt.getLength(), len(comps)))
            for c in comps:
                fname = c.getFieldName() or c.getDefaultFieldName()
                comment = ("   // " + clean(c.getComment(), 120)) if c.getComment() else ""
                f.write("  +0x%04x  %4d  %-30s %s%s\n" % (c.getOffset(), c.getLength(),
                                                          c.getDataType().getDisplayName(), fname, comment))
            f.write("\n")
        for dt in sorted(unions, key=key):
            f.write("UNION %s   size 0x%x\n" % (dt.getPathName(), dt.getLength()))
            for c in dt.getComponents():
                fname = c.getFieldName() or c.getDefaultFieldName()
                f.write("  %4d  %-30s %s\n" % (c.getLength(), c.getDataType().getDisplayName(), fname))
            f.write("\n")

    with out(folder, "12_enums.txt") as f:
        for dt in sorted(enums, key=key):
            f.write("ENUM %s   size %d\n" % (dt.getPathName(), dt.getLength()))
            for v, n in sorted(((dt.getValue(n), str(n)) for n in dt.getNames()), key=lambda p: p[0]):
                f.write("  %-40s = %d (0x%x)\n" % (n, v, v & 0xFFFFFFFFFFFFFFFF))
            f.write("\n")
    stats["Structures"] = len(structs)
    stats["Unions"] = len(unions)
    stats["Enums (Ghidra types)"] = len(enums)


# ---------------------------------------------------------------- per-function dump
def function_header(fn, k, info, table_by_id):
    callers = sorted(set(str(c.getName(True)) for c in callers_cache.get(k, [])))
    callees = sorted(set(str(c.getName(True)) for c in callees_cache.get(k, [])))
    h = ["// " + "=" * 76,
         "// FUNCTION:  %s" % fn.getName(True),
         "// ENTRY:     %s   SIZE: %d bytes   NAME SOURCE: %s" % (
             k, fn.getBody().getNumAddresses(), fn.getSymbol().getSource()),
         "// CALLED BY (%d): %s" % (len(callers), short_list(callers)),
         "// CALLS (%d): %s" % (len(callees), short_list(callees, 25))]
    level = compare_level(k)
    if level:
        h.append("// COMPARES STRINGS: %s" % level)
    if info["strings"]:
        h.append("// STRINGS (%d):" % len(info["strings"]))
        for ins_addr, text, raw in info["strings"][:MAX_FUNC_STRINGS]:
            h.append('//   %s  "%s"%s' % (ins_addr, clean(text, 100), "  (raw)" if raw else ""))
        if len(info["strings"]) > MAX_FUNC_STRINGS:
            h.append("//   (+%d more)" % (len(info["strings"]) - MAX_FUNC_STRINGS))
    if info["data"]:
        h.append("// DATA (%d):" % len(info["data"]))
        for t, (r, w, a) in info["data"].items():
            s = data_index[t].get("summary", {})
            h.append("//   %s  %-28s [%s %s]  %s  (here: R%d W%d A%d)" % (
                t, s.get("symbol", "?"), s.get("block", "?"), s.get("section", "?"),
                clean(s.get("value", ""), 120), r, w, a))
    for tid in func_tables.get(k, []):
        t = table_by_id[tid]
        preview = ", ".join('"%s"' % clean(e["text"], 30) for e in t["entries"][:6])
        h.append("// STRING TABLE #%d @ %s (%d entries, %s): %s%s" % (
            tid, t["start"], len(t["entries"]), t["verdict"], preview,
            " ..." if len(t["entries"]) > 6 else ""))
    h.append("// " + "=" * 76)
    return "\n".join(h)


def dump_function_evidence(folder):
    funcs = [f for f in jiter(fm.getFunctions(True)) if not f.isThunk()]

    def sort_key(fn):
        ns = str(fn.getParentNamespace().getName(True))
        return (1 if ns == "Global" else 0, ns, fn.getEntryPoint().getOffset())

    funcs.sort(key=sort_key)
    table_by_id = {t["id"]: t for t in tables}
    decomp = open_decompiler() if DECOMPILE_ALL else None
    human = out(folder, "13_function_dump.txt")
    ai = out(folder, "13_function_dump - AI.txt") if decomp is not None else None
    ok = failed = 0
    failed_rows = []
    started = time.time()
    try:
        current_ns = None
        for i, fn in enumerate(funcs):
            check()
            if i % 25 == 0:
                monitor.setMessage("Function dump %d/%d" % (i + 1, len(funcs)))
            if i and i % 250 == 0:
                print("    function dump %d/%d (%.0f s)" % (i, len(funcs), time.time() - started))

            k = fkey(fn)
            code_human = code_ai = ""
            if decomp is not None:
                res = decomp.decompileFunction(fn, DECOMPILE_TIMEOUT, monitor)
                if res is not None and res.decompileCompleted() and res.getDecompiledFunction():
                    c = res.getDecompiledFunction().getC()
                    code_human = clean_c(c, keep_comments=True)
                    code_ai = clean_c(c, keep_comments=AI_KEEP_WARNINGS)
                    ok += 1
                else:
                    msg = res.getErrorMessage() if res is not None else "no result"
                    code_human = "// [decompile failed: %s]" % clean(msg, 200)
                    failed += 1
                    failed_rows.append((k, str(fn.getName(True)), clean(msg, 200)))

            # human file: namespace line + evidence header + code with comments
            ns = str(fn.getParentNamespace().getName(True))
            if ns != current_ns:
                current_ns = ns
                human.write("\n// NAMESPACE: %s\n" % ns)
            info = func_info.get(k, {"strings": [], "data": {}})
            human.write(function_header(fn, k, info, table_by_id) + "\n")
            human.write((code_human + "\n\n") if code_human else "\n")

            # AI file: code only (failed decompiles are skipped)
            if ai is not None and code_ai:
                if AI_ADDRESS_LINE:
                    ai.write("// %s\n" % k)
                ai.write(code_ai + "\n\n")
    finally:
        human.close()
        if ai is not None:
            ai.close()
        if decomp is not None:
            decomp.dispose()
    stats_c["Functions in dump (thunks skipped)"] = len(funcs)
    if DECOMPILE_ALL:
        stats_c["Decompiled OK"] = ok
        stats_c["Decompile failed (assembly only)"] = failed
        with out(folder, "decompile_failed.txt") as ff:
            ff.write("Functions with NO decompiled C. Use the assembly (same ENTRY address) for these.\n")
            ff.write("ENTRY\tNAME\tREASON\n")
            for k, name, msg in failed_rows:
                ff.write("%s\t%s\t%s\n" % (k, name, msg))


# ---------------------------------------------------------------- assembly dump
def dump_assembly(folder):
    """Every defined instruction in address order, grouped by function.
    Same line format as the old SIM_Assembly_Dump.py, so existing parsers still work."""
    monitor.setMessage("Dump: assembly")
    count = outside = groups = 0
    previous = None
    cancelled = False
    instructions = listing.getInstructions(True)
    f = out(folder, ASM_FILENAME)
    try:
        f.write("# PROGRAM: %s\n# IMAGE BASE: %s\n# LANGUAGE: %s\n" % (
            prog.getName(), prog.getImageBase(), prog.getLanguageID()))
        f.write("# Defined instructions only; address order; function headings are not class boundaries.\n")
        f.write("# ADDRESS             INSTRUCTION\n")
        try:
            while instructions.hasNext():
                check()
                ins = instructions.next()
                address = ins.getAddress()
                fn = fm.getFunctionContaining(address)
                group = str(fn.getEntryPoint()) if fn is not None else "<unassigned>"
                if group != previous:
                    if fn is None:
                        f.write("\n# OUTSIDE KNOWN FUNCTIONS\n")
                    else:
                        f.write("\n# FUNCTION: %s | ENTRY: %s\n" % (fn.getName(True), fn.getEntryPoint()))
                        groups += 1
                    previous = group
                f.write("%-20s %s\n" % (address, ins))
                count += 1
                if fn is None:
                    outside += 1
                if count % 4096 == 0:
                    monitor.setMessage("Assembly: %d instructions" % count)
        except Cancelled:
            cancelled = True
        f.write("\n# STATUS: %s | INSTRUCTIONS: %d\n" % (
            "CANCELLED / INCOMPLETE" if cancelled else "COMPLETE", count))
    finally:
        f.close()
    stats_asm["Assembly instructions"] = count
    stats_asm["Function sections in the assembly dump"] = groups
    stats_asm["Instructions outside known functions"] = outside
    if cancelled:
        raise Cancelled()


# ---------------------------------------------------------------- json + summary
def write_json(folder):
    monitor.setMessage("Writing JSON index")
    index = {
        "program": str(prog.getName()),
        "md5": str(prog.getExecutableMD5()),
        "image_base": str(prog.getImageBase()),
        "string_tables": tables,
        "data": sorted((rec["summary"] for rec in data_index.values() if "summary" in rec),
                       key=lambda s: int(s["address"], 16)),
    }
    with out(folder, "dump_index.json") as f:
        json.dump(index, f, indent=1)


def token_rows(folder=None):
    rows = []
    for fdir, name in sorted(written_files, key=lambda x: (x[0], x[1])):
        if name == "00_summary.txt" or (folder is not None and fdir != folder):
            continue
        path = os.path.join(fdir, name)
        if not os.path.isfile(path):
            continue
        with open(path, encoding="utf-8", errors="replace", newline="") as f:
            text = f.read()
        chars = len(text)
        label = name if folder is not None else os.path.join(os.path.basename(fdir), name)
        rows.append((label, chars, text.count("\n"), int(math.ceil(chars / CHARS_PER_TOKEN))))
    return rows


def format_token_table(rows):
    width = max([30] + [len(r[0]) for r in rows])
    lines = ["FILE SIZES AND TOKEN ESTIMATES",
             "  Estimate: 1 token per %.1f characters. Real counts vary by model and content."
             % CHARS_PER_TOKEN,
             "  %-*s %12s %10s %12s" % (width, "FILE", "CHARS", "LINES", "EST.TOKENS")]
    for name, chars, nlines, tokens in rows:
        lines.append("  %-*s %12s %10s %12s" % (width, name, "{:,}".format(chars), "{:,}".format(nlines),
                                                 "~{:,}".format(tokens)))
    return lines


def program_lines(seconds, cancelled):
    lines = []
    if cancelled:
        lines.append("*** CANCELLED - PARTIAL DUMP ***")
    lines += ["Program:       %s" % prog.getName(),
              "Original file: %s" % prog.getExecutablePath(),
              "MD5:           %s" % prog.getExecutableMD5(),
              "Language:      %s" % prog.getLanguageID(),
              "Compiler:      %s" % prog.getCompilerSpec().getCompilerSpecID(),
              "Image base:    %s" % prog.getImageBase(),
              "Dumped:        %s  (%.1f s)" % (time.strftime("%Y-%m-%d %H:%M:%S"), seconds), ""]
    return lines


def stat_lines(d):
    return ["%-44s %d" % (k, v) for k, v in d.items()]


def write_summaries(seconds, cancelled):
    base = os.path.basename(dirs["asm"])[:-len("_ASSEMBLY")]
    sister = ("Sister folders (same function addresses link them):\n"
              "  %s_ASSEMBLY      ground truth: every instruction\n"
              "  %s_C_PSEUDOCODE  Ghidra's decompiled C (can be wrong or incomplete)\n"
              "  %s_INVENTORY     facts about the whole program, plus the master summary\n" % (base, base, base))

    with out(dirs["asm"], "00_summary.txt") as f:
        f.write("ASSEMBLY DUMP\n=============\n")
        f.write("\n".join(program_lines(seconds, cancelled)) + "\n")
        f.write("\n".join(stat_lines(stats_asm)) + "\n\nFILES\n")
        f.write("  %s  every defined instruction in address order, grouped by function\n" % ASM_FILENAME)
        f.write("\n" + "\n".join(format_token_table(token_rows(dirs["asm"]))) + "\n\nNOTES\n")
        f.write("  - This is the ground truth: nothing Ghidra could disassemble is left out.\n")
        f.write("  - Function headings are Ghidra's guesses at boundaries, not class boundaries.\n\n")
        f.write(sister)

    with out(dirs["c"], "00_summary.txt") as f:
        f.write("C PSEUDOCODE DUMP\n=================\n")
        f.write("\n".join(program_lines(seconds, cancelled)) + "\n")
        f.write("\n".join(stat_lines(stats_c)) + "\n\nFILES\n")
        f.write("  13_function_dump.txt        every function for humans: evidence header + code\n")
        f.write("  13_function_dump - AI.txt   code only, no whole-line comments\n")
        f.write("  decompile_failed.txt        functions with no C: use the assembly for these\n")
        f.write("\n" + "\n".join(format_token_table(token_rows(dirs["c"]))) + "\n\nNOTES\n")
        f.write("  - This is Ghidra's reading of the assembly. Variable types can be wrong and some\n")
        f.write("    code can be dropped or merged. When it disagrees with the assembly, trust the assembly.\n")
        f.write("  - The AI file removes whole-line comments only; inline comments are kept.\n\n")
        f.write(sister)

    with out(dirs["inv"], "00_summary.txt") as f:
        f.write("INVENTORY - MASTER SUMMARY%s\n=========================\n" % ("  (CANCELLED - PARTIAL)" if cancelled else ""))
        f.write("\n".join(program_lines(seconds, cancelled)) + "\n")
        f.write("INVENTORY\n" + "\n".join(stat_lines(stats)) + "\n\n")
        f.write("ASSEMBLY\n" + "\n".join(stat_lines(stats_asm)) + "\n\n")
        f.write("C PSEUDOCODE\n" + "\n".join(stat_lines(stats_c)) + "\n\nFILES IN THIS FOLDER\n")
        f.write("  01-06  inventory: memory, imports, exports, classes, functions, strings\n")
        f.write("  07      constants: read-only data used by code, typed by the instructions that use it\n")
        f.write("  08      variables: writable globals (.data values are INITIAL values only)\n")
        f.write("  09      string pointer tables (enum candidates) with consuming functions\n")
        f.write("  10      string compare chains (if/else enum parsers)\n")
        f.write("  11-12   structures and Ghidra enum types\n")
        f.write("  dump_index.json  tables and data in machine-readable form\n\n")
        f.write("OTHER FOLDERS\n  %s\n  %s\n" % (dirs["asm"], dirs["c"]))
        f.write("\n" + "\n".join(format_token_table(token_rows())) + "\n\nNOTES\n")
        f.write("  - !TYPE CONFLICT = same address used as different types; check before naming.\n")
        f.write("  - (raw) = string read from undefined bytes; nothing was created in the program.\n")
        f.write("  - Compare detection uses callee names containing 'cmp'; custom compare\n")
        f.write("    functions still named FUN_ are not detected.\n\n")
        f.write(sister)


def main():
    base = re.sub(r"[^\w.-]", "_", str(prog.getName()))
    dirs["asm"] = os.path.join(OUTPUT_ROOT, base + "_ASSEMBLY")
    dirs["c"] = os.path.join(OUTPUT_ROOT, base + "_C_PSEUDOCODE")
    dirs["inv"] = os.path.join(OUTPUT_ROOT, base + "_INVENTORY")
    for d in dirs.values():
        os.makedirs(d, exist_ok=True)
    inv, asm, cdir = dirs["inv"], dirs["asm"], dirs["c"]
    print("[*] Dumping %s to:\n    %s\n    %s\n    %s" % (prog.getName(), asm, cdir, inv))
    started = time.time()
    cancelled = False
    steps = [
        ("memory blocks",   lambda: dump_memory(inv)),
        ("imports",         lambda: dump_imports(inv)),
        ("exports",         lambda: dump_exports(inv)),
        ("classes",         lambda: dump_classes(inv)),
        ("call graph",      build_call_cache),
        ("function list",   lambda: dump_function_list(inv)),
        ("strings",         lambda: dump_strings(inv)),
        ("code scan",       scan_instructions),
        ("data",            lambda: dump_data(inv)),
        ("string tables",   lambda: scan_string_tables(inv)),
        ("compare chains",  lambda: dump_compare_chains(inv)),
        ("data types",      lambda: dump_datatypes(inv)),
        ("json index",      lambda: write_json(inv)),
        ("assembly",        lambda: dump_assembly(asm)),
        ("function dump",   lambda: dump_function_evidence(cdir)),
    ]
    try:
        for name, step in steps:
            t0 = time.time()
            step()
            print("[+] %-16s %.1f s" % (name, time.time() - t0))
    except Cancelled:
        cancelled = True
        print("[!] Cancelled. Partial dump written.")
    seconds = time.time() - started
    write_summaries(seconds, cancelled)
    print("\n[*] Summary:")
    for d in (stats, stats_asm, stats_c):
        for k, v in d.items():
            print("    %-44s %d" % (k, v))
    for line in format_token_table(token_rows()):
        print("    " + line)
    print("[*] Done in %.1f s." % seconds)


main()
