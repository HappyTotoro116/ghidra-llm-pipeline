# Copyright 2026 Ryu116
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

r"""triage_evidence_v2.py - first-pass TRIAGE of the groups: KEEP? / REPLACE? / UNKNOWN (read-only).

Reads the LITE_AC folder made by make_full_lite.py (group folders with one .txt per function) and,
optionally, 02_imports.txt from the INVENTORY folder (so Windows API calls can be recognised).
Writes two files into OUT\TRIAGE (a new folder next to the LITE folder, or --report-dir):
  TRIAGE.tsv          one line per group: counts + first-guess verdict + reasons (edit the VERDICT column later)
  TRIAGE_REPORT.txt   summary table first, then the evidence per group
Every verdict ends with "?" because it is a guess from simple rules. You make the final call.

Usage (PowerShell), full paths:
  python "D:\...\triage_evidence.py" --lite "D:\...\OUT\LITE_AC" --imports "D:\...\il2fb.exe_INVENTORY\02_imports.txt"
Terminal already in the folder with OUT (cd):
  python .\triage_evidence.py --lite .\OUT\LITE_AC --imports "<path to>\02_imports.txt"

Options: --report-dir FOLDER, --runtime-prefixes "RTS_,SFS_,nh_" (name starts that mean runtime / file handling)."""
import argparse, os, re, sys
from collections import Counter, defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--lite", required=True, help="the LITE_AC folder (group folders inside)")
ap.add_argument("--imports", default=None, help="02_imports.txt from the INVENTORY folder (recommended)")
ap.add_argument("--report-dir", default=None, help="default: the folder that contains the LITE folder")
ap.add_argument("--overrides", default=None, help="v2: OVERRIDES.tsv (ENTRY<TAB>LABEL<TAB>NOTE): labels you decided by hand; default: OVERRIDES.tsv next to the script or in the report folder")
ap.add_argument("--runtime-prefixes", default="RTS_,SFS_,nh_",
                help="comma list of function-name starts that mean runtime / file handling")
ap.add_argument("--crt-start", default="411000", help="v2: hex address where the C runtime zone starts; functions at/after it with no game strings do not inherit KEEP/WRAP (0 = off)")
a = ap.parse_args()

if not os.path.isdir(a.lite):
    sys.exit("LITE folder not found: " + a.lite)
REPORT_DIR = a.report_dir or os.path.join(os.path.dirname(os.path.abspath(a.lite)), "TRIAGE")
os.makedirs(REPORT_DIR, exist_ok=True)

UNNAMED = re.compile(r"^(FUN_|thunk_FUN_|LAB_|SUB_|Catch_|Catch@|Unwind@|switchD_)")
HELPER = re.compile(r"^(thunk_|Catch_|Catch@|Unwind@)")
# v2: C runtime (statically linked MSVC CRT) evidence: leading-underscore names that are not Java_ glue, and CRT-only strings
CRT_STRINGS = ("Microsoft Visual C++ Runtime Library", "__MSVCRT_HEAP_SELECT", "__GLOBAL_HEAP_SELECTED", "1#INF", "1#QNAN",
               "1#SNAN", "1#IND", "<program name unknown>", "GenuineIntel", "AuthenticAMD",
               "IsProcessorFeaturePresent", "MessageBoxA")


FILE_APIS = {"CreateFileA", "CreateFileW", "ReadFile", "WriteFile", "SetFilePointer", "MapViewOfFile",
             "UnmapViewOfFile", "CreateFileMappingA", "CreateFileMappingW", "GetFileSize"}


LABEL_STR = re.compile(r"\bs_([A-Za-z0-9_]{4,70}?)_[0-9a-fA-F]{8}\b")
CRT_PHRASES = ("runtime error", "R60", "TLOSS", "DOMAIN error", "SING error", "abnormal program termination",
               "Assertion failed", "floating point", "not enough space", "CorExitProcess", "mscoree")


def _norm(x):
    return re.sub(r"[^A-Za-z0-9]", "", x).lower()


_CRT_NORM = [_norm(c) for c in CRT_STRINGS + CRT_PHRASES]


def is_crt_str(x):
    n = _norm(x)
    return any(c and c in n for c in _CRT_NORM)


def label_strings(code):
    """Ghidra names string data like s__s_bin_java_dll_00420cd4 -> '_s bin java dll' (text only, not exact)."""
    return [m.strip().replace("_", " ").strip() for m in LABEL_STR.findall(code)]


def is_crt_name(n):
    return n.startswith("_") and not n.startswith("_Java_") and not UNNAMED.match(n) and "::" not in n


def clean(n):
    """_Java_x@12 -> Java_x ; _malloc -> malloc"""
    return re.sub(r"@\w+$", "", n[1:] if n.startswith("_") else n)

HDR = re.compile(r"^// FUNCTION:\s+(\S+)\s+ENTRY:\s+([0-9A-Fa-f]{8})")
PAIRS = re.compile(r"\b([0-9a-fA-F]{8})=([^,\s]+)")
STR = re.compile(r'"([^"\\\n]{4,60})"')
OS_LIBS = {"kernel32", "user32", "gdi32", "advapi32", "shell32", "ole32", "oleaut32", "comdlg32",
           "comctl32", "shlwapi", "version", "msvcrt", "ntdll"}
PREFIXES = tuple(p.strip() for p in a.runtime_prefixes.split(",") if p.strip())


def natural(t):
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", t)]


def read(p):
    with open(p, encoding="utf-8", errors="replace") as f:
        return f.read()


# ---- imports: name -> library (lower case, no .dll)
imports = {}
if not a.imports:                      # v2: look for 02_imports.txt next to the script or in the current folder
    for _d in (os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        _p = os.path.join(_d, "02_imports.txt")
        if os.path.isfile(_p):
            a.imports = _p
            break
if a.imports:
    if not os.path.isfile(a.imports):
        sys.exit("imports file not found: " + a.imports)
    for ln in read(a.imports).split("\n"):
        p = ln.rstrip("\r").split("\t")
        if len(p) >= 2 and p[0] != "LIBRARY":
            lib = p[0].split("::")[-1].strip().lower()
            lib = lib[:-4] if lib.endswith(".dll") else lib
            imports.setdefault(p[1].strip(), lib)
else:
    print("NOTE: no --imports file given, so Windows API calls will not be recognised.")

# ---- parse every function file
funcs = []                      # one dict per function
entry_group = {}
groups = sorted([d for d in os.listdir(a.lite) if os.path.isdir(os.path.join(a.lite, d))], key=natural)
if not groups:
    sys.exit("No group folders inside: " + a.lite)
for g in groups:
    gdir = os.path.join(a.lite, g)
    for fn in sorted(os.listdir(gdir), key=natural):
        if not fn.lower().endswith(".txt") or fn.startswith("_"):
            continue
        text = read(os.path.join(gdir, fn))
        m = HDR.search(text)
        if not m:
            continue
        name, entry = m.group(1), m.group(2).lower()
        calls, callers = [], []
        for ln in text.split("\n"):
            if ln.startswith("// CALLS:"):
                calls = [(x.lower(), y) for x, y in PAIRS.findall(ln)]
            elif ln.startswith("// CALLED BY:"):
                callers = [(x.lower(), y) for x, y in PAIRS.findall(ln)]
        k = text.find("\n[")
        body = text[k:] if k >= 0 else text
        c_at = body.find("[C PSEUDOCODE]")
        c_part = body[c_at:] if c_at >= 0 else ""
        tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", body))
        used = sorted(t for t in tokens if t in imports)
        funcs.append({"group": g, "name": name, "entry": entry, "calls": calls, "callers": callers,
                      "imports": used, "strings": list(dict.fromkeys(STR.findall(c_part) + label_strings(c_part))),
                      "named": not UNNAMED.match(clean(name)) and not UNNAMED.match(name), "jni": clean(name).startswith("Java_"),
                      "runtime": clean(name).startswith(PREFIXES) if PREFIXES else False,
                      "helper": bool(HELPER.match(name))})
        entry_group[entry] = g

# ---- per group evidence + first-guess verdict
by_group = defaultdict(list)
for f in funcs:
    by_group[f["group"]].append(f)

info = {}
for g in groups:
    fs = by_group.get(g, [])
    n = len(fs)
    named = [f for f in fs if f["named"]]
    lib_funcs = Counter()
    imp_count = Counter()
    n_os = n_other = 0
    for f in fs:
        libs = {imports[i] for i in f["imports"]}
        for lb in libs:
            lib_funcs[lb] += 1
        for i in f["imports"]:
            imp_count[i] += 1
        if libs & OS_LIBS:
            n_os += 1
        if libs - OS_LIBS:
            n_other += 1
    n_jni = sum(1 for f in fs if f["jni"])
    n_rt = sum(1 for f in fs if f["runtime"])
    n_help = sum(1 for f in fs if f["helper"])
    n_crt = sum(1 for f in fs if is_crt_name(f["name"]) or f["name"] == "entry")
    crt_str = [x for f in fs for x in f["strings"] if is_crt_str(x)]
    reasons = []
    if n_jni and n_jni * 2 >= n:
        verdict = "KEEP? (Java glue)"
        reasons.append("%d of %d functions named Java_..." % (n_jni, n))
    elif n_jni:
        verdict = "MIXED? (Java glue + helpers)"
        reasons.append("%d of %d functions named Java_..., the rest are helpers: check inside" % (n_jni, n))
    elif named and n_rt * 2 >= len(named):
        verdict = "REPLACE? (runtime names)"
        reasons.append("%d of %d named functions start with %s" % (n_rt, len(named), "/".join(PREFIXES)))
    elif n_crt or crt_str:
        if n > 30:
            verdict = "MIXED? (C runtime + other code)"
            reasons.append("%d runtime-looking names, but %d functions: check inside" % (n_crt, n))
        else:
            verdict = "REPLACE? (C runtime)"
            reasons.append("%d CRT-style names%s" % (n_crt, "; CRT strings: " + ", ".join(sorted(set(crt_str))[:3]) if crt_str else ""))
    elif n and n_help == n:
        verdict = "REPLACE? (thunks/catch only)"
        reasons.append("every function is a thunk or catch block")
    elif n and imports and n_os * 2 >= n and n_other == 0:
        verdict = "REPLACE? (mostly OS calls)"
        reasons.append("%d of %d functions call Windows/CRT APIs, none call media/other libraries" % (n_os, n))
    else:
        verdict = "UNKNOWN"
        reasons.append("no strong evidence from names or imports")
    if n_other:
        reasons.append("%d function(s) call other libraries: %s" % (
            n_other, ", ".join(lb for lb in lib_funcs if lb not in OS_LIBS)))
    links = Counter()
    for f in fs:
        for ad, _ in f["calls"] + f["callers"]:
            og = entry_group.get(ad)
            if og and og != g:
                links[og] += 1
    info[g] = {"n": n, "named": len(named), "jni": n_jni, "rt": n_rt, "os": n_os, "other": n_other,
               "verdict": verdict, "reasons": "; ".join(reasons), "libs": lib_funcs, "imps": imp_count,
               "links": links, "fs": fs}

# ---- v2: second pass - an UNKNOWN group whose call links go (70%+) to REPLACE? groups is runtime plumbing too
for _ in range(3):
    for g in groups:
        i = info[g]
        if i["verdict"].startswith("UNKNOWN") and i["jni"] == 0 and i["links"]:
            tot = sum(i["links"].values())
            rt = sum(c for og, c in i["links"].items() if info[og]["verdict"].startswith("REPLACE?"))
            if rt * 10 >= tot * 7:
                i["verdict"] = "REPLACE? (linked to runtime groups)"
                i["reasons"] = "%d of %d call links go to groups already marked REPLACE?" % (rt, tot)

# ---- TRIAGE.tsv
tsv = os.path.join(REPORT_DIR, "TRIAGE.tsv")
with open(tsv, "w", encoding="utf-8", newline="\n") as f:
    f.write("GROUP\tFUNCS\tNAMED\tJNI\tRUNTIME_NAMES\tOS_IMPORT_FUNCS\tOTHER_IMPORT_FUNCS\tVERDICT\tREASONS\n")
    for g in groups:
        i = info[g]
        f.write("%s\t%d\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (
            g, i["n"], i["named"], i["jni"], i["rt"], i["os"], i["other"], i["verdict"], i["reasons"]))

# ---- TRIAGE_REPORT.txt
cnt = Counter(info[g]["verdict"].split(" ")[0] for g in groups)
out = ["TRIAGE REPORT - first guess from simple rules (every verdict is a guess; you decide)",
       "LITE folder: " + a.lite,
       "Imports file: " + (a.imports or "(none)"),
       "Groups: %d   KEEP? %d   REPLACE? %d   UNKNOWN %d   functions: %d" % (
           len(groups), cnt["KEEP?"], cnt["REPLACE?"], cnt["UNKNOWN"] + cnt["MIXED?"], len(funcs)),
       "",
       "SUMMARY",
       "%-24s %5s %5s %4s %5s %6s %6s  %s" % ("GROUP", "FUNCS", "NAMED", "JNI", "RUNT", "OS-API", "OTHER", "VERDICT"),
       "-" * 90]
for g in groups:
    i = info[g]
    out.append("%-24s %5d %5d %4d %5d %6d %6d  %s" % (
        g, i["n"], i["named"], i["jni"], i["rt"], i["os"], i["other"], i["verdict"]))
out += ["", "Columns: NAMED = not FUN_/thunk/Catch names | JNI = Java_ names | RUNT = runtime-prefix names",
        "OS-API = functions calling Windows/CRT APIs | OTHER = functions calling other libraries (media, network...)",
        "", "=" * 90, "DETAILS PER GROUP", "=" * 90]
for g in groups:
    i = info[g]
    out.append("")
    out.append("%s   ->   %s" % (g, i["verdict"]))
    out.append("  why:      " + i["reasons"])
    if i["libs"]:
        out.append("  libraries (functions using each): " + ", ".join("%s x%d" % kv for kv in i["libs"].most_common(8)))
    if i["imps"]:
        out.append("  top API calls: " + ", ".join("%s x%d" % kv for kv in i["imps"].most_common(8)))
    nm = [f["name"] for f in i["fs"] if f["named"]]
    out.append("  named (%d): %s" % (len(nm), ", ".join(nm[:12]) + (" ... (+%d)" % (len(nm) - 12) if len(nm) > 12 else "")))
    out.append("  unnamed functions: %d" % (i["n"] - len(nm)))
    st = list(dict.fromkeys(s for f in i["fs"] for s in f["strings"]))
    if st:
        out.append("  strings: " + " | ".join('"%s"' % s for s in st[:8]) + (" ..." if len(st) > 8 else ""))
    if i["links"]:
        out.append("  linked groups (call links): " + ", ".join(
            "%s [%s] x%d" % (og, info[og]["verdict"].split(" ")[0], c) for og, c in i["links"].most_common(6)))
rp = os.path.join(REPORT_DIR, "TRIAGE_REPORT.txt")
with open(rp, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out) + "\n")

print("\n".join(out[3:4]))
print("Wrote " + tsv)
print("Wrote " + rp)

# ======================================================================================
# v2: PER-FUNCTION triage -> FUNCTIONS.tsv + FUNCTIONS_SUMMARY.txt   (labels WRAP / KEEP / REPLACE / UNKNOWN)
#   WRAP    = Java-facing glue (or its helper) that calls Windows / DirectInput / winmm APIs: keep the Java signature, new body
#   KEEP    = game code with its own logic (JNI glue with no OS call, exported SFS_ API, helpers of those)
#   REPLACE = C runtime, allocator, thunks, import stubs, helpers called only by runtime
#   UNKNOWN = has its own strings or is shared by runtime and game code: look at it by hand
# Every label is a guess from names, imports, strings and call links (inferred, not proven).
# ======================================================================================
def _game_strings(f):
    return [s for s in f["strings"] if not is_crt_str(s) and re.search(r"[A-Za-z]{4}", s)]


byentry = {f["entry"]: f for f in funcs}
label, why = {}, {}


def setl(f, lab, w):
    label[f["entry"]] = lab
    why[f["entry"]] = w


# v2: labels decided by hand win over every rule (and their helpers then follow through the call links)
overrides = {}
CRT_START = int(a.crt_start, 16)
_ov = a.overrides
if not _ov:
    for _d in (REPORT_DIR, os.path.dirname(os.path.abspath(__file__)), os.getcwd()):
        _p = os.path.join(_d, "OVERRIDES.tsv")
        if os.path.isfile(_p):
            _ov = _p
            break
if _ov and os.path.isfile(_ov):
    for _ln in read(_ov).split("\n"):
        _p = _ln.rstrip("\r").split("\t")
        if len(_p) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{8}", _p[0].strip()) and _p[1].strip().upper() in ("KEEP", "WRAP", "REPLACE", "UNKNOWN"):
            overrides[_p[0].strip().lower()] = (_p[1].strip().upper(), _p[2].strip() if len(_p) > 2 else "")
    print("Overrides: %d from %s" % (len(overrides), _ov))

for f in funcs:
    n, cn = f["name"], clean(f["name"])
    if f["entry"] in overrides:
        setl(f, overrides[f["entry"]][0], "override: " + overrides[f["entry"]][1])
    elif f["jni"]:
        apis = [i for i in f["imports"]]
        setl(f, "WRAP" if apis else "KEEP", ("JNI glue calling " + ", ".join(apis[:3])) if apis else "JNI glue, no OS API call")
    elif cn.startswith("RTS_"):
        setl(f, "REPLACE", "runtime allocator (RTS_*)")
    elif cn.startswith("SFS_"):
        setl(f, "KEEP", "exported SFS_ API: other DLLs may call it, keep the signature")
    elif n == "entry" or is_crt_name(n):
        setl(f, "REPLACE", "C runtime name")
    elif f["helper"]:
        setl(f, "REPLACE", "thunk / catch block")
    elif "::" in n or cn.startswith("operator_"):
        setl(f, "REPLACE", "import stub / C++ runtime")
    elif info[f["group"]]["verdict"].startswith("REPLACE?") and not any(i in FILE_APIS for i in f["imports"]) \
            and not _game_strings(f):
        setl(f, "REPLACE", "inside group: " + info[f["group"]]["verdict"])
for _ in range(40):
    changed = False
    for f in funcs:
        e = f["entry"]
        if e in label:
            continue
        cl = [label.get(c) for c, _ in f["callers"] if c in byentry and c != e]
        if not cl or None in cl:
            continue
        s = set(cl)
        if s == {"REPLACE"}:
            if _game_strings(f):            # own game strings and only runtime above it: launcher-like, look by hand
                setl(f, "UNKNOWN", "own strings, called only by runtime: " + " | ".join(_game_strings(f)[:2]))
            else:
                setl(f, "REPLACE", "called only by runtime functions")
        elif "REPLACE" in s:
            setl(f, "UNKNOWN", "shared: called by runtime and by game code")
        elif s <= {"KEEP", "WRAP"}:
            if CRT_START and int(e, 16) >= CRT_START and not _game_strings(f):
                setl(f, "REPLACE", "C runtime zone, no game strings (guard)")
                changed = True
                continue
            setl(f, "WRAP" if f["imports"] else "KEEP", "helper of Java glue")
        else:
            continue
        changed = True
    if not changed:
        break
# v2: shared helpers (called by runtime AND game code) - split them by what they do
for _ in range(10):
    changed = False
    for f in funcs:
        e = f["entry"]
        if label.get(e) != "UNKNOWN" or not why[e].startswith("shared:"):
            continue
        fa = [i for i in f["imports"] if i in FILE_APIS]
        cl = [label.get(c) for c, _ in f["calls"] if c in byentry and c != e]
        if fa:
            setl(f, "KEEP", "shared helper that uses file APIs (" + ", ".join(fa[:3]) + "): file layer")
            changed = True
        elif cl and set(cl) == {"REPLACE"} and not _game_strings(f):
            setl(f, "REPLACE", "shared helper that only calls runtime functions")
            changed = True
    if not changed:
        break
# v2: reachability - a function that no KEEP / WRAP function (or own-strings function) can reach is not used by game code
roots = [f["entry"] for f in funcs if label.get(f["entry"]) in ("KEEP", "WRAP")
         or (label.get(f["entry"]) == "UNKNOWN" and "own strings" in why[f["entry"]])
         or (f["entry"] not in label and _game_strings(f))]
seen, stack = set(roots), list(roots)
while stack:
    cur = stack.pop()
    for c, _ in byentry[cur]["calls"]:
        if c in byentry and c not in seen and label.get(c) != "REPLACE":
            seen.add(c)
            stack.append(c)
for f in funcs:
    if f["entry"] not in label and f["entry"] not in seen:
        setl(f, "REPLACE", "not reachable from any KEEP/WRAP function: runtime only")
for f in funcs:
    if f["entry"] not in label:
        gs = _game_strings(f)
        setl(f, "UNKNOWN", ("own strings: " + " | ".join(gs[:2])) if gs else "no strong evidence")

with open(os.path.join(REPORT_DIR, "FUNCTIONS.tsv"), "w", encoding="utf-8", newline="\n") as fo:
    fo.write("GROUP\tENTRY\tNAME\tLABEL\tREASON\n")
    for f in sorted(funcs, key=lambda x: (x["group"].lower(), x["entry"])):
        fo.write("%s\t%s\t%s\t%s\t%s\n" % (f["group"], f["entry"], f["name"], label[f["entry"]], why[f["entry"]]))
tot = Counter(label.values())
per = defaultdict(Counter)
for f in funcs:
    per[f["group"]][label[f["entry"]]] += 1
LAB = ("KEEP", "WRAP", "REPLACE", "UNKNOWN")
sm = ["PER-FUNCTION TRIAGE (guesses from names, imports, strings, call links)",
      "TOTAL  " + "   ".join("%s %d" % (x, tot[x]) for x in LAB) + "   functions %d" % len(funcs), "",
      "%-24s %5s %5s %5s %8s %8s" % ("GROUP", "KEEP", "WRAP", "REPL", "UNKNOWN", "FUNCS"), "-" * 62]
for g in groups:
    c = per[g]
    sm.append("%-24s %5d %5d %5d %8d %8d" % (g, c["KEEP"], c["WRAP"], c["REPLACE"], c["UNKNOWN"], sum(c.values())))
with open(os.path.join(REPORT_DIR, "FUNCTIONS_SUMMARY.txt"), "w", encoding="utf-8", newline="\n") as fo:
    fo.write("\n".join(sm) + "\n")
print(sm[1])
print("Wrote " + os.path.join(REPORT_DIR, "FUNCTIONS.tsv"))
print("Wrote " + os.path.join(REPORT_DIR, "FUNCTIONS_SUMMARY.txt"))
