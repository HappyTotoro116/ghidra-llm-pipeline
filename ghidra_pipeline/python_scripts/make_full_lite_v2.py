# Copyright 2026 Ryu116 (also known as HappyTotoro116)
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

#!/usr/bin/env python3
r"""
make_full_lite_v2.py - build FULL, LITE_AC, LITE_A and LITE_C class files from the Ghidra dumps.

Usage (PowerShell), in the folder with the dump files:
  python .\make_full_lite_v2.py --in . --out .\OUT
  python .\make_full_lite_v2.py --in . --out .\OUT --groups .\groups.tsv

Input folder needs:
  14_Assembly_dump.txt   13_function_dump.txt   04_classes.txt (empty is fine)
Optional --grouper-dir FOLDER: a folder tree with functions.tsv files that already group the functions (from another tool).
Optional --groups file: lines of  GroupName<TAB>ENTRY_ADDR  (no-RTTI games).

Grouping priority: --groups > 04_classes.txt (RTTI) > "Class::method" name >
SMS class / SMS prefix (if --sms) >
v2: Java class from _Java_<pkg>_<Class>_<method> names, C exports with the prefixes in C_PREFIX_GROUPS (edit for your game), entry >
v2: call graph (a function called only from ONE group joins that group; repeats until nothing changes) >
leftover shared helpers: old fallback (shared rare globals + address adjacency, capped by --max-group).

Output:
  FULL/<Class>.txt   whole class: header, then per function ASSEMBLY, then its C
  LITE_AC/<Class>/_class.h + <addr>_<name>.txt   comment header + [ASSEMBLY] + [C PSEUDOCODE]
  LITE_A/<Class>/...                             comment header + [ASSEMBLY] only
  LITE_C/<Class>/...                             comment header + [C PSEUDOCODE] only
  GLOBALS_SHARED.tsv   data addresses touched by 2+ groups, with the groups (and isolated functions) that touch them
  Report.txt
In every _class.h each address is labelled // GLOBAL (also used by another group) or // LOCAL (only this group).
All three LITE folders keep the same full header (FUNCTION / SIGNATURE / CALLS / CALLED BY / GLOBALS/DATA).
// CALLS also lists tail-jump targets (a JMP to another function entry).
"""
import argparse, os, re, sys
from collections import defaultdict

ASM_HDR = re.compile(r"^# FUNCTION: (.*?) \| ENTRY: ([0-9A-Fa-f]{8})\s*$")
ASM_LN = re.compile(r"^([0-9A-Fa-f]{8})\s+(\S+)\s*(.*)$")
C_HDR = re.compile(r"^// FUNCTION:\s+(.*?)\s*$")
C_ENTRY = re.compile(r"^// ENTRY:\s+([0-9A-Fa-f]{8})")
HEX8 = re.compile(r"0x([0-9A-Fa-f]{8})\b")
BRANCH = {"CALL", "JMP", "JE", "JNE", "JZ", "JNZ", "JA", "JAE", "JB", "JBE", "JG", "JGE",
          "JL", "JLE", "JS", "JNS", "JC", "JNC", "JO", "JNO", "JP", "JNP", "LOOP"}


def read(p):
    for enc in ("utf-8", "utf-16", "latin-1"):
        try:
            with open(p, encoding=enc) as f:
                return f.read()
        except (UnicodeError, OSError):
            continue
    return ""


def safe(s, n=60):
    return re.sub(r"[^\w.~-]+", "_", s)[:n].strip("_") or "x"


def est(s):
    return int(len(s) / 3.2)


def parse_asm(text):
    funcs, cur = {}, None
    for ln in text.split("\n"):
        m = ASM_HDR.match(ln)
        if m:
            cur = {"name": m.group(1), "lines": []}
            funcs[m.group(2).lower()] = cur
        elif cur is not None and ln.strip():
            cur["lines"].append(ln.rstrip())
    return funcs


def parse_c(text):
    lines = text.split("\n")
    starts = []
    for i, ln in enumerate(lines):
        if C_HDR.match(ln) and i >= 1 and lines[i - 1].startswith("// ===="):
            starts.append(i - 1)
    funcs = {}
    for n, s in enumerate(starts):
        e = starts[n + 1] if n + 1 < len(starts) else len(lines)
        blk = lines[s:e]
        while blk and (blk[-1].startswith("// NAMESPACE:") or not blk[-1].strip()):
            blk.pop()
        name, addr, hdr, k = "", "", [], 1
        eqs = 0
        for k, ln in enumerate(blk):
            if ln.startswith("// ===="):
                eqs += 1
                if eqs == 2:
                    break
            hdr.append(ln)
        code = "\n".join(blk[k + 1:]).strip("\n")
        data = []
        for ln in hdr:
            m = C_HDR.match(ln)
            if m:
                name = m.group(1)
            m = C_ENTRY.match(ln)
            if m:
                addr = m.group(1).lower()
            m = re.match(r"^//\s+([0-9A-Fa-f]{8})\s+(\S+)\s+(.*)$", ln)
            if m:
                data.append((m.group(1).lower(), m.group(2), m.group(3).strip()))
        ns = ""
        j = s - 1
        if j >= 0 and lines[j].startswith("// NAMESPACE:"):
            ns = lines[j].split(":", 1)[1].strip()
        if addr:
            funcs[addr] = {"name": name, "code": code, "data": data, "ns": ns,
                           "hdr": [h for h in hdr if h.startswith("// CALL")]}
    return funcs


def parse_classes(text):
    classes, cur = {}, None
    for ln in text.split("\n"):
        m = re.match(r"^CLASS (.+?)\s+\(methods: (\d+)\)", ln)
        if m:
            cur = {"labels": [], "methods": []}
            classes[m.group(1)] = cur
            continue
        if cur is None:
            continue
        m = re.match(r"^\s+\[Label\]\s+([0-9A-Fa-f]{8})\s+(.*)$", ln)
        if m:
            cur["labels"].append((m.group(1).lower(), m.group(2).strip()))
            continue
        m = re.match(r"^\s+([0-9A-Fa-f]{8})\s+(\S+)\s+(.*)$", ln)
        if m:
            cur["methods"].append((m.group(1).lower(), m.group(3).strip()))
    return classes


def parse_sms(text):
    """SMS dump (old 3 columns or new 8): ADDR, ORIGINAL, READABLE, KIND, CLASS, CONV, ARGBYTES, SIGNATURE."""
    sms = {}
    for ln in text.split("\n"):
        p = ln.rstrip("\r").split("\t")
        if len(p) >= 3 and re.fullmatch(r"[0-9A-Fa-f]{8}", p[0].strip()):
            p += [""] * (8 - len(p))
            sms[p[0].strip().lower()] = {"orig": p[1].strip(), "name": p[2].strip(), "kind": p[3].strip(),
                                         "cls": p[4].strip(), "conv": p[5].strip(), "arg": p[6].strip(),
                                         "sig": p[7].strip()}
    return sms


def sms_class(orig):
    """Class from an MSVC-mangled symbol: ?Create@CDirDraw@@QAE... -> CDirDraw."""
    if not orig.startswith("?"):
        return ""
    if orig.startswith("??"):
        rest = orig[4:] if orig[2:3] == "_" else orig[3:]
        scope = rest.split("@@", 1)[0] if "@@" in rest else ""
    else:
        m = re.match(r"^\?[^@]+@((?:[^@]+@)*)@", orig)
        scope = m.group(1).rstrip("@") if m else ""
    parts = [x for x in scope.split("@") if x and not x.startswith("?")]
    return "::".join(reversed(parts)) if parts else ""


def sms_prefix(readable):
    m = re.match(r"^([A-Za-z0-9]+)_", readable) or re.match(r"^([A-Z]{2,}?)(?=[A-Z][a-z])", readable)
    return m.group(1) if m and len(m.group(1)) >= 2 else ""


def load_groups(path):
    g = {}
    for ln in read(path).split("\n"):
        p = ln.strip().split("\t")
        if len(p) >= 2 and re.fullmatch(r"[0-9A-Fa-f]{8}", p[1].strip()):
            g[p[1].strip().lower()] = p[0].strip()
    return g


def load_grouper(root):
    g = {}
    for dp, _, fs in os.walk(root):
        if "functions.tsv" not in fs:
            continue
        name = os.path.basename(dp)
        rows = read(os.path.join(dp, "functions.tsv")).split("\n")[1:]
        for ln in rows:
            p = ln.split("\t")
            if len(p) >= 8 and re.fullmatch(r"[0-9A-Fa-f]{8}", p[0]):
                e = p[0].lower()
                if p[7] == "yes" or e not in g:
                    g[e] = name
    return g


def asm_refs(lines, entries):
    calls, indirect, data = [], 0, []
    own = ""
    for ln in lines:
        m0 = ASM_LN.match(ln)
        if m0:
            own = m0.group(1).lower()
            break
    for ln in lines:
        m = ASM_LN.match(ln)
        if not m:
            continue
        mn, ops = m.group(2).upper(), m.group(3)
        if mn in BRANCH:
            if mn == "CALL":
                t = HEX8.search(ops)
                if t and "[" not in ops:
                    calls.append(t.group(1).lower())
                else:
                    indirect += 1
            elif mn == "JMP":                       # tail jump: JMP straight to another function entry
                t = HEX8.search(ops)
                if t and "[" not in ops:
                    tt = t.group(1).lower()
                    if tt in entries and tt != own:
                        calls.append(tt)
            continue
        for t in HEX8.findall(ops):
            t = t.lower()
            if t not in entries and t not in data:
                data.append(t)
    return calls, indirect, data


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="inp", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--groups")
    ap.add_argument("--max-group", type=int, default=150, help="max functions per fallback group")
    ap.add_argument("--common", type=int, default=12, help="globals used by more functions than this are ignored")
    ap.add_argument("--sms", help="optional symbol dump (only for games that have one): names, classes, prefixes")
    ap.add_argument("--min-prefix", type=int, default=4, help="functions needed to make an SMS prefix group")
    ap.add_argument("--grouper-dir", help="folder tree with functions.tsv files that group the functions (optional)")
    a = ap.parse_args()

    asm = parse_asm(read(os.path.join(a.inp, "14_Assembly_dump.txt")))
    cf = parse_c(read(os.path.join(a.inp, "13_function_dump.txt")))
    classes = parse_classes(read(os.path.join(a.inp, "04_classes.txt")))
    manual = load_grouper(a.grouper_dir) if a.grouper_dir else {}
    if a.groups:
        manual.update(load_groups(a.groups))
    if not asm:
        sys.exit("No functions found in 14_Assembly_dump.txt")

    entries = set(asm) | set(cf)
    name_of = {}
    for e in entries:
        name_of[e] = (asm.get(e) or {}).get("name") or (cf.get(e) or {}).get("name") or "FUN_" + e
    cls_of = {}
    for cn, c in classes.items():
        for addr, _ in c["methods"]:
            cls_of.setdefault(addr, cn)
    data_name = {}
    sms = parse_sms(read(a.sms)) if a.sms else {}
    sms_cls, sms_pre = {}, {}
    if sms:
        cnt = defaultdict(int)
        for e in entries:
            if e in sms:
                orig, rd = sms[e]["orig"], sms[e]["name"]
                if re.match(r"^(FUN_|thunk_|LAB_|SUB_)", name_of[e]) and rd:
                    name_of[e] = rd
                c_ = sms[e]["cls"] or sms_class(orig)
                if c_:
                    sms_cls[e] = c_
                else:
                    pr = sms_prefix(rd)
                    if pr:
                        sms_pre[e] = pr
                        cnt[pr.lower()] += 1
        sms_pre = {e: pr for e, pr in sms_pre.items() if cnt[pr.lower()] >= a.min_prefix}
        for ad, v in sms.items():
            if ad not in entries and v["name"]:
                data_name.setdefault(ad, v["name"])
    for e, c in cf.items():
        for addr, nm, _ in c["data"]:
            data_name.setdefault(addr, nm)
    for cn, c in classes.items():
        for addr, lab in c["labels"]:
            data_name.setdefault(addr, cn + "::" + lab)

    group_of, how, how_of = {}, defaultdict(int), {}
    canon = {}
    for e in sorted(entries):
        if e in manual:
            g, h = manual[e], "groups.tsv"
        elif e in cls_of:
            g, h = cls_of[e], "RTTI class"
        elif e in sms_cls:
            g, h = sms_cls[e], "SMS class"
        else:
            nm = name_of[e]
            m = re.match(r"^((?:\w+::)*\w+)::[~\w]+", nm)
            if m:
                g, h = m.group(1), "name prefix"
            elif (cf.get(e) or {}).get("ns"):
                g, h = cf[e]["ns"], "name prefix"
            elif e in sms_pre:
                g, h = "SMS_" + sms_pre[e], "SMS prefix"
            else:
                g, h = "_UNGROUPED", "none"
        group_of[e] = canon.setdefault(safe(g, 80).lower(), safe(g, 80))   # Windows ignores case
        how_of[e] = h
        how[h] += 1

    callers = defaultdict(set)
    refs = {}
    for e in entries:
        calls, ind, data = asm_refs((asm.get(e) or {}).get("lines", []), entries)
        refs[e] = (calls, ind, data)
        for t in calls:
            callers[t].add(e)

    # ---- v2: name seeds, then call graph (exact facts from the assembly: who CALLs whom) ----
    # ---- EDIT FOR YOUR GAME ----
    # C_PREFIX_GROUPS: exported C functions that start with a prefix go to one group.
    #   example: GameLib_Open, GameLib_Close  ->  group "GameLib"
    #   leave it empty {} if the game has no such prefixes
    C_PREFIX_GROUPS = {"GameLib": "GameLib", "MemAlloc": "MemAlloc"}
    # MERGE: Java classes (from JNI names) that belong in one group.
    #   example: {"MyInputStream": "MyIO", "MyOutputStream": "MyIO"}
    MERGE = {}
    JNI_RX = re.compile(r"^_?Java_(?:[a-z][a-z0-9]*_)+([A-Z][A-Za-z0-9]*)_")
    CEXP_RX = re.compile(r"^_?(%s)_[A-Za-z]\w*?(?:@\d+)?$" % "|".join(map(re.escape, C_PREFIX_GROUPS))) if C_PREFIX_GROUPS else None

    def seed_group(nm):
        m = JNI_RX.match(nm)
        if m:
            return MERGE.get(m.group(1), m.group(1))
        m = CEXP_RX.match(nm) if CEXP_RX else None
        if m:
            return C_PREFIX_GROUPS[m.group(1)]
        return "Startup" if nm == "entry" else ""

    def claim(e, g, h):
        group_of[e] = canon.setdefault(safe(g, 80).lower(), safe(g, 80))
        how[how_of[e]] -= 1
        how_of[e] = h
        how[h] += 1

    for e in sorted(entries):
        if how_of[e] == "none":
            g_ = seed_group(name_of[e])
            if g_:
                claim(e, g_, "name (Java class / C export)")
    for _round in range(100):
        changed = False
        for e in sorted(entries):
            if how_of[e] != "none":
                continue
            cs = {c for c in callers.get(e, ()) if c != e}
            if cs:
                if all(how_of[c] != "none" for c in cs):
                    gs = {group_of[c] for c in cs}
                    if len(gs) == 1:
                        claim(e, gs.pop(), "call graph (one calling group)")
                        changed = True
            else:                                   # nobody calls it: use what it calls
                cs2 = {c for c in refs[e][0] if c != e and c in entries}
                if cs2 and all(how_of[c] != "none" for c in cs2):
                    gs = {group_of[c] for c in cs2}
                    if len(gs) == 1:
                        claim(e, gs.pop(), "call graph (called groups)")
                        changed = True
        if not changed:
            break

    # ---- fallback grouping for the leftovers (shared helpers) ----
    left = [e for e in sorted(entries) if how_of[e] == "none"]
    if left:
        par = {e: e for e in left}
        size = {e: 1 for e in left}

        def find(x):
            while par[x] != x:
                par[x] = par[par[x]]
                x = par[x]
            return x

        def union(x, y):
            x, y = find(x), find(y)
            if x == y or size[x] + size[y] > a.max_group:
                return False
            if x > y:
                x, y = y, x
            par[y] = x
            size[x] += size[y]
            return True

        users = defaultdict(list)
        for e in left:
            for d in refs[e][2]:
                users[d].append(e)
        for d, us in users.items():
            if 2 <= len(us) <= a.common:
                for u in us[1:]:
                    union(us[0], u)
        n_glob = len({find(e) for e in left})

        def last_addr(e):
            ls = (asm.get(e) or {}).get("lines", [])
            for ln in reversed(ls):
                m = ASM_LN.match(ln)
                if m:
                    return int(m.group(1), 16)
            return int(e, 16)

        for i in range(1, len(left)):
            prev, cur = left[i - 1], left[i]
            if size[find(cur)] == 1 and int(cur, 16) - last_addr(prev) <= 32:
                union(prev, cur)
        roots = defaultdict(list)
        for e in left:
            roots[find(e)].append(e)
        n = 0
        for r, ms in sorted(roots.items()):
            n += 1
            for e in ms:
                group_of[e] = "SHARED%03d_%s" % (n, ms[0])
                how_of[e] = "shared helper (globals+adjacency)"
        how["none"] = 0
        how["shared helper (globals+adjacency)"] = len(left)

    members = defaultdict(list)
    for e in sorted(entries):
        members[group_of[e]].append(e)

    # which groups touch each data address: 2+ groups = GLOBAL (shared), 1 group = LOCAL (private to that group)
    addr_groups = defaultdict(set)
    for e in entries:
        for d in refs[e][2]:
            addr_groups[d].add(group_of[e])
    group_size = {g_: len(m_) for g_, m_ in members.items()}

    full_dir = os.path.join(a.out, "FULL")
    os.makedirs(full_dir, exist_ok=True)
    MODES = ("ac", "a", "c")
    lite_dirs = {m: os.path.join(a.out, "LITE_" + m.upper()) for m in MODES}
    for d_ in lite_dirs.values():
        os.makedirs(d_, exist_ok=True)

    def fn_head(e):
        calls, ind, data = refs[e]
        out = ["// FUNCTION: %s  ENTRY: %s  CLASS: %s" % (name_of[e], e, group_of[e])]
        v = sms.get(e)
        if v and v["sig"]:
            out.append("// SIGNATURE: " + v["sig"])
        elif v and v["conv"]:
            out.append("// CONV: %s%s" % (v["conv"], ("  stack args: %s bytes" % v["arg"]) if v["arg"] else ""))
        cl = []
        for t in dict.fromkeys(calls):
            cl.append("%s=%s" % (t, name_of.get(t, "?")))
        out.append("// CALLS: " + (", ".join(cl) if cl else "(none)") +
                   ("  + %d indirect/virtual" % ind if ind else ""))
        cb = sorted(callers.get(e, []))
        out.append("// CALLED BY: " + (", ".join("%s=%s" % (t, name_of[t]) for t in cb[:25]) if cb else "(none direct; maybe via vtable)"))
        gl = ["%s=%s" % (d, data_name[d]) if d in data_name else d for d in data]
        out.append("// GLOBALS/DATA: " + (", ".join(gl[:40]) if gl else "(none)"))
        return "\n".join(out)

    def fn_body(e, mode="ac", with_head=True):
        a_ = asm.get(e)
        c_ = cf.get(e)
        parts = []
        if with_head:
            parts.append(fn_head(e))
        if "a" in mode:
            parts.append("[ASSEMBLY]")
            parts.append("\n".join(a_["lines"]) if a_ else "(no assembly found)")
        if "c" in mode:
            parts.append("[C PSEUDOCODE]")
            parts.append(c_["code"] if c_ and c_["code"] else "(no C: decompile failed or missing)")
        return "\n".join(parts)

    def class_header(g, ms):
        out = ["// CLASS: %s   functions: %d" % (g, len(ms))]
        c = classes.get(g)
        if c:
            out.append("// RTTI / vtable labels:")
            for addr, lab in c["labels"]:
                out.append("//   %s  %s" % (addr, lab))
        out.append("// Methods:")
        for e in ms:
            out.append("//   %s  %s" % (e, name_of[e]))
        gl = []
        for e in ms:
            for d in refs[e][2]:
                if d not in gl:
                    gl.append(d)
        gl.sort(key=lambda d: 0 if len(addr_groups[d]) >= 2 else 1)      # GLOBAL first, order kept inside
        out.append("// Globals/data touched by this class (union). GLOBAL = also touched by another group; LOCAL = only this group:")
        for d in gl[:300]:
            out.append("// %s  %s  %s" % ("GLOBAL" if len(addr_groups[d]) >= 2 else "LOCAL ", d, data_name.get(d, "")))
        return "\n".join(out)

    rep = []
    tf = 0
    tlm = {m: 0 for m in MODES}
    for g, ms in sorted(members.items()):
        hd = class_header(g, ms)
        full = [hd]
        for e in ms:
            full.append("\n" + "=" * 70 + "\n" + fn_body(e))
        ft = "\n".join(full) + "\n"
        with open(os.path.join(full_dir, g + ".txt"), "w", encoding="utf-8") as f:
            f.write(ft)
        lt_g = {}
        for m_ in MODES:
            d = os.path.join(lite_dirs[m_], g)
            os.makedirs(d, exist_ok=True)
            with open(os.path.join(d, "_class.h"), "w", encoding="utf-8") as f:
                f.write(hd + "\n")
            lt = est(hd)
            for e in ms:
                body = fn_body(e, m_) + "\n"
                lt += est(body)
                with open(os.path.join(d, "%s_%s.txt" % (e, safe(name_of[e]))), "w", encoding="utf-8") as f:
                    f.write(body)
            tlm[m_] += lt
            lt_g[m_] = lt
        tf += est(ft)
        rep.append((est(ft), lt_g["ac"], lt_g["a"], lt_g["c"], len(ms), len(ms) + 1, g))

    # GLOBALS_SHARED.tsv: every address touched by 2+ groups, and which groups (isolated = group of 1 function)
    shared = sorted((d for d, gs in addr_groups.items() if len(gs) >= 2),
                    key=lambda d: (-len(addr_groups[d]), d))
    with open(os.path.join(a.out, "GLOBALS_SHARED.tsv"), "w", encoding="utf-8", newline="\n") as f:
        f.write("ADDRESS\tNAME\tGROUP_COUNT\tGROUPS (isolated = a group of one function)\n")
        for d in shared:
            gs = sorted(addr_groups[d])
            f.write("%s\t%s\t%d\t%s\n" % (d, data_name.get(d, ""), len(gs), " | ".join(
                g_ + (" (isolated)" if group_size.get(g_, 0) == 1 else "") for g_ in gs)))
    n_local = sum(1 for gs in addr_groups.values() if len(gs) == 1)

    noc = sum(1 for e in entries if not (cf.get(e) or {}).get("code"))
    noa = sum(1 for e in entries if e not in asm)
    nf = len(members)
    nl = sum(r[5] for r in rep)
    W = 78
    lines = ["Grouped by: " + ", ".join("%s=%d" % kv for kv in sorted(how.items())), "",
             "%11s %11s %11s %11s  %9s  %10s  %s" % ("FULL tok", "LITE_AC tok", "LITE_A tok", "LITE_C tok", "functions", "files/LITE", "group"),
             "-" * 100]
    for tf_, ta_, tb_, tc_, n_, lf_, g_ in sorted(rep, key=lambda r: -r[0]):
        lines.append("%11d %11d %11d %11d  %9d  %10d  %s" % (tf_, ta_, tb_, tc_, n_, lf_, g_))
    lines += ["=" * 100, "TOTALS",
              "%11d %11d %11d %11d  %9d  %10d  (all groups)" % (tf, tlm["ac"], tlm["a"], tlm["c"], len(entries), nl),
              "",
              "Classes/groups ........ %d" % nf,
              "Functions ............. %d" % len(entries),
              "  with assembly ....... %d" % len(asm),
              "  with C .............. %d" % len(cf),
              "  without C ........... %d" % noc,
              "  without assembly .... %d" % noa,
              "FULL files ............ %d" % nf,
              "LITE files (each of 3)  %d  (%d function files + %d class headers)" % (nl, nl - nf, nf),
              "FULL tokens (est) ..... %d" % tf,
              "LITE_AC tokens (est) .. %d  (%.1f%% of FULL)" % (tlm["ac"], 100.0 * tlm["ac"] / max(tf, 1)),
              "LITE_A tokens (est) ... %d  (%.1f%% of FULL)" % (tlm["a"], 100.0 * tlm["a"] / max(tf, 1)),
              "LITE_C tokens (est) ... %d  (%.1f%% of FULL)" % (tlm["c"], 100.0 * tlm["c"] / max(tf, 1))]
    lines += ["Data addresses GLOBAL (2+ groups)  %d   (see GLOBALS_SHARED.tsv)" % len(shared),
              "Data addresses LOCAL (1 group) ..... %d" % n_local]
    with open(os.path.join(a.out, "Report.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print("\n".join(lines[-16:]))


if __name__ == "__main__":
    main()
