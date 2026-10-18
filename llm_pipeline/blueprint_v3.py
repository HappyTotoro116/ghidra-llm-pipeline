# Copyright 2026 Ryu116
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

r"""blueprint_v3.py (v2 + return-value fact) - Python reads the ASSEMBLY of each function and writes a BLUEPRINT (facts + skeleton)
plus a CHECKLIST (facts the LLM's code must contain). Read-only. No LLM.

Usage:  python .\blueprint_v3.py --group ".\SOURCE\LITE_AC\<GroupName>" --out ".\G_<GroupName>\BLUEPRINT_v3"
Input : the per-function .txt files of one group (header + [ASSEMBLY] + optional [C PSEUDOCODE]).
Output: <entry>_<name>.blueprint.txt   facts, lifted code, checklist, declarations, skeleton, optional Ghidra C hint
        <entry>_<name>.check.json      must_call / must_use_globals / must_use_strings / nargs / checklist / machine facts
Everything is read from the assembly text; nothing is guessed about behavior that the assembly does not show."""
import argparse, json, os, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--group", required=True, help="folder of one group (LITE_AC\\<Group>)")
ap.add_argument("--out", required=True)
ap.add_argument("--checklist-overrides", default=None, help="CHECKLIST_OVERRIDES.txt: ENTRY<TAB>text adds a line; ENTRY<TAB>-word removes auto lines containing word")
ap.add_argument("--index-dir", default=None, help="folder with ALL groups (LITE_AC) to learn callee signatures; default: parent of --group")
a = ap.parse_args()

MEM = re.compile(r"\[(0x[0-9A-Fa-f]{6,8})\]")
STK = re.compile(r"\[(EBP|ESP)\s*([+-])\s*(0x[0-9A-Fa-f]+)\]", re.I)
WRITE_FIRST = {"MOV", "MOVZX", "MOVSX", "LEA", "POP", "SETZ", "SETNZ", "FST", "FSTP", "FISTP", "FIST", "FNSTCW", "FNSTSW", "XCHG"}
RW_FIRST = {"ADD", "SUB", "AND", "OR", "XOR", "INC", "DEC", "NEG", "NOT", "SHL", "SHR", "SAR", "ADC", "SBB"}
READ_ONLY = {"CMP", "TEST", "PUSH", "FLD", "FILD", "FADD", "FSUB", "FMUL", "FDIV", "FCOM", "FCOMP", "FLDCW"}


REGS = {"EAX", "EBX", "ECX", "EDX", "ESI", "EDI", "AX", "AL"}
BIN = {"ADD": "+", "SUB": "-", "AND": "&", "OR": "|", "XOR": "^", "IMUL": "*", "SHL": "<<", "SHR": ">>", "SAR": ">>"}
BRANCH = re.compile(r"^(J[A-Z]+|LOOP\w*|CMP|TEST|SET[A-Z]+|CMOV[A-Z]+|REP\w*|MOVS\w|STOS\w|SCAS\w|CMPS\w)$")

def _jni_table():
    t = {4: "GetVersion", 5: "DefineClass", 6: "FindClass", 7: "FromReflectedMethod", 8: "FromReflectedField",
         9: "ToReflectedMethod", 10: "GetSuperclass", 11: "IsAssignableFrom", 12: "ToReflectedField", 13: "Throw",
         14: "ThrowNew", 15: "ExceptionOccurred", 16: "ExceptionDescribe", 17: "ExceptionClear", 18: "FatalError",
         19: "PushLocalFrame", 20: "PopLocalFrame", 21: "NewGlobalRef", 22: "DeleteGlobalRef", 23: "DeleteLocalRef",
         24: "IsSameObject", 25: "NewLocalRef", 26: "EnsureLocalCapacity", 27: "AllocObject", 28: "NewObject",
         29: "NewObjectV", 30: "NewObjectA", 31: "GetObjectClass", 32: "IsInstanceOf", 33: "GetMethodID"}
    ty = ["Object", "Boolean", "Byte", "Char", "Short", "Int", "Long", "Float", "Double", "Void"]
    i = 34
    for x in ty:
        for v in ("", "V", "A"):
            t[i] = "Call%sMethod%s" % (x, v); i += 1
    for x in ty:
        for v in ("", "V", "A"):
            t[i] = "CallNonvirtual%sMethod%s" % (x, v); i += 1
    t[i] = "GetFieldID"; i += 1
    for x in ty[:9]:
        t[i] = "Get%sField" % x; i += 1
    for x in ty[:9]:
        t[i] = "Set%sField" % x; i += 1
    t[i] = "GetStaticMethodID"; i += 1
    for x in ty:
        for v in ("", "V", "A"):
            t[i] = "CallStatic%sMethod%s" % (x, v); i += 1
    t[i] = "GetStaticFieldID"; i += 1
    for x in ty[:9]:
        t[i] = "GetStatic%sField" % x; i += 1
    for x in ty[:9]:
        t[i] = "SetStatic%sField" % x; i += 1
    for n in ("NewString", "GetStringLength", "GetStringChars", "ReleaseStringChars", "NewStringUTF",
              "GetStringUTFLength", "GetStringUTFChars", "ReleaseStringUTFChars", "GetArrayLength", "NewObjectArray",
              "GetObjectArrayElement", "SetObjectArrayElement"):
        t[i] = n; i += 1
    pr = ty[1:9]
    for fmt in ("New%sArray", "Get%sArrayElements", "Release%sArrayElements", "Get%sArrayRegion", "Set%sArrayRegion"):
        for x in pr:
            t[i] = fmt % x; i += 1
    for n in ("RegisterNatives", "UnregisterNatives", "MonitorEnter", "MonitorExit", "GetJavaVM", "GetStringRegion",
              "GetStringUTFRegion", "GetPrimitiveArrayCritical", "ReleasePrimitiveArrayCritical", "GetStringCritical",
              "ReleaseStringCritical", "NewWeakGlobalRef", "DeleteWeakGlobalRef", "ExceptionCheck",
              "NewDirectByteBuffer", "GetDirectBufferAddress", "GetDirectBufferCapacity", "GetObjectRefType"):
        t[i] = n; i += 1
    return t


JNI_FN = _jni_table()      # index -> name; table offset = index * 4 (32-bit). 167 = NewStringUTF = 0x29c
assert JNI_FN[167] == "NewStringUTF" and JNI_FN[169] == "GetStringUTFChars" and JNI_FN[228] == "ExceptionCheck"
REGMEM = re.compile(r"\[\s*(E[A-Z]{2})\s*(?:\+\s*(0x[0-9A-Fa-f]+))?\s*\]")


def pseudo(ops, names, nargs, jni=False):
    """Straight-line reading of the assembly: registers tracked as expressions. Stops at the first branch.
    Returns (lines, complete, reads_after_call)."""
    regs, pend, out, rac = {}, [], [], []
    calls_seen, tmp = [], 0
    started = False
    esp = [0]      # bytes pushed so far (for [ESP+k] argument reads)

    def argname(k):
        return {0: "env", 1: "self"}.get(k, "arg%d" % (k - 1)) if jni else "arg%d" % k

    def ext(o):
        o = o.strip()
        o = re.sub(r"^(byte|word|dword|qword)\s+ptr\s+", "", o, flags=re.I)
        m = MEM.fullmatch(o)
        if m:
            g = m.group(1)[2:].lower().zfill(8)
            return names.get(g, "DAT_" + g)
        m = STK.fullmatch(o)
        if m and m.group(1).upper() == "EBP" and m.group(2) == "+":
            return argname((int(m.group(3), 16) - 8) // 4)
        if m and m.group(1).upper() == "ESP" and m.group(2) == "+" and int(m.group(3), 16) - esp[0] >= 4:
            return argname((int(m.group(3), 16) - esp[0] - 4) // 4)
        m = REGMEM.fullmatch(o)
        if m and m.group(1).upper() in regs:
            base, off = regs[m.group(1).upper()], int(m.group(2), 16) if m.group(2) else 0
            if base == "env" and off == 0:
                return "(*env)"
            if base == "(*env)" and off % 4 == 0 and off // 4 in JNI_FN:
                return "(*env)->" + JNI_FN[off // 4]
            return "*(%s%s)" % (base, (" + 0x%x" % off) if off else "")
        if re.fullmatch(r"0x[0-9A-Fa-f]+|-?\d+", o):
            return o
        if o.upper() in regs:
            return regs[o.upper()]
        if o.upper() in REGS | {"ESP", "EBP"}:
            return o.upper()
        return None

    def note_reads(expr):
        for g in re.findall(r"(?:DAT|PTR|BYTE|WORD)_[0-9a-fA-F]{8}", expr):
            for c in calls_seen:
                rac.append((c, g))

    for addr, mn, opnd in ops:
        parts = [x.strip() for x in opnd.split(",", 1)] if opnd else []
        d = parts[0] if parts else ""
        sr = parts[1] if len(parts) > 1 else ""
        if BRANCH.match(mn):
            out.append("// BRANCH at %s (%s %s): the rest is not straight-line, read the assembly" % (addr, mn.lower(), opnd))
            return out, False, rac
        if mn == "PUSH":
            esp[0] += 4
        elif mn == "POP":
            esp[0] -= 4
        elif d.upper() == "ESP" and mn in ("SUB", "ADD") and re.fullmatch(r"0x[0-9A-Fa-f]+", sr or ""):
            esp[0] += int(sr, 16) * (1 if mn == "SUB" else -1)
        if mn == "PUSH" and d.upper() in ("EBP", "EBX", "ESI", "EDI") and d.upper() not in regs:
            continue        # saving a callee-saved register, not an argument
        if mn in ("PUSH", "POP") and d.upper() in ("EBP", "EBX", "ESI", "EDI") and not started:
            continue
        if mn == "POP" and d.upper() in ("EBP", "EBX", "ESI", "EDI"):
            continue
        if d.upper() in ("ESP", "EBP") and mn in ("MOV", "SUB", "ADD", "LEA"):
            continue
        if mn == "RET":
            e = regs.get("EAX")
            out.append("return %s;" % e if e is not None else "return;  // EAX not set in this function")
            return out, True, rac
        started = True
        if mn == "PUSH":
            v = ext(d)
            pend.append(v if v is not None else d)
            continue
        if mn == "CALL":
            tm = re.match(r"0x([0-9A-Fa-f]{8})$", d)
            if tm:
                tgt = names.get(tm.group(1).lower(), "FUN_" + tm.group(1).lower())
            else:
                tgt = ext(d) or d
            tmp += 1
            rv = "ret%d" % tmp
            out.append("%s = %s(%s);" % (rv, tgt, ", ".join(reversed(pend))))
            pend = []
            calls_seen.append(tgt)
            regs["EAX"] = rv
            continue
        if mn == "MOV" or mn == "MOVZX" or mn == "MOVSX":
            v = ext(sr)
            if v is None:
                out.append("// raw: %s %s" % (mn.lower(), opnd)); return out, False, rac
            note_reads(v)
            if d.upper() in REGS:
                regs[d.upper()] = v
            else:
                t = ext(d)
                if t is None:
                    out.append("// raw: %s %s" % (mn.lower(), opnd)); return out, False, rac
                out.append("%s = %s;" % (t, v))
            continue
        if mn == "LEA":
            m = re.match(r"\[(.*)\]$", sr)
            regs[d.upper()] = "&(%s)" % (m.group(1) if m else sr)
            continue
        if mn in BIN or mn in ("INC", "DEC", "NEG", "NOT"):
            if mn in ("INC", "DEC", "NEG", "NOT"):
                dv, sv = ext(d), {"INC": "1", "DEC": "1"}.get(mn)
                op = {"INC": "+", "DEC": "-"}.get(mn)
                if dv is None:
                    out.append("// raw: %s %s" % (mn.lower(), opnd)); return out, False, rac
                nv = ("%s %s 1" % (dv, op)) if op else ("%s(%s)" % ("-" if mn == "NEG" else "~", dv))
            else:
                if mn == "XOR" and d.upper() == sr.upper():
                    regs[d.upper()] = "0"; continue
                dv, sv = ext(d), ext(sr)
                if dv is None or sv is None:
                    out.append("// raw: %s %s" % (mn.lower(), opnd)); return out, False, rac
                note_reads(sv)
                nv = "(%s %s %s)" % (dv, BIN[mn], sv)
            if d.upper() in REGS:
                regs[d.upper()] = nv
            else:
                out.append("%s = %s;" % (dv, nv.strip("()") if nv.startswith("(") else nv))
            continue
        out.append("// raw: %s %s" % (mn.lower(), opnd))
        return out, False, rac
    return out, False, rac


JCC = {"JZ": "E", "JE": "E", "JNZ": "NE", "JNE": "NE", "JL": "L", "JNGE": "L", "JLE": "LE", "JNG": "LE", "JG": "G",
       "JNLE": "G", "JGE": "GE", "JNL": "GE", "JB": "B", "JC": "B", "JNAE": "B", "JBE": "BE", "JNA": "BE", "JA": "A",
       "JNBE": "A", "JAE": "AE", "JNB": "AE", "JNC": "AE", "JS": "S", "JNS": "NS"}
SETCC = {"SET" + k[1:]: v for k, v in JCC.items()}
CMOVCC = {"CMOV" + k[1:]: v for k, v in JCC.items()}
CAST = {"byte": "uint8_t", "word": "uint16_t", "qword": "uint64_t"}
CSAVE = ("EBP", "EBX", "ESI", "EDI")


def d_is_edi(opnd):
    return opnd.replace(" ", "").upper().endswith("EDI")


LBL = r"L_[0-9a-f]{8}"


def negate(c):
    c = c.strip()
    m = re.fullmatch(r"(.+?) (==|!=) (.+)", c)
    if m and not re.search(r"&&|\|\||\?", c) and c.count(" == ") + c.count(" != ") == 1:
        return "%s %s %s" % (m.group(1), "!=" if m.group(2) == "==" else "==", m.group(3))
    return "!(%s)" % c


def structure(lines):
    """Turn simple goto patterns into if { } and do { } while (); anything else stays as goto."""
    L = [x for x in lines]
    # peephole: strlen idiom  (ecx = -(len)-2; ecx = ~ecx; ecx = ecx - 1;  ->  ecx = strlen(...))
    i = 0
    while i < len(L) - 2:
        m = re.match(r"^ecx = \(uint32_t\)\(-\(int32_t\)strlen\(\(char\*\)(\w+)\) - 2\);", L[i])
        if m and L[i + 1] == "ecx = ~ecx;" and L[i + 2] == "ecx = ecx - 1;":
            L[i:i + 3] = ["ecx = strlen((char*)%s);" % m.group(1)]
        i += 1

    k = 0
    while k < len(L) - 1:                              # "goto X; X:"  -> nothing
        m = re.fullmatch(r"goto (" + LBL + ");", L[k])
        if m and L[k + 1] == m.group(1) + ":":
            del L[k]
        else:
            k += 1

    i = 0
    while i < len(L) - 1:                              # ecx = -(len)-2; ecx = ~ecx;  ->  ecx = len + 1
        m = re.match(r"^ecx = \(uint32_t\)\(-\(int32_t\)strlen\(\(char\*\)(\w+)\) - 2\);", L[i])
        if m and L[i + 1] == "ecx = ~ecx;":
            L[i:i + 2] = ["ecx = strlen((char*)%s) + 1;" % m.group(1)]
        i += 1

    def refs(lab):
        return sum(1 for x in L if re.search(r"goto " + lab + r"\b", x))

    def balanced(body):
        d = 0
        for x in body:
            if x.startswith("}"):
                d -= 1
                if d < 0:
                    return False
            if x.endswith("{"):
                d += 1
        return d == 0

    def jumps_back(body, i):
        for x in body:
            for t in re.findall(r"goto (" + LBL + ")", x):
                if (t + ":") in L[:i + 1]:
                    return True
        return False

    changed = True
    guard = 0
    while changed and guard < 500:
        changed, guard = False, guard + 1
        for i, l in enumerate(L):                      # label nobody jumps to: drop
            m = re.fullmatch(r"(" + LBL + "):", l)
            if m and refs(m.group(1)) == 0:
                del L[i]; changed = True; break
        if changed:
            continue
        for i, l in enumerate(L):                      # forward skip:  if (C) goto X; ...; X:
            m = re.fullmatch(r"if \((.*)\) goto (" + LBL + ");", l)
            if not m or refs(m.group(2)) != 1 or (m.group(2) + ":") not in L[i + 1:]:
                continue
            j = L.index(m.group(2) + ":", i + 1)
            body = L[i + 1:j]
            if not body or any(re.fullmatch(LBL + ":", b) for b in body) or not balanced(body) or jumps_back(body, i):
                continue
            L[i:j + 1] = ["if (%s) {" % negate(m.group(1))] + body + ["}"]
            changed = True; break
        if changed:
            continue
        for j, l in enumerate(L):                      # backward jump:  X: ...; if (C) goto X;
            m = re.fullmatch(r"if \((.*)\) goto (" + LBL + ");", l)
            if not m or refs(m.group(2)) != 1 or (m.group(2) + ":") not in L[:j]:
                continue
            i = L.index(m.group(2) + ":")
            body = L[i + 1:j]
            if not body or any(re.fullmatch(LBL + ":", b) for b in body) or not balanced(body):
                continue
            L[i:j + 1] = ["do {"] + body + ["} while (%s);" % m.group(1)]
            changed = True; break
    out, ind = [], 0
    for x in L:
        if x.startswith("}"):
            ind = max(0, ind - 1)
        out.append("  " * ind + x if not re.fullmatch(LBL + ":", x) else x)
        if x.endswith("{") and not x.startswith("if (") or (x.startswith("if (") and x.endswith("{") and "goto" not in x):
            ind += 1
    return out


def lift(ops, names, jni=False):
    """Register-level C for the whole function (branches as if/goto). Complete unless a line says 'raw'.
    Returns (lines, complete, nargs_read, jni_names)."""
    addrs = {a for a, _, _ in ops}
    targets = set()
    for a, mn, op in ops:
        if (mn in JCC or mn == "JMP") and re.fullmatch(r"0x[0-9A-Fa-f]{8}", op.strip()):
            t = op.strip()[2:].lower()
            if t in addrs:
                targets.add(t)
    out, pend, sym, jn = [], [], {}, []
    kc = {}          # sub-register known to be a constant, e.g. {"al": "0"} after eax = 0
    # sbb idiom: "sbb eax,eax ; sbb eax,-1" = strcmp-style result (-1 if the last compare was below, else 1)
    sbbmap, skipaddr = {}, set()
    for _i in range(len(ops) - 2):
        (a1, m1, o1), (a2, m2, o2), (a3, _m3, _o3) = ops[_i], ops[_i + 1], ops[_i + 2]
        if m1 == "SBB" and o1.replace(" ", "").upper() == "EAX,EAX" and m2 == "SBB" and \
                o2.replace(" ", "").upper() in ("EAX,-0X1", "EAX,-1", "EAX,0XFFFFFFFF"):
            sbbmap[a1] = a3
            skipaddr |= {a1, a2}
    st = {"esp": 0, "flag": None, "complete": True, "maxarg": -1, "tmp": 0}
    seen = set()
    callinfo = {}
    # prepass: biggest stack depth = size of the local frame (for ESP-relative locals)
    e_, F = 0, 0
    for _a, _mn, _op in ops:
        _p = [x.strip() for x in _op.split(",", 1)] if _op else []
        if _mn == "PUSH":
            e_ += 4
        elif _mn == "POP":
            e_ -= 4
        elif _p and _p[0].upper() == "ESP" and _mn in ("SUB", "ADD") and len(_p) > 1 and re.fullmatch(r"0x[0-9A-Fa-f]+", _p[1]):
            e_ += int(_p[1], 16) * (1 if _mn == "SUB" else -1)
        F = max(F, e_)

    def hexnorm(t):
        def f(m):
            v = int(m.group(0), 16)
            return "-0x%x" % (0x100000000 - v) if 0xfffff000 <= v <= 0xffffffff else m.group(0)
        return re.sub(r"0x[0-9a-fA-F]{8}\b", f, t)

    def frame_at(k):
        return "(uint32_t)(frame + %d)" % (F + k - st["esp"])

    def argname(k):
        st["maxarg"] = max(st["maxarg"], k)
        return {0: "env", 1: "self"}.get(k, "arg%d" % (k - 1)) if jni else "arg%d" % k

    def gname(h):
        h = h.lower().zfill(8)
        return names.get(h, "DAT_" + h)

    def ext(o):
        o = o.strip()
        cast = None
        m = re.match(r"^(byte|word|dword|qword)\s+ptr\s+(.*)$", o, re.I)
        if m:
            cast = CAST.get(m.group(1).lower())
            o = m.group(2).strip()
        if re.fullmatch(r"0x[0-9A-Fa-f]+|-?\d+", o):
            return o
        if o.upper() == "ESP":
            return frame_at(0)
        if re.fullmatch(r"[A-Za-z]{2,3}", o) and o.upper() not in ("PTR",):
            return kc.get(o.lower(), o.lower())
        if re.fullmatch(r"\[\s*ESP\s*\]", o, re.I):
            o = "[ESP + 0x0]"
        m = MEM.fullmatch(o)
        if m:
            g = gname(m.group(1)[2:])
            return "((%s*)&%s)[0]" % (cast, g) if cast else g
        m = STK.fullmatch(o)
        if m:
            k = int(m.group(3), 16)
            if m.group(1).upper() == "EBP":
                if m.group(2) == "+" and k >= 8:
                    return argname((k - 8) // 4)
                return "local_%x" % k
            if m.group(2) == "+" and k - st["esp"] >= 4:
                return argname((k - st["esp"] - 4) // 4)
            kk = k if m.group(2) == "+" else -k
            return "*(%s*)(frame + %d)" % (cast or "uint32_t", F + kk - st["esp"])
        m = re.fullmatch(r"\[\s*(E[A-Z]{2})\s*(?:\+\s*(0x[0-9A-Fa-f]+))?\s*\]", o)
        if m:
            r, off = m.group(1).lower(), int(m.group(2), 16) if m.group(2) else 0
            if sym.get(r) == "env" and off == 0:
                return "(*env)"
            return "*(%s%s*)(%s%s)" % (cast or "uint32_t", "", r, (" + 0x%x" % off) if off else "")
        m = re.fullmatch(r"\[(.*)\]", o)
        if m:
            inner = re.sub(r"\s+", " ", m.group(1).strip()).lower()
            inner = hexnorm(re.sub(r"\besp\b", frame_at(0), inner))
            return "*(%s*)(%s)" % (cast or "uint32_t", inner)
        return None

    def cond(code):
        f = st["flag"]
        if f is None:
            st["complete"] = False
            return "/*flags unknown*/ 1"
        if f[0] == "cmp":
            a, b = f[1], f[2]
            sc = {"E": "%s == %s", "NE": "%s != %s", "L": "(int32_t)%s < (int32_t)%s", "LE": "(int32_t)%s <= (int32_t)%s",
                  "G": "(int32_t)%s > (int32_t)%s", "GE": "(int32_t)%s >= (int32_t)%s",
                  "B": "(uint32_t)%s < (uint32_t)%s", "BE": "(uint32_t)%s <= (uint32_t)%s",
                  "A": "(uint32_t)%s > (uint32_t)%s", "AE": "(uint32_t)%s >= (uint32_t)%s",
                  "S": "(int32_t)(%s - %s) < 0", "NS": "(int32_t)(%s - %s) >= 0"}
            return sc[code] % (a, b)
        v = "(%s & %s)" % (f[1], f[2]) if f[0] == "test" and f[1] != f[2] else f[1]
        sc = {"E": "%s == 0", "NE": "%s != 0", "S": "(int32_t)%s < 0", "NS": "(int32_t)%s >= 0",
              "L": "(int32_t)%s < 0", "GE": "(int32_t)%s >= 0", "LE": "(int32_t)%s <= 0", "G": "(int32_t)%s > 0",
              "B": "0 /*carry*/", "BE": "%s == 0", "A": "%s != 0", "AE": "1 /*no carry*/"}
        return sc[code] % v if "%s" in sc[code] else sc[code]

    def raw(a, mn, op):
        out.append("/* raw %s: %s %s */" % (a, mn.lower(), op))
        st["complete"] = False

    last = [0]
    for a, mn, opnd in ops:
        for _ln in out[last[0]:]:
            _lowmap = {"eax": "al", "ebx": "bl", "ecx": "cl", "edx": "dl"}
            _m = re.match(r"^(e[abcd]x) = (.*);", _ln)
            if _m and _m.group(2).strip() == "0" and _m.group(1) in _lowmap:
                kc[_lowmap[_m.group(1)]] = "0"
            else:
                for _r in re.findall(r"\b(e[abcd]x|[abcd]l)\s*=(?!=)", _ln):
                    kc.pop(_lowmap.get(_r, _r), None)
        last[0] = len(out)
        if a in targets:
            kc.clear()
            if a not in sbbmap:
                out.append("L_%s:" % a)
        if a in skipaddr:
            if a in sbbmap:
                f = st["flag"]
                prev = out[-1] if out else ""
                if f and f[0] == "cmp" and not prev.startswith(("goto", "return")) and not prev.endswith(":"):
                    out.append("eax = ((uint32_t)%s < (uint32_t)%s) ? 0xffffffff : 1;" % (f[1], f[2]))
            continue
        if mn == "SCASB.REPNE" and kc.get("al") == "0" and d_is_edi(opnd):
            out.append("ecx = (uint32_t)(-(int32_t)strlen((char*)edi) - 2);   /* repne scasb */")
            continue
        parts = [x.strip() for x in re.split(r",(?![^\[]*\])", opnd)] if opnd else []
        d = parts[0] if parts else ""
        sr = parts[1] if len(parts) > 1 else ""
        if mn == "PUSH":
            st["esp"] += 4
            if d.upper() in CSAVE and a not in seen and d.lower() not in sym and not any("%s =" % d.lower() in x for x in out):
                continue
            v = ext(d)
            pend.append(v if v is not None else d)
            continue
        if mn == "POP":
            st["esp"] -= 4
            if d.upper() in CSAVE:
                continue
            raw(a, mn, opnd); continue
        if d.upper() in ("ESP", "EBP") and mn in ("MOV", "SUB", "ADD", "LEA"):
            if d.upper() == "ESP" and mn in ("SUB", "ADD") and re.fullmatch(r"0x[0-9A-Fa-f]+", sr):
                st["esp"] += int(sr, 16) * (1 if mn == "SUB" else -1)
            continue
        if mn in ("NOP", "LEAVE", "CDQ") and mn != "CDQ":
            continue
        if mn == "RET":
            out.append("return eax;"); continue
        if mn == "CALL":
            tm = re.fullmatch(r"0x([0-9A-Fa-f]{8})", d)
            if tm:
                tgt = names.get(tm.group(1).lower(), "FUN_" + tm.group(1).lower())
            else:
                m = re.search(r"\[\s*(E[A-Z]{2})\s*(?:\+\s*(0x[0-9A-Fa-f]+))?\s*\]", d)
                tgt = None
                if m and sym.get(m.group(1).lower()) == "(*env)":
                    off = int(m.group(2), 16) if m.group(2) else 0
                    if off // 4 in JNI_FN:
                        tgt = "(*env)->" + JNI_FN[off // 4]
                        jn.append(JNI_FN[off // 4])
                if tgt is None:
                    tgt = "(*%s)" % (ext(d) or d)
            pend = [("env" if sym.get(v) == "env" else v) for v in pend]
            if not tgt.startswith("(*"):
                callinfo[tgt] = len(pend)
            out.append("eax = %s(%s);" % (tgt, ", ".join(reversed(pend))))
            pend = []
            sym.pop("eax", None)
            continue
        if mn == "JMP":
            tm = re.fullmatch(r"0x([0-9A-Fa-f]{8})", d)
            out.append("goto L_%s;" % tm.group(1).lower() if tm and tm.group(1).lower() in addrs else "/* jmp %s: tail call or indirect */ return eax;" % d)
            continue
        if mn in JCC:
            tm = re.fullmatch(r"0x([0-9A-Fa-f]{8})", d)
            if tm and tm.group(1).lower() in sbbmap and st["flag"] and st["flag"][0] == "cmp":
                f = st["flag"]
                out.append("if (%s) { eax = ((uint32_t)%s < (uint32_t)%s) ? 0xffffffff : 1; goto L_%s; }" %
                           (cond(JCC[mn]), f[1], f[2], sbbmap[tm.group(1).lower()]))
                targets.add(sbbmap[tm.group(1).lower()])
            elif tm:
                out.append("if (%s) goto L_%s;" % (cond(JCC[mn]), tm.group(1).lower()))
            else:
                raw(a, mn, opnd)
            continue
        if mn in SETCC:
            out.append("%s = (%s);" % (ext(d) or d, cond(SETCC[mn]))); continue
        if mn in CMOVCC:
            out.append("if (%s) %s = %s;" % (cond(CMOVCC[mn]), ext(d), ext(sr))); continue
        if mn == "CMP" or mn == "TEST":
            x, y = ext(d), ext(sr)
            if x is None or y is None:
                raw(a, mn, opnd); continue
            st["flag"] = ("cmp" if mn == "CMP" else "test", x, y); continue
        if mn in ("MOV", "MOVZX", "MOVSX"):
            x, y = ext(d), ext(sr)
            if x is None or y is None:
                raw(a, mn, opnd); continue
            if re.fullmatch(r"e[a-z]{2}", x) and y in ("env", "(*env)"):
                sym[x] = y          # only prepares the JNI function-table call: no line emitted
                continue
            out.append("%s = %s;" % (x, y))
            if re.fullmatch(r"e[a-z]{2}", x):
                if y == "env":
                    sym[x] = "env"
                elif y == "(*env)" or (y.startswith("*(") and sym.get(re.sub(r"[^a-z]", "", y.split("(")[-1].split(" ")[0])) == "env"):
                    sym[x] = "(*env)"
                else:
                    sym.pop(x, None)
            continue
        if mn == "LEA":
            m = re.fullmatch(r"\[(.*)\]", sr)
            x = ext(d)
            if m and x:
                inner = hexnorm(re.sub(r"\besp\b", frame_at(0), re.sub(r"\s+", " ", m.group(1).strip()).lower()))
                out.append("%s = %s;" % (x, inner)); sym.pop(x, None)
            else:
                raw(a, mn, opnd)
            continue
        BINOP = {"ADD": "+", "SUB": "-", "AND": "&", "OR": "|", "XOR": "^", "IMUL": "*", "SHL": "<<", "SHR": ">>", "SAR": ">>"}
        if mn in BINOP and sr:
            x, y = ext(d), ext(sr)
            if x is None or y is None:
                raw(a, mn, opnd); continue
            if mn == "IMUL" and len(parts) == 3:
                out.append("%s = %s * %s;" % (x, y, ext(parts[2]))); sym.pop(x, None); continue
            if mn == "XOR" and x == y:
                out.append("%s = 0;" % x); st["flag"] = ("res", x); sym.pop(x, None); continue
            out.append("%s = %s %s %s;" % (x, x, BINOP[mn], y)); st["flag"] = ("res", x); sym.pop(x, None); continue
        if mn in ("INC", "DEC", "NEG", "NOT") and d:
            x = ext(d)
            if x is None:
                raw(a, mn, opnd); continue
            out.append({"INC": "%s = %s + 1;", "DEC": "%s = %s - 1;", "NEG": "%s = -%s;", "NOT": "%s = ~%s;"}[mn] % (x, x))
            st["flag"] = ("res", x); continue
        if mn == "CDQ":
            out.append("edx = ((int32_t)eax < 0) ? 0xFFFFFFFF : 0;"); continue
        raw(a, mn, opnd)
    out = structure(out)
    if any("frame" in x for x in out):
        out.insert(0, "uint8_t frame[%d];   /* this function's stack frame (locals, buffers, saved registers) */" % max(F, 4))
    return out, st["complete"], st["maxarg"] + 1, jn, callinfo


def parse(path):
    txt = open(path, encoding="utf-8", errors="replace").read().replace("\r", "")
    head, asm, c, sec = [], [], [], "head"
    for ln in txt.split("\n"):
        if ln.startswith("[ASSEMBLY]"):
            sec = "asm"; continue
        if ln.startswith("[C PSEUDOCODE]"):
            sec = "c"; continue
        (head if sec == "head" else asm if sec == "asm" else c).append(ln)
    return head, [l for l in asm if l.strip()], "\n".join(c).strip()


def header_map(head):
    names = {}
    info = {"name": "", "entry": "", "strings": []}
    for ln in head:
        m = re.match(r"// FUNCTION:\s*(\S+)\s+ENTRY:\s*([0-9a-fA-F]+)", ln)
        if m:
            info["name"], info["entry"] = m.group(1), m.group(2).lower()
        for addr, nm in re.findall(r"([0-9a-fA-F]{8})=([A-Za-z_][\w@?$.]*)", ln):
            names[addr.lower()] = nm
        info["strings"] += re.findall(r'"([^"]{2,})"', ln) if "STRING" in ln.upper() else []
    return info, names


def analyse(path):
    head, asm, c = parse(path)
    info, names = header_map(head)
    ops = []
    for ln in asm:
        m = re.match(r"\s*([0-9a-fA-F]{8})\s+(\S+)\s*(.*)$", ln)
        if m:
            ops.append((m.group(1).lower(), m.group(2).upper(), m.group(3).strip()))
    steps, calls, glob = [], [], {}
    ret_bytes, uses_ebp, st0_last, eax_set = 0, False, None, False
    stack_reads = set()
    consts = []
    for addr, mn, opnd in ops:
        if mn == "PUSH" and opnd.upper() == "EBP":
            uses_ebp = True
        if mn == "RET":
            ret_bytes = int(opnd, 16) if opnd else 0
            steps.append((addr, "return" + (" (pops %d bytes of arguments: stdcall)" % ret_bytes if ret_bytes else "")))
            continue
        if mn in ("CALL", "JMP") and mn == "CALL":
            tm = re.match(r"0x([0-9A-Fa-f]{8})$", opnd)
            if tm:
                tgt = names.get(tm.group(1).lower(), "FUN_" + tm.group(1).lower())
            else:
                tgt = opnd
            calls.append(tgt)
            steps.append((addr, "call " + tgt))
            continue
        for mm in STK.finditer(opnd):
            if mm.group(1).upper() == "EBP" and mm.group(2) == "+":
                off = int(mm.group(3), 16)
                if off >= 8:
                    stack_reads.add((off - 8) // 4)
        dst = opnd.split(",")[0].strip() if opnd else ""
        for mm in MEM.finditer(opnd):
            g = mm.group(1)[2:].lower().zfill(8)
            gname = names.get(g, "DAT_" + g)
            rec = glob.setdefault(gname, {"addr": g, "read": 0, "write": 0})
            is_dst = MEM.search(dst) is not None and mm.group(1) in dst
            if mn in WRITE_FIRST and is_dst:
                rec["write"] += 1; steps.append((addr, "write %s" % gname))
            elif mn in RW_FIRST and is_dst:
                rec["read"] += 1; rec["write"] += 1; steps.append((addr, "read+write %s (%s)" % (gname, mn.lower())))
            else:
                rec["read"] += 1; steps.append((addr, "read %s" % gname))
        for im in re.findall(r"(?:^|,)\s*(0x[0-9A-Fa-f]+|-?\d+)\s*$", opnd):
            if mn in ("MOV", "ADD", "SUB", "CMP", "AND", "OR", "XOR", "PUSH", "TEST") and MEM.search(opnd) is not None:
                consts.append((addr, mn, im))
        if mn in ("FLD", "FILD"):
            st0_last = "float/double (x87)"
        if dst.upper() in ("EAX", "AX", "AL") and mn in WRITE_FIRST | RW_FIRST:
            eax_set = True
    # arguments: from name @N, else RET n
    m = re.search(r"@(\d+)$", info["name"])
    argbytes = int(m.group(1)) if m else ret_bytes
    jni = info["name"].lstrip("_").startswith("Java_")
    nargs = argbytes // 4
    pl, complete, rac = pseudo(ops, names, nargs, jni)
    lf, lcomplete, nread, ljn, callinfo = lift(ops, names, jni)
    if any(re.match(r"return\s+\S", x) for x in pl):
        eax_set = True
    jn = ljn or [m for x in pl for m in re.findall(r"\(\*env\)->(\w+)", x)]
    k = 0
    for i2, c in enumerate(calls):
        if "[" in c and k < len(jn):
            calls[i2] = "(*env)->" + jn[k]; k += 1
    return {"callinfo": callinfo, "jn": jn, "lift": lf, "lift_complete": lcomplete, "nread": nread, "pseudo": pl, "pseudo_complete": complete, "rac": rac, "info": info, "ops": ops, "steps": steps, "calls": calls, "glob": glob, "argbytes": argbytes,
            "nargs": nargs, "jni": jni, "uses_ebp": uses_ebp, "ret": st0_last or ("value in EAX" if eax_set else "none seen"),
            "stack_reads": sorted(stack_reads), "consts": consts, "c": c, "strings": info["strings"]}


def cname(n):
    n = n.lstrip("_")
    return re.sub(r"@\d+$", "", n)


CL_OVR = {}
if a.checklist_overrides and os.path.exists(a.checklist_overrides):
    for _ln in open(a.checklist_overrides, encoding="utf-8"):
        _p = _ln.rstrip("\n").split("\t", 1)
        if len(_p) == 2 and re.fullmatch(r"[0-9a-fA-F]{8}", _p[0].strip()):
            CL_OVR.setdefault(_p[0].strip().lower(), []).append(_p[1].strip())


def _consts(text):
    out = []
    for m in re.finditer(r"\b0x[0-9a-fA-F]+\b|\b\d+\b", text):
        try:
            v = int(m.group(0), 0)
        except ValueError:
            continue
        out.append(v)
    return out


def make_checklist(lift, entry):
    """Simple checklist from the structured lift. Length follows the function's complexity.
    Returns (lines, machine) where machine = facts Python can verify in the LLM's code."""
    lines = [x.strip() for x in lift if not x.strip().startswith("uint8_t frame[")]
    items, stack = [], []
    nloop = nif = 0
    steps, cond_consts, nstrlen = set(), set(), 0
    labels_seen = []
    goto_back = 0
    for ln in lines:
        m = re.fullmatch(r"(L_[0-9a-f]{8}):", ln)
        if m:
            labels_seen.append(m.group(1))
            continue
        ind = "  " * len(stack)
        if ln == "do {":
            nloop += 1
            stack.append(["loop", nloop, len(items)])
            items.append(ind + "[ ] loop %d: ..." % nloop)
            continue
        m = re.fullmatch(r"\} while \((.*)\);", ln)
        if m and stack and stack[-1][0] == "loop":
            _, n, idx = stack.pop()
            cond = m.group(1)
            items[idx] = items[idx].replace("...", "repeats while " + cond)
            cond_consts |= {v for v in _consts(cond) if v >= 2}
            continue
        m = re.fullmatch(r"if \((.*)\) \{", ln)
        if m:
            nif += 1
            stack.append(["if", nif, len(items)])
            items.append(ind + "[ ] if %d: %s" % (nif, m.group(1)))
            cond_consts |= {v for v in _consts(m.group(1)) if v >= 2}
            continue
        if ln == "}":
            if stack:
                stack.pop()
            continue
        # statements
        mm = re.search(r"(\w+) (?:\+=|= \1 \+) (0x[0-9a-fA-F]+|\d+);", ln)
        if mm and int(mm.group(2), 0) >= 2 and mm.group(1) in ("eax", "ecx", "edx", "esi", "edi", "ebp"):
            steps.add(int(mm.group(2), 0))
            items.append(ind + "[ ] %s advances by %s" % (mm.group(1), mm.group(2)))
        if "strlen(" in ln:
            nstrlen += 1
            items.append(ind + "[ ] string length (strlen) of %s" % re.search(r"strlen\(\(char\*\)(\w+)\)", ln).group(1))
        cm = re.search(r"= (\(\*env\)->\w+|[A-Za-z_]\w*)\(", ln)
        if cm and cm.group(1) not in ("strlen",) and not ln.startswith("if"):
            items.append(ind + "[ ] call %s" % cm.group(1))
        if "? 0xffffffff : 1" in ln:
            items.append(ind + "[ ] compare result is -1 if below, else 1 (strcmp style)")
        g = re.search(r"goto (L_[0-9a-f]{8});", ln)
        if g:
            if g.group(1) in labels_seen:
                goto_back += 1
                items.append(ind + "[ ] jump back to %s (loop kept as goto)" % g.group(1))
            else:
                items.append(ind + "[ ] jump forward to %s" % g.group(1))
        mr = re.fullmatch(r"return (.*);", ln)
        if mr:
            items.append(ind + "[ ] return %s" % mr.group(1))
    # a plain if(...) goto L...; that is still a goto in the lift
    rf = None
    if len(lines) >= 2 and lines[-1] == "return eax;":
        mrf = re.fullmatch(r"eax = (?:\(\*env\)->)?([A-Za-z_]\w*)\(.*\);", lines[-2])
        if mrf and mrf.group(1) != "strlen":
            rf = mrf.group(1)
            for k in range(len(items) - 1, -1, -1):
                if items[k].strip() == "[ ] return eax":
                    items[k] = items[k].replace("return eax", "return the result of %s" % rf)
                    break
    out = [x for x in items]
    for w in CL_OVR.get(entry, []):
        if w.startswith("-"):
            out = [x for x in out if w[1:].strip() not in x]
        else:
            out.append("[ ] (user) " + w)
    machine = {"loops": nloop + goto_back, "steps": sorted(steps), "cond_consts": sorted(cond_consts),
               "strlen": nstrlen, "return_from": rf}
    return out, machine


def blueprint(r):
    i = r["info"]
    L = ["BLUEPRINT  %s  (entry %s)" % (cname(i["name"]), i["entry"]), "",
         "FACTS (read from the assembly; these are not guesses)"]
    if r["jni"]:
        extra = max(0, r["nargs"] - 2)
        L.append("  convention : stdcall, %d bytes of arguments = %d args (JNI: JNIEnv* env, jobject self%s)" % (
            r["argbytes"], r["nargs"], (", then %d Java argument(s)" % extra) if extra else ""))
    else:
        if r["argbytes"]:
            L.append("  arguments  : %d bytes popped by RET = %d args" % (r["argbytes"], r["nargs"]))
        else:
            L.append("  arguments  : reads %d stack argument(s) (cdecl: the caller cleans the stack)" % r["nread"])
    L.append("  return     : %s" % r["ret"])
    L.append("  calls (in order): %s" % (", ".join(r["calls"]) or "none"))
    if r["glob"]:
        L.append("  globals    :")
        for g, v in r["glob"].items():
            L.append("    %-16s %s  reads %d, writes %d" % (g, v["addr"], v["read"], v["write"]))
    else:
        L.append("  globals    : none")
    if r["consts"]:
        L.append("  constants  : " + ", ".join("%s %s" % (m.lower(), im) for _, m, im in r["consts"]))
    if r["strings"]:
        L.append("  strings    : " + " | ".join('"%s"' % s for s in r["strings"]))
    L += ["", "PSEUDO (Python's straight-line reading of the assembly; %s)" % (
        "complete: this is the exact behavior" if r["pseudo_complete"] else "INCOMPLETE: stops at a branch or unknown instruction")]
    L += ["  " + x for x in r["pseudo"]]
    if not r["pseudo_complete"]:
        L += ["", "LIFTED (every instruction as register-level C; %s). Registers are variables, branches are if/goto." % (
            "complete" if r["lift_complete"] else "some lines are raw"),
            "  Rebuild normal C from this: turn the if/goto into if/else/loops, give variables good names.",
            "  Names (functions, globals) and constants here are exact; do not change them."]
        L += ["  " + x for x in r["lift"]]
    cl, _m = make_checklist(r["lift"], r["info"]["entry"].lower())
    if cl:
        L += ["", "CHECKLIST (what the finished function must do; one short line each, nested lines are inside the line above)"] + ["  " + x for x in cl]
    L += ["", "STEPS (assembly order)"]
    for n, (addr, s) in enumerate(r["steps"], 1):
        L.append("  %d. [%s] %s" % (n, addr, s))
    L += ["", "DECLARATIONS (written by Python and added to your code automatically: do NOT write includes, extern lines or prototypes yourself)"]
    L += ["  " + x for x in declarations(r, INDEX)]
    L += ["", "SKELETON (fill in; keep every name above exactly)"]
    ret_t = "int32_t" if r["ret"] != "none seen" else "void"
    conv = "__stdcall" if (r["argbytes"] or r["jni"]) else "__cdecl"
    if r["jni"]:
        params = "JNIEnv *env, jobject self" + "".join(", int32_t arg%d" % k for k in range(1, max(0, r["nargs"] - 2) + 1))
    else:
        params = ", ".join("int32_t arg%d" % k for k in range(r["nargs"] or r["nread"])) or "void"
    L.append("  %s %s %s(%s)" % (ret_t, conv, cname(i["name"]), params))
    L.append("  {")
    for g in r["glob"]:
        L.append("      /* uses global %s */" % g)
    for c in r["calls"]:
        L.append("      /* must call %s */" % c)
    L.append("      /* TODO: body = the PSEUDO lines above, in order */")
    L.append("  }")
    if r["c"] and "{" in r["c"]:
        L += ["", "GHIDRA C (hint only; if it disagrees with the FACTS, trust the FACTS)", r["c"]]
    return "\n".join(L) + "\n"


def bare(n):
    return re.sub(r"@\d+$", "", n.lstrip("_"))


def build_index(root):
    """name/entry -> (conv, nargs) for every function in LITE_AC, from each function's own assembly (RET n / stack reads)."""
    idx = {}
    for dp, _, fs in os.walk(root):
        for f in fs:
            if not f.lower().endswith(".txt"):
                continue
            try:
                r = analyse(os.path.join(dp, f))
            except Exception:
                continue
            if not r["info"]["name"]:
                continue
            na = r["nargs"] if r["argbytes"] else r["nread"]
            val = ("__stdcall" if (r["argbytes"] or r["jni"]) else "__cdecl", na)
            idx[bare(r["info"]["name"])] = val
            idx["FUN_" + r["info"]["entry"]] = val
    return idx


def declarations(r, idx):
    L = ["#include <stdint.h>"]
    if any("strlen(" in x for x in r["lift"]):
        L.append("#include <string.h>")
    if r["jni"] or r["jn"]:
        L.append("#include <jni.h>")
    for g, v in r["glob"].items():
        L.append("extern uint32_t %s;" % g)
    for c in sorted(set(r["calls"])):
        if not re.fullmatch(r"[A-Za-z_]\w*", c) or c == bare(r["info"]["name"]):
            continue
        conv, na = idx.get(bare(c), (None, None))
        site = r["callinfo"].get(c, 0)
        if conv is None:
            conv, na = "__cdecl", site
        else:
            na = max(na, site)      # a wrapper that jumps to another function reads no stack itself: trust the call site too
        params = ", ".join("int32_t a%d" % k for k in range(na)) or "void"
        L.append("int32_t %s %s(%s);" % (conv, c, params))
    return L


def check(r):
    return {"function": cname(r["info"]["name"]), "entry": r["info"]["entry"], "nargs": r["nargs"] or r["nread"],
            "must_call": sorted(set([c for c in r["calls"] if re.fullmatch(r"[A-Za-z_]\w*", c)] +
                                    r["jn"])),
            "must_use_globals": sorted(r["glob"]),
            "must_use_strings": r["strings"],
            "reads_after_call": sorted(set(r["rac"])), "pseudo_complete": r["pseudo_complete"],
            "declarations": declarations(r, INDEX),
            "checklist": make_checklist(r["lift"], r["info"]["entry"].lower())[0],
            "machine": make_checklist(r["lift"], r["info"]["entry"].lower())[1]}


INDEX = build_index(a.index_dir or os.path.dirname(os.path.abspath(a.group.rstrip("\\/"))))
print("signatures learned for %d names" % len(INDEX))
os.makedirs(a.out, exist_ok=True)
files = sorted(f for f in os.listdir(a.group) if f.lower().endswith(".txt"))
for f in files:
    r = analyse(os.path.join(a.group, f))
    if not r["info"]["name"]:
        continue
    stem = os.path.splitext(f)[0]
    open(os.path.join(a.out, stem + ".blueprint.txt"), "w", encoding="utf-8", newline="\n").write(blueprint(r))
    json.dump(check(r), open(os.path.join(a.out, stem + ".check.json"), "w", encoding="utf-8", newline="\n"), indent=1)
    print("wrote", stem)
