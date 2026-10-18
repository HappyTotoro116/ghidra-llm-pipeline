# Copyright 2026 Ryu116 (also known as HappyTotoro116)
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

r"""build_roles_v2.py - ROLES map from the per-function triage (read-only, no LLM needed).

Reads  OUT\TRIAGE\FUNCTIONS.tsv  (made by triage_evidence_v2.py).
Writes into the same folder (or --out-dir):
  ROLES.tsv        one line per group: track, label counts, role text, priority
  ROLES.txt        the map: 1_KEEP | 2_WRAP | 3_SHARED (helpers both tracks use) | 4_UNKNOWN | 5_REPLACE
  QUEUE_KEEP.tsv   every KEEP function (GROUP, ENTRY, NAME)   - the KEEP track, per function
  QUEUE_WRAP.tsv   every WRAP function                         - the WRAP track, per function
  QUEUE_UNKNOWN.tsv  functions to look at by hand
KEEP and WRAP stay separate tracks and are never merged; shared helpers are converted once.
Every track / role is a guess from the labels (observed counts, inferred meaning).

Usage:  python .\build_roles_v2.py --triage .\OUT\TRIAGE
Option: --llm [--model NAME] [--url http://127.0.0.1:1234]   ask a local model (LM Studio) for a one-line role per group.
        Off by default: the role text then comes from Python only (Java class names, API names)."""
import argparse, json, os, re, sys
from collections import Counter, defaultdict

ap = argparse.ArgumentParser()
ap.add_argument("--triage", required=True, help="folder with FUNCTIONS.tsv (OUT\\TRIAGE)")
ap.add_argument("--out-dir", default=None)
ap.add_argument("--llm", action="store_true", help="refine each role with a local model (LM Studio)")
ap.add_argument("--model", default="phi-4-reasoning")
ap.add_argument("--url", default="http://127.0.0.1:1234")
a = ap.parse_args()

src = os.path.join(a.triage, "FUNCTIONS.tsv")
if not os.path.isfile(src):
    sys.exit("FUNCTIONS.tsv not found in: " + a.triage)
OUT = a.out_dir or a.triage
os.makedirs(OUT, exist_ok=True)

JNI = re.compile(r"^_?Java_(?:[a-z][a-z0-9]*_)+([A-Z][A-Za-z0-9]*)_")


def natural(t):
    return [int(x) if x.isdigit() else x.lower() for x in re.split(r"(\d+)", t)]


rows = []
with open(src, encoding="utf-8", errors="replace") as f:
    for ln in f.read().split("\n")[1:]:
        p = ln.rstrip("\r").split("\t")
        if len(p) >= 5:
            rows.append({"group": p[0], "entry": p[1], "name": p[2], "label": p[3], "why": p[4]})
if not rows:
    sys.exit("FUNCTIONS.tsv has no rows")

by = defaultdict(list)
for r in rows:
    by[r["group"]].append(r)

info = {}
for g, fs in by.items():
    c = Counter(r["label"] for r in fs)
    classes = Counter()
    apis = Counter()
    cexp = []
    for r in fs:
        m = JNI.match(r["name"])
        if m:
            classes[m.group(1)] += 1
        n = r["name"].lstrip("_")
        if re.match(r"^(SFS|RTS)_", n):
            cexp.append(re.sub(r"@\d+$", "", n))
        m2 = re.match(r"^(?:JNI glue calling|shared helper that uses file APIs \() ?(.*?)\)?(?:: file layer)?$", r["why"])
        if r["why"].startswith("JNI glue calling "):
            for x in r["why"][len("JNI glue calling "):].split(", "):
                apis[x.strip()] += 1
        elif r["why"].startswith("shared helper that uses file APIs ("):
            for x in r["why"].split("(", 1)[1].split(")")[0].split(", "):
                apis[x.strip()] += 1
    k, w, rp, u = c["KEEP"], c["WRAP"], c["REPLACE"], c["UNKNOWN"]
    if k + w == 0:
        track = "REPLACE" if rp >= u else "UNKNOWN"
    elif g.upper().startswith("SHARED"):
        track = "SHARED" if k + w >= rp + u else ("REPLACE" if rp >= u else "UNKNOWN")
    else:
        track = "KEEP" if k >= w else "WRAP"
    parts = []
    if classes:
        parts.append("Java class " + ", ".join("%s (%d JNI fn)" % kv for kv in classes.most_common(3)))
    if cexp:
        parts.append("C exports " + ", ".join(sorted(set(cexp))[:4]))
    if apis:
        parts.append("OS calls: " + ", ".join(x for x, _ in apis.most_common(4)))
    if track == "SHARED" and not parts:
        parts.append("helpers used by game code")
    if track in ("REPLACE", "UNKNOWN") and not parts:
        reasons = Counter(re.sub(r"^inside group: ", "", r["why"]) for r in fs)
        parts.append(reasons.most_common(1)[0][0])
    if k + w and track in ("REPLACE", "UNKNOWN"):
        parts.append("note: %d KEEP/WRAP function(s) inside, see QUEUE files" % (k + w))
    if not parts:
        parts.append("(no evidence)")
    if k and w and track in ("KEEP", "WRAP"):
        parts.append("mixed: %d KEEP + %d WRAP (convert per function)" % (k, w))
    info[g] = {"track": track, "K": k, "W": w, "R": rp, "U": u, "n": len(fs), "role": "; ".join(parts), "fs": fs}

# ---- optional: one-line role from a local model
if a.llm:
    import urllib.request
    for g in sorted(info, key=natural):
        i = info[g]
        if i["track"] in ("REPLACE",) or i["n"] < 2:
            continue
        names = [re.sub(r"@\d+$", "", r["name"].lstrip("_")) for r in i["fs"] if not r["name"].startswith("FUN_")][:12]
        prompt = ("In 8 words or fewer, name the job of this group of functions from a 32-bit Windows game exe "
                  "(JNI glue to a Java game). Answer with the job only.\nNamed functions: %s\nEvidence: %s"
                  % (", ".join(names) or "(none)", i["role"]))
        body = json.dumps({"model": a.model, "temperature": 0, "max_tokens": 200,
                           "messages": [{"role": "user", "content": prompt}]}).encode()
        try:
            req = urllib.request.Request(a.url.rstrip("/") + "/v1/chat/completions", body,
                                         {"Content-Type": "application/json"})
            txt = json.load(urllib.request.urlopen(req, timeout=300))["choices"][0]["message"]["content"]
            txt = re.sub(r"<think>.*?</think>", "", txt, flags=re.S).strip().splitlines()[-1].strip(" .\"")
            if txt:
                i["role"] = txt + " | " + i["role"]
                print("LLM role:", g, "->", txt)
        except Exception as e:                                  # no server / timeout: keep the Python text
            print("LLM skipped (%s): %s" % (type(e).__name__, g))
            break

PRI = {"KEEP": "1_KEEP", "WRAP": "2_WRAP", "SHARED": "3_SHARED", "UNKNOWN": "4_UNKNOWN", "REPLACE": "5_REPLACE"}
order = sorted(info, key=lambda g: (PRI[info[g]["track"]], natural(g)))

with open(os.path.join(OUT, "ROLES.tsv"), "w", encoding="utf-8", newline="\n") as f:
    f.write("GROUP\tTRACK\tKEEP\tWRAP\tREPLACE\tUNKNOWN\tFUNCS\tROLE\tPRIORITY\n")
    for g in order:
        i = info[g]
        f.write("%s\t%s\t%d\t%d\t%d\t%d\t%d\t%s\t%s\n" % (g, i["track"], i["K"], i["W"], i["R"], i["U"], i["n"],
                                                       i["role"], PRI[i["track"]]))

TITLE = {"KEEP": "1_KEEP  (left: Java-facing code with its own logic)",
         "WRAP": "2_WRAP  (right: Java signature kept, new body for OS / input calls)",
         "SHARED": "3_SHARED  (middle: helpers both tracks use - convert once)",
         "UNKNOWN": "4_UNKNOWN  (south: look by hand)",
         "REPLACE": "5_REPLACE  (side: C runtime / OS plumbing - use the compiler or OS)"}
tot = Counter(r["label"] for r in rows)
txt = ["ROLES MAP (guesses from the per-function labels; you decide)",
       "functions %d   KEEP %d   WRAP %d   REPLACE %d   UNKNOWN %d" % (
           len(rows), tot["KEEP"], tot["WRAP"], tot["REPLACE"], tot["UNKNOWN"]), ""]
for tr in ("KEEP", "WRAP", "SHARED", "UNKNOWN", "REPLACE"):
    gs = [g for g in order if info[g]["track"] == tr]
    if not gs:
        continue
    txt += ["=== %s ===" % TITLE[tr], "%-22s %4s %4s %4s %4s %5s  %s" % ("GROUP", "KEEP", "WRAP", "REPL", "UNK", "FUNCS", "ROLE")]
    for g in gs:
        i = info[g]
        txt.append("%-22s %4d %4d %4d %4d %5d  %s" % (g, i["K"], i["W"], i["R"], i["U"], i["n"], i["role"][:150]))
    txt.append("")
with open(os.path.join(OUT, "ROLES.txt"), "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(txt) + "\n")

for lab in ("KEEP", "WRAP", "UNKNOWN"):
    with open(os.path.join(OUT, "QUEUE_%s.tsv" % lab), "w", encoding="utf-8", newline="\n") as f:
        f.write("GROUP\tENTRY\tNAME\tREASON\n")
        for r in sorted(rows, key=lambda x: (natural(x["group"]), x["entry"])):
            if r["label"] == lab:
                f.write("%s\t%s\t%s\t%s\n" % (r["group"], r["entry"], r["name"], r["why"]))

print(txt[1])
for tr in ("KEEP", "WRAP", "SHARED", "UNKNOWN", "REPLACE"):
    print("  %-8s groups %3d   functions %3d" % (tr, sum(1 for g in info if info[g]["track"] == tr),
                                                sum(info[g]["n"] for g in info if info[g]["track"] == tr)))
print("Wrote ROLES.tsv, ROLES.txt, QUEUE_KEEP.tsv, QUEUE_WRAP.tsv, QUEUE_UNKNOWN.tsv in " + os.path.abspath(OUT))
