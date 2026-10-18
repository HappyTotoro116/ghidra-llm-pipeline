# Copyright 2026 Ryu116
# Licensed under the Apache License, Version 2.0
# http://www.apache.org/licenses/LICENSE-2.0

r"""analyze_out.py - token reports for the OUT folder made by make_full_lite.py (read-only).
Run:  python .\analyze_out.py --out-dir "D:\...\OUT"
Reads OUT\FULL, OUT\LITE_AC, OUT\LITE_A, OUT\LITE_C (and an old OUT\LITE if present), writes into OUT\Reports:
  Token_<NAME>_by_name.txt   Token_<NAME>_by_tokens.txt   (one pair per folder, 8 files)
Each report lists every folder, then the files under it, with CHARS, LINES, EST.TOKENS and
how many requests each model needs. Options: --model NAME=CONTEXT (repeat), --prompt-tokens,
--out-ratio, --many-files, --reports-dir."""
import argparse, math, os, re, sys

ap = argparse.ArgumentParser()
ap.add_argument("--out-dir", required=True, help="the OUT folder (has FULL, LITE_AC, LITE_A, LITE_C inside)")
ap.add_argument("--reports-dir", default=None, help="default: <out-dir>\\Reports")
ap.add_argument("--chars-per-token", type=float, default=3.2)
ap.add_argument("--model", action="append", metavar="NAME=CONTEXT")
ap.add_argument("--prompt-tokens", type=int, default=2000)
ap.add_argument("--out-ratio", type=float, default=1.0)
ap.add_argument("--many-files", type=int, default=100000,
                help="folders with this many direct files are shown as loose per-file rows")
a = ap.parse_args()
cpt = a.chars_per_token
REPORTS = a.reports_dir or os.path.join(a.out_dir, "Reports")

models = []
for m in (a.model or ["qwen2.5-coder=32768", "qwen3.5=262144"]):
    name, _, ctx = m.partition("=")
    try:
        ctx = int(ctx)
    except ValueError:
        sys.exit("Bad --model (use NAME=CONTEXT): " + m)
    usable = int((ctx - a.prompt_tokens) / (1.0 + a.out_ratio))
    if usable <= 0:
        sys.exit("Context too small for the prompt: " + m)
    models.append({"name": name, "ctx": ctx, "budget": usable})


def natural(name):
    return [int(t) if t.isdigit() else t.lower() for t in re.split(r"(\d+)", name)]


def stat(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        t = f.read()
    return len(t), t.count("\n"), int(math.ceil(len(t) / cpt))


def req_file(tokens, budget):
    return max(1, int(math.ceil(tokens / float(budget))))


def req_unit(files, budget):
    """Pack the files of one folder, in order, into as few requests as fit."""
    reqs, cur = 0, 0
    for _, _, _, t in sorted(files, key=lambda x: natural(x[0])):
        if t > budget:
            if cur:
                reqs += 1
                cur = 0
            reqs += req_file(t, budget)
        elif cur + t > budget:
            reqs += 1
            cur = t
        else:
            cur += t
    return reqs + (1 if cur else 0)




def analyze(root, tag):
    units = {}
    for dp, dn, fn in os.walk(root):
        if not fn:
            continue
        rel = os.path.relpath(dp, root)
        if len(fn) >= a.many_files:
            for f in fn:
                units[os.path.join(rel, f)] = (True, [(f,) + stat(os.path.join(dp, f))])
        else:
            units[rel] = (False, [(f,) + stat(os.path.join(dp, f)) for f in fn])
    rows = []
    for name, (loose, files) in units.items():
        tok = sum(x[3] for x in files)
        rows.append({"name": name, "loose": loose, "files": files,
                     "chars": sum(x[1] for x in files), "lines": sum(x[2] for x in files), "tok": tok,
                     "req": [req_unit(files, m["budget"]) for m in models]})
    nfold = len(rows)
    nfiles = sum(len(r["files"]) for r in rows)
    tot = sum(r["tok"] for r in rows)
    chars = sum(r["chars"] for r in rows)
    lines = sum(r["lines"] for r in rows)
    SUMMARY = ["TOKEN REPORT - %s  (estimate: 1 token per %.1f chars)" % (tag, cpt),
               "Root: " + root,
               "Usable input = (context - {:,} prompt) / (1 + {:g} reply ratio)".format(a.prompt_tokens, a.out_ratio), ""]
    over_by_model = []
    for i, m in enumerate(models):
        over = [(r, x) for r in rows for x in r["files"] if x[3] > m["budget"]]
        over_by_model.append(over)
        SUMMARY.append("%-16s context %8s  usable %8s  ->  %6s requests,  files too big for one request: %d" % (
            m["name"][:16], "{:,}".format(m["ctx"]), "{:,}".format(m["budget"]),
            "{:,}".format(sum(r["req"][i] for r in rows)), len(over)))
    SUMMARY.append("")
    W = 150
    EQ, DASH = "=" * W, "-" * W
    COLS = "%6s %12s %9s %12s" + " %9s" * len(models) + "   %s"
    HEAD = "    " + COLS % tuple(["FILES", "CHARS", "LINES", "EST.TOKENS"] + ["REQ " + m["name"][:5] for m in models] + ["FOLDER / FILE"])

    def nums(files, chars_, lines_, tok, reqs, label, prefix):
        return prefix + COLS % tuple([files, "{:,}".format(chars_), "{:,}".format(lines_), "~{:,}".format(tok)] + list(reqs) + [label])

    totals = [EQ, "TOTALS",
              nums("{:,}".format(nfiles), chars, lines, tot,
                   ["{:,}".format(sum(r["req"][i] for r in rows)) for i in range(len(models))],
                   "(folders/units: {:,}, files: {:,})".format(nfold, nfiles), "    "), EQ]

    def report(fname, title, unit_key, file_key, extra=()):
        out = SUMMARY + [EQ, title, HEAD, EQ]
        for r in sorted(rows, key=unit_key):
            out.append(nums(len(r["files"]), r["chars"], r["lines"], r["tok"], r["req"], r["name"], "--- "))
            if not r["loose"]:
                out.append("")
                for k, x in enumerate(sorted(r["files"], key=file_key), 1):
                    out.append(nums(k, x[1], x[2], x[3], [req_file(x[3], m["budget"]) for m in models], x[0], "  > "))
            out.append(DASH)
        out += totals + list(extra)
        with open(os.path.join(REPORTS, fname), "w", encoding="utf-8", newline="\n") as f:
            f.write("\n".join(out) + "\n")

    extra = []
    for m, over in zip(models, over_by_model):
        if over:
            extra += ["", "FILES TOO BIG FOR ONE REQUEST OF %s (usable %s)" % (m["name"], "{:,}".format(m["budget"]))]
            extra += ["%12s   %s\\%s" % ("~{:,}".format(x[3]), r["name"], x[0])
                      for r, x in sorted(over, key=lambda p: -p[1][3])[:200]]
            if len(over) > 200:
                extra.append("   (+%d more)" % len(over))
    report("Token_%s_by_name.txt" % tag, "%s: FOLDERS A-Z; FILES INSIDE A-Z" % tag,
           lambda r: natural(r["name"]), lambda x: natural(x[0]))
    report("Token_%s_by_tokens.txt" % tag, "%s: FOLDERS LARGEST FIRST; FILES INSIDE LARGEST FIRST" % tag,
           lambda r: -r["tok"], lambda x: -x[3], extra)
    print("\n".join(SUMMARY))
    print("  %s: %d folders/units, %d files, ~%s tokens" % (tag, nfold, nfiles, "{:,}".format(tot)))
    print("")


os.makedirs(REPORTS, exist_ok=True)
done = 0
for tag in ("FULL", "LITE_AC", "LITE_A", "LITE_C", "LITE"):
    p = os.path.join(a.out_dir, tag)
    if os.path.isdir(p):
        analyze(p, tag)
        done += 1
if not done:
    sys.exit("No FULL / LITE_AC / LITE_A / LITE_C folder inside: " + a.out_dir)
print("Reports written to " + os.path.abspath(REPORTS))
