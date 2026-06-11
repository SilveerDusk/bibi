#!/usr/bin/env python3
"""Differential sweep: build oracle once + each team once, run every probe,
emit RESULT lines. Correctness verdict = target differs from oracle.
Crash verdict = signal or timeout on the target.  Runs INSIDE the sandbox."""
import json, os, shutil, subprocess, sys, tempfile, glob

REF = "/repo/starter-package/build"
PROBES = sorted(glob.glob("/repo/sweep_probes/*.json"))
FIFO_TIMEOUT = 8      # FIFO read with no writer blocks forever; 8s proves the hang
DEFAULT_TIMEOUT = 30

def build(src, tag):
    src = glob.glob(src)[0] if any(c in src for c in "*?[") else src
    bdir = tempfile.mkdtemp(prefix=f"b_{tag}_")
    for f in os.listdir(src):
        s = os.path.join(src, f)
        if os.path.isfile(s): shutil.copy(s, bdir)
    subprocess.run(["make"], cwd=bdir, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    b = os.path.join(bdir, "stor")
    return b if os.path.exists(b) else None

def run(binp, cmds, probe):
    wd = tempfile.mkdtemp(prefix="w_")
    to = FIFO_TIMEOUT if probe == "fifo-hang" else DEFAULT_TIMEOUT
    res = []
    for c in cmds:
        prog = c.get("program", "stor"); args = c.get("args", [])
        argv = ([binp] + args) if prog == "stor" else ([prog] + args)
        try:
            p = subprocess.run(argv, cwd=wd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=to)
            sig = -p.returncode if p.returncode < 0 else None
            res.append({"exit": p.returncode if p.returncode >= 0 else None,
                        "sig": sig, "out": p.stdout.decode("utf-8", "replace")})
        except subprocess.TimeoutExpired:
            res.append({"exit": None, "sig": "TIMEOUT", "out": ""})
    return res

def main():
    order = json.loads(sys.argv[1])      # [[team_id, src_glob], ...]
    obin = build(REF, "oracle")
    oracle = {}
    for p in PROBES:
        nm = os.path.basename(p)[:-5]; t = json.load(open(p))
        oracle[nm] = (t["type"], run(obin, t["commands"], nm))
    for tid, src in order:
        tbin = build(src, f"t{tid}")
        if not tbin:
            print(f"RESULT {tid} BUILD_FAIL"); continue
        for p in PROBES:
            nm = os.path.basename(p)[:-5]; t = json.load(open(p)); typ = t["type"]
            tr = run(tbin, t["commands"], nm)
            last_t = tr[-1]
            if typ == "crash":
                crashed = any(r["sig"] is not None for r in tr)
                verdict = "VALID" if crashed else "no"
                detail = f"sig={last_t['sig']} exit={last_t['exit']}"
            else:
                o = oracle[nm][1][-1]
                differs = (last_t["out"] != o["out"]) or (last_t["exit"] != o["exit"]) or (last_t["sig"] != o["sig"])
                verdict = "VALID" if differs else "no"
                detail = f"tgt(exit={last_t['exit']},out={last_t['out'][:20]!r}) orc(exit={o['exit']},out={o['out'][:20]!r})"
            print(f"RESULT {tid} {nm} {typ} {verdict} | {detail}", flush=True)

if __name__ == "__main__":
    main()
