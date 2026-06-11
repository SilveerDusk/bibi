#!/usr/bin/env python3
"""
break_runner.py — local grader emulator for Break-It (run INSIDE the sandbox).

Builds a target's stor from its source dir, optionally the reference oracle,
seeds a fresh workdir with a starting enc.db, replays a test.json's commands,
and reports stdout/exit per command. For correctness tests it also runs the
reference oracle and flags whether target output DIFFERS (=> break is valid).

Usage (inside container, repo mounted at /repo):
  python3 /repo/build/break_runner.py \
      --target-src /repo/break-it-code/SMK-112/source/*/build \
      --seed-db    /repo/break-it-code/SMK-112/enc.db \
      --test       /repo/break_drafts/SMK-112/correctness-reregister-allowed/test.json

  --oracle-src defaults to /repo/starter-package/build (the reference).
  --no-oracle  skips the oracle comparison.
  --seed-db    optional; if omitted the workdir starts with no enc.db.
"""
import argparse, json, os, shutil, subprocess, sys, tempfile, glob

REF_DEFAULT = "/repo/starter-package/build"

def build(src_dir, tag):
    src_dir = glob.glob(src_dir)[0] if any(c in src_dir for c in "*?[") else src_dir
    bdir = tempfile.mkdtemp(prefix=f"build_{tag}_")
    for f in os.listdir(src_dir):
        s = os.path.join(src_dir, f)
        if os.path.isfile(s):
            shutil.copy(s, bdir)
    r = subprocess.run(["make"], cwd=bdir, stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE, universal_newlines=True)
    binp = os.path.join(bdir, "stor")
    if not os.path.exists(binp):
        print(f"[BUILD FAIL {tag}]\n{r.stdout}\n{r.stderr}", file=sys.stderr)
        sys.exit(2)
    return bdir, binp

def run_cmds(binp, commands, seed_db):
    """Run command sequence in a fresh workdir; return list of {stdout,exit,signal}."""
    wd = tempfile.mkdtemp(prefix="work_")
    if seed_db and os.path.exists(seed_db):
        shutil.copy(seed_db, os.path.join(wd, "enc.db"))
    results = []
    for cmd in commands:
        prog = cmd.get("program", "stor")
        args = cmd.get("args", [])
        stdin = cmd.get("stdin", None)
        argv = ([binp] + args) if prog == "stor" else ([prog] + args)
        try:
            p = subprocess.run(argv, cwd=wd,
                               input=stdin.encode() if stdin is not None else None,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               timeout=60)
            sig = -p.returncode if p.returncode < 0 else None
            results.append({"stdout": p.stdout.decode("utf-8", "replace"),
                            "exit": p.returncode if p.returncode >= 0 else None,
                            "signal": sig})
        except subprocess.TimeoutExpired:
            results.append({"stdout": "", "exit": None, "signal": "TIMEOUT>60s"})
    return wd, results

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target-src", required=True)
    ap.add_argument("--oracle-src", default=REF_DEFAULT)
    ap.add_argument("--seed-db", default=None)
    ap.add_argument("--test", required=True)
    ap.add_argument("--no-oracle", action="store_true")
    a = ap.parse_args()

    test = json.load(open(a.test))
    cmds = test["commands"]
    ttype = test.get("type", "?")
    print(f"# test: {a.test}\n# type: {ttype}  target_team: {test.get('target_team')}")

    _, tbin = build(a.target_src, "target")
    _, tres = run_cmds(tbin, cmds, a.seed_db)

    ores = None
    if not a.no_oracle and ttype == "correctness":
        _, obin = build(a.oracle_src, "oracle")
        _, ores = run_cmds(obin, cmds, a.seed_db)

    differs_any = False
    crashed_any = False
    for i, cmd in enumerate(cmds):
        t = tres[i]
        line = f"[{i}] {cmd.get('program','stor')} {' '.join(cmd.get('args',[]))}"
        if cmd.get("stdin") is not None:
            line += f"   (stdin {len(cmd['stdin'])}B)"
        print(line)
        print(f"    target: exit={t['exit']} signal={t['signal']} stdout={t['stdout']!r}")
        if t["signal"] not in (None,):
            crashed_any = True
        if ores is not None:
            o = ores[i]
            print(f"    oracle: exit={o['exit']} signal={o['signal']} stdout={o['stdout']!r}")
            d = (t["stdout"] != o["stdout"]) or (t["exit"] != o["exit"]) or (t["signal"] != o["signal"])
            dt = (t["stdout"].rstrip("\n") != o["stdout"].rstrip("\n")) or (t["exit"] != o["exit"])
            print(f"    DIFFERS(exact)={d}  DIFFERS(stdout-trimmed)={dt}")
            differs_any = differs_any or d
        exp = test.get("expected")
        if exp and i < len(exp):
            print(f"    expected(declared): {exp[i]}")

    print("\n# VERDICT")
    if ttype == "crash":
        print(f"  crash break: {'VALID (signal/timeout observed)' if crashed_any else 'NOT triggered'}")
    elif ttype == "correctness" and ores is not None:
        print(f"  correctness break: {'VALID (target differs from oracle)' if differs_any else 'INVALID (outputs match)'}")
    else:
        print(f"  type={ttype}: inspect target results above "
              f"(integrity/confidentiality/security need the real key / marker check).")

if __name__ == "__main__":
    main()
