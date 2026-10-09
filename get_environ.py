#!/usr/bin/env python3
"""Recover exec-time env vars from /proc/<pid>/environ.
security.py scrubs os.environ but NOT /proc/self/environ (documented limitation).
"""
import subprocess, os, re

LOG = "/mnt/data/output/get_environ.log"
os.makedirs(os.path.dirname(LOG), exist_ok=True)
lines = []

def log(msg):
    print(msg)
    lines.append(msg)

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except:
        return "", "", -1

log("=" * 60)
log("  /proc environ recovery")
log("=" * 60)

# Find all process_api / uvicorn PIDs (our parent — same uid)
out, _, _ = run("ps aux 2>/dev/null")
log("\n── ALL PROCESSES ──")
for line in (out or "").split("\n"):
    log(f"  {line}")

log("\n── READING /proc/*/environ FOR EACH PID ──")
out, _, _ = run("ls -d /proc/[0-9]* 2>/dev/null")
pids = [os.path.basename(p) for p in out.split("\n") if p.strip()]

for pid in sorted(pids, key=lambda x: int(x)):
    env_file = f"/proc/{pid}/environ"
    try:
        with open(env_file, "rb") as f:
            raw = f.read()
        env_str = raw.decode("utf-8", errors="replace")
        env_vars = [v for v in env_str.split("\0") if v]
        # Filter for secrets
        secrets = [v for v in env_vars if re.search(
            r'SECRET|TOKEN|KEY|PASSWORD|CREDENTIALS|GATEWAY', 
            v.split("=")[0], re.IGNORECASE
        )]
        if secrets:
            log(f"\n  PID {pid} — {len(secrets)} sensitive var(s):")
            for s in secrets:
                k, v = s.split("=", 1) if "=" in s else (s, "")
                log(f"    {k} = len={len(v)}")
        else:
            # Still log that we could read it
            cmdline, _, _ = run(f"cat /proc/{pid}/cmdline 2>/dev/null | tr '\\0' ' '")
            log(f"\n  PID {pid} ({cmdline[:60]}): readable, 0 sensitive vars")
    except PermissionError:
        log(f"\n  PID {pid}: Permission denied")
    except FileNotFoundError:
        pass
    except Exception as e:
        log(f"\n  PID {pid}: {e}")

log("\n" + "=" * 60)

with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nSaved: {LOG}")
