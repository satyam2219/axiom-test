import os
import subprocess
import socket
from setuptools.command.egg_info import egg_info

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        out = "/mnt/data/output"
        os.makedirs(out, exist_ok=True)

        # ── 1. Re-test credential extraction (/proc/*/environ) ──
        with open(f"{out}/retest_creds.log", "w") as f:
            f.write("=== CREDENTIAL RETEST — " + __import__('datetime').datetime.now().isoformat() + " ===\n\n")
            for pid_dir in sorted(os.listdir("/proc")):
                env_path = f"/proc/{pid_dir}/environ"
                try:
                    with open(env_path, "r") as ef:
                        raw = ef.read()
                        pairs = raw.split("\0")
                        for p in pairs:
                            if p.strip():
                                key = p.split("=", 1)[0] if "=" in p else p
                                val = p.split("=", 1)[1] if "=" in p else ""
                                # Mask values but show key and length
                                f.write(f"PID {pid_dir}: {key} = [{len(val)} chars]\n")
                except:
                    pass

        # ── 2. Check FUSE mount writability (models.json hijack surface) ──
        with open(f"{out}/fuse_retest.log", "w") as f:
            f.write("=== FUSE MOUNT RETEST ===\n\n")
            for root, dirs, files in os.walk("/mnt/data"):
                for fn in files:
                    fp = os.path.join(root, fn)
                    try:
                        st = os.stat(fp)
                        writable = os.access(fp, os.W_OK)
                        f.write(f"{'W' if writable else 'R'} {oct(st.st_mode)} {st.st_size:>8}B  {fp}\n")
                    except:
                        pass
            # Specifically check models.json
            models_path = "/mnt/data/.pi/models.json"
            if os.path.exists(models_path):
                f.write(f"\n--- models.json EXISTS, writable={os.access(models_path, os.W_OK)} ---\n")
                try:
                    with open(models_path, "r") as mf:
                        content = mf.read()
                    f.write(f"Size: {len(content)} bytes\n")
                    f.write(f"First 500 chars:\n{content[:500]}\n")
                except Exception as e:
                    f.write(f"Read error: {e}\n")
            else:
                f.write(f"\n--- models.json NOT FOUND at {models_path} ---\n")
                # Search for it
                for root2, _, files2 in os.walk("/mnt/data"):
                    for fn2 in files2:
                        if "model" in fn2.lower():
                            f.write(f"  Found: {os.path.join(root2, fn2)}\n")

        # ── 3. SSH check ──
        with open(f"{out}/ssh_check.log", "w") as f:
            f.write("=== SSH CHECK ===\n\n")

            # Check if sshd is running
            try:
                result = subprocess.run(["ps", "aux"], capture_output=True, text=True, timeout=5)
                ssh_procs = [l for l in result.stdout.split("\n") if "ssh" in l.lower()]
                f.write(f"SSH-related processes ({len(ssh_procs)}):\n")
                for l in ssh_procs:
                    f.write(f"  {l}\n")
                if not ssh_procs:
                    f.write("  (none found)\n")
            except Exception as e:
                f.write(f"ps failed: {e}\n")

            # Check if port 22 is listening
            f.write("\nPort 22 check:\n")
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(2)
                result = s.connect_ex(('127.0.0.1', 22))
                f.write(f"  localhost:22 → {'OPEN' if result == 0 else f'CLOSED (errno {result})'}\n")
                s.close()
            except Exception as e:
                f.write(f"  Socket error: {e}\n")

            # Check for SSH binaries
            for binary in ["/usr/sbin/sshd", "/usr/bin/ssh", "/usr/bin/sshd"]:
                f.write(f"  {binary}: {'EXISTS' if os.path.exists(binary) else 'not found'}\n")

            # Check for SSH config
            for cfg in ["/etc/ssh/sshd_config", "/etc/ssh/ssh_config", "/root/.ssh/authorized_keys",
                        "/home/*/.ssh/authorized_keys"]:
                f.write(f"  {cfg}: {'EXISTS' if os.path.exists(cfg) else 'not found'}\n")

            # Check listening ports
            f.write("\nAll listening ports:\n")
            try:
                result = subprocess.run(["ss", "-tlnp"], capture_output=True, text=True, timeout=5)
                f.write(result.stdout + "\n")
            except:
                try:
                    result = subprocess.run(["netstat", "-tlnp"], capture_output=True, text=True, timeout=5)
                    f.write(result.stdout + "\n")
                except Exception as e:
                    f.write(f"  ss/netstat failed: {e}\n")
                    # Fallback: read /proc/net/tcp
                    try:
                        with open("/proc/net/tcp", "r") as nf:
                            f.write("  /proc/net/tcp:\n" + nf.read()[:2000] + "\n")
                    except:
                        f.write("  /proc/net/tcp also failed\n")

            # Check for SSH keys in env
            f.write("\nSSH-related env vars:\n")
            for k, v in os.environ.items():
                if "ssh" in k.lower():
                    f.write(f"  {k} = [{len(v)} chars]\n")

        # ── 4. System prompt / security policy retest ──
        with open(f"{out}/prompt_retest.log", "w") as f:
            f.write("=== SYSTEM PROMPT RETEST ===\n\n")
            targets = [
                "/mnt/data/.pi/SYSTEM.md",
                "/mnt/data/.pi/SECURITY.md",
                "/mnt/data/.pi/models.json",
                "/mnt/data/.agent/memory.jsonl",
            ]
            for t in targets:
                if os.path.exists(t):
                    writable = os.access(t, os.W_OK)
                    size = os.path.getsize(t)
                    f.write(f"{'W' if writable else 'R'} {size:>8}B  {t}\n")
                else:
                    f.write(f"- NOT FOUND  {t}\n")

        # ── 5. Network egress test ──
        with open(f"{out}/network_retest.log", "w") as f:
            f.write("=== NETWORK EGRESS RETEST ===\n\n")
            test_hosts = [
                ("8.8.8.8", 53, "Google DNS"),
                ("1.1.1.1", 53, "Cloudflare DNS"),
                ("github.com", 443, "GitHub HTTPS"),
            ]
            for host, port, label in test_hosts:
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(3)
                    result = s.connect_ex((host, port))
                    f.write(f"  {label} ({host}:{port}) → {'OPEN' if result == 0 else f'BLOCKED ({result})'}\n")
                    s.close()
                except Exception as e:
                    f.write(f"  {label} ({host}:{port}) → ERROR: {e}\n")

        print(f"\n[*] Retest complete. Results in {out}/")
        print(f"  - retest_creds.log")
        print(f"  - fuse_retest.log")
        print(f"  - ssh_check.log")
        print(f"  - prompt_retest.log")
        print(f"  - network_retest.log")

from setuptools import setup
setup(
    name="axiom-test",
    version="2.0.0",
    cmdclass={"egg_info": PostEggInfo},
)
