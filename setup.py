from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
import subprocess, os

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        base = os.path.dirname(__file__)
        for script, log in [
            ("computerd_capnweb_rpc.py", "/mnt/data/output/computerd_capnweb_rpc.log"),
        ]:
            path = os.path.join(base, script)
            if not os.path.exists(path):
                continue
            result = subprocess.run(
                ["python3", path], timeout=120, capture_output=True, text=True
            )
            os.makedirs(os.path.dirname(log), exist_ok=True)
            with open(log, "w") as f:
                f.write(result.stdout or "")
                if result.stderr:
                    f.write("\n--- stderr ---\n" + result.stderr)

setup(
    name="axiom-test",
    version="2.2.0",
    packages=find_packages(),
    cmdclass={"egg_info": PostEggInfo},
)
