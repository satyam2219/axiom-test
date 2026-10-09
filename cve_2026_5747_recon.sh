#!/usr/bin/env bash
# CVE-2026-5747 Prerequisite Recon — run inside the sandbox container as appuser
# Non-destructive: read-only checks only
set -euo pipefail

echo "=== CVE-2026-5747 Prerequisite Assessment ==="
echo "Date: $(date -u)"
echo ""

# ─── 1. Transport type (PCI vs MMIO) ───
echo "── 1. VIRTIO TRANSPORT TYPE ──"
echo "CVE-2026-5747 requires PCI transport. Firecracker defaults to MMIO."
echo ""

echo "[1a] PCI bus (/sys/bus/pci):"
if [ -d /sys/bus/pci/devices ] && [ "$(ls -A /sys/bus/pci/devices 2>/dev/null)" ]; then
    echo "  FOUND — PCI devices present (CVE may apply)"
    ls -la /sys/bus/pci/devices/ 2>/dev/null || true
else
    echo "  NOT FOUND — no PCI bus or empty → MMIO transport → CVE BLOCKED"
fi
echo ""

echo "[1b] Virtio MMIO (/sys/bus/virtio):"
ls -la /sys/bus/virtio/devices/ 2>/dev/null && echo "  Virtio devices found" || echo "  No virtio bus"
echo ""

echo "[1c] /proc/iomem virtio regions:"
cat /proc/iomem 2>/dev/null | grep -i virtio || echo "  Cannot read /proc/iomem or no virtio entries"
echo ""

echo "[1d] lspci (if available):"
lspci 2>/dev/null || echo "  lspci not installed"
echo ""

# ─── 2. Current UID / root escalation ───
echo "── 2. PRIVILEGE LEVEL ──"
echo "CVE-2026-5747 requires guest root."
echo ""

echo "[2a] Current user:"
id
echo ""

echo "[2b] Setuid binaries in PATH:"
find /usr/bin /usr/sbin /usr/local/bin /bin /sbin -perm -4000 -type f 2>/dev/null | head -20 || echo "  None found"
echo ""

echo "[2c] Capabilities on current process:"
cat /proc/self/status | grep -i cap 2>/dev/null || echo "  Cannot read"
echo ""

echo "[2d] Can we write /etc/passwd?"
if [ -w /etc/passwd ]; then
    echo "  YES — /etc/passwd is writable! Root escalation possible"
else
    echo "  NO — /etc/passwd not writable"
fi
echo ""

echo "[2e] sudo available?"
sudo -l 2>/dev/null || echo "  sudo not available or not configured"
echo ""

echo "[2f] Writable cron dirs:"
for d in /etc/cron.d /etc/cron.daily /var/spool/cron /var/spool/cron/crontabs; do
    if [ -w "$d" ] 2>/dev/null; then
        echo "  WRITABLE: $d"
    fi
done
echo "  (check complete)"
echo ""

# ─── 3. Firecracker VMM version ───
echo "── 3. FIRECRACKER VERSION ──"
echo ""

echo "[3a] /proc/cpuinfo hypervisor:"
grep -i "hypervisor\|model name\|vendor_id" /proc/cpuinfo 2>/dev/null | head -5 || echo "  Cannot read"
echo ""

echo "[3b] DMI/SMBIOS:"
cat /sys/class/dmi/id/product_name 2>/dev/null || echo "  Not available"
cat /sys/class/dmi/id/sys_vendor 2>/dev/null || echo "  Vendor not available"
cat /sys/class/dmi/id/bios_version 2>/dev/null || echo "  BIOS version not available"
echo ""

echo "[3c] ACPI tables (may reveal FC version):"
cat /sys/firmware/acpi/tables/FACP 2>/dev/null | strings | head -10 || echo "  No ACPI tables"
echo ""

echo "[3d] Kernel cmdline (FC passes boot params):"
cat /proc/cmdline 2>/dev/null || echo "  Cannot read"
echo ""

echo "[3e] Device tree (if MMIO):"
ls /proc/device-tree/ 2>/dev/null || echo "  No device tree"
echo ""

echo "[3f] Kernel version:"
uname -a 2>/dev/null || echo "  Cannot read"
echo ""

# ─── 4. Seccomp status ───
echo "── 4. SECCOMP STATUS ──"
echo ""

echo "[4a] /proc/self/status seccomp:"
grep -i seccomp /proc/self/status 2>/dev/null || echo "  Not in status"
echo ""

echo "[4b] Total syscall filter count:"
cat /proc/sys/kernel/seccomp/actions_avail 2>/dev/null || echo "  Not available"
echo ""

# ─── 5. Computerd RPC secret (from /proc/self/environ) ───
echo "── 5. COMPUTERD ROOT-PROCESS ACCESS ──"
echo ""

echo "[5a] RPC_CLIENT_SECRET in /proc/self/environ:"
if tr '\0' '\n' < /proc/self/environ 2>/dev/null | grep -q "RPC_CLIENT_SECRET"; then
    echo "  FOUND — can authenticate to computerd (root process) on :8080"
    echo "  (value redacted)"
else
    echo "  NOT FOUND in exec-time env"
fi
echo ""

echo "[5b] Computerd process (running as root):"
ps aux 2>/dev/null | grep -i computerd | grep -v grep || echo "  Cannot see computerd process"
echo ""

echo "[5c] Computerd health check:"
curl -sf http://127.0.0.1:8080/health 2>/dev/null && echo "  Computerd healthy on :8080" || echo "  Not reachable or not healthy"
echo ""

# ─── 6. Kernel modules / device access ───
echo "── 6. KERNEL/DEVICE ACCESS ──"
echo ""

echo "[6a] /dev/kvm:"
ls -la /dev/kvm 2>/dev/null || echo "  Not present"
echo ""

echo "[6b] /dev/vhost-net:"
ls -la /dev/vhost-net 2>/dev/null || echo "  Not present"
echo ""

echo "[6c] /dev/mem:"
ls -la /dev/mem 2>/dev/null || echo "  Not present"
echo ""

echo "[6d] Can load kernel modules?"
ls /lib/modules/ 2>/dev/null || echo "  No kernel modules dir"
echo ""

echo "[6e] Virtio device details:"
for d in /sys/bus/virtio/devices/*/; do
    if [ -d "$d" ]; then
        echo "  Device: $(basename $d)"
        cat "$d/modalias" 2>/dev/null && true
        cat "$d/device" 2>/dev/null && true
    fi
done
echo ""

# ─── Summary ───
echo "══════════════════════════════════════"
echo "  CVE-2026-5747 PREREQUISITE SUMMARY"
echo "══════════════════════════════════════"
echo ""

PCI_FOUND="NO"
if [ -d /sys/bus/pci/devices ] && [ "$(ls -A /sys/bus/pci/devices 2>/dev/null)" ]; then
    PCI_FOUND="YES"
fi

ROOT="NO"
if [ "$(id -u)" = "0" ]; then
    ROOT="YES"
fi

PASSWD_WRITABLE="NO"
if [ -w /etc/passwd ]; then
    PASSWD_WRITABLE="YES"
fi

echo "  PCI transport present:    $PCI_FOUND  (required: YES)"
echo "  Running as root:          $ROOT  (required: YES)"
echo "  /etc/passwd writable:     $PASSWD_WRITABLE  (escalation path)"
echo "  Firecracker version:      UNKNOWN"
echo "  Seccomp filters:          $(grep Seccomp_filters /proc/self/status 2>/dev/null | awk '{print $2}' || echo 'unknown')"
echo ""

if [ "$PCI_FOUND" = "YES" ] && [ "$ROOT" = "YES" ]; then
    echo "  WARNING — PREREQUISITES MET — CVE-2026-5747 may be exploitable"
    echo "    Next: check FC version, craft virtio descriptor PoC"
elif [ "$PCI_FOUND" = "YES" ] && [ "$ROOT" = "NO" ] && [ "$PASSWD_WRITABLE" = "YES" ]; then
    echo "  PARTIAL — PCI found + /etc/passwd writable = escalation then exploit"
elif [ "$PCI_FOUND" = "NO" ]; then
    echo "  BLOCKED — No PCI transport. CVE-2026-5747 requires PCI virtio."
    echo "    Firecracker almost certainly using MMIO (its default)."
else
    echo "  BLOCKED — Missing prerequisites"
fi
echo ""
echo "=== Recon complete ==="
