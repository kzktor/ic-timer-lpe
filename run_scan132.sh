#!/bin/bash
# Usage: run_scan132.sh LOG EXTRA_CMDLINE_ARGS...
# SELinux endgame scan on the extracted 13.2 kernel, using the device's own
# policy.bin. Mirrors run_ioring.sh (nokaslr, 4 vCPUs, ic_root=1,
# io_uring spray) but swaps in the 13.2 Image and a scan-capable initramfs.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttynull stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init nokaslr ic_root=1 ic_target=oracle ic_spray=ioring ic_pc=0 ic_iorings=512"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 4 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/scan132.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
