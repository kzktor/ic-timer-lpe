#!/bin/bash
# Usage: run_mcast_app.sh LOG [EXTRA_CMDLINE_ARGS...]
# Same harness as run_mcast_exp.sh (13.2 / 16.1.13.2 kernel, KASLR on, 8 vCPUs)
# but with the app-mode initramfs: reap_init runs /exploit as uid/gid 1000,
# creates /ic-proof-root (0400 root), /ic-proof-shell (0600 uid 1000) and
# /tmp/ic-exec-helper (0755 copy of the exploit).
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_target=oracle ic_pc=0 ic_reverse=1 ic_peak=1 ic_fork=1"
timeout 1500 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/icbuild/${IC_INITRD:-mcast_app2.cpio.gz} \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
