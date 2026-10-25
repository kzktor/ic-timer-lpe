#!/bin/bash
# Usage: run_skbprobe132.sh LOG [EXTRA_CMDLINE_ARGS...]
# Boots reap132_skbprobe.cpio.gz (exploit.new12: ic_pp_skb probe).
# Only the AF_UNIX SOCK_DGRAM payload probe runs, with pagetypeinfo
# snapshots every 128 queued datagrams.
cd /d/kwork/icbuild || exit 1
LOG=$1
shift
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
BASE="console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init stack_depot_disable=on cgroup_disable=pressure kvm-arm.mode=protected bootconfig ioremap_guard transparent_hugepage=never vmalloc=400M swiotlb=noforce cgroup.memory=nosocket,nokmem disable_dma32=on ic_pageprobe=1 ic_root=1 ic_pp_anon=0 ic_pp_pte=0 ic_pp_aio_ctxs=0 ic_pp_perf_events=0 ic_pp_pkt_blocks=0 ic_pp_pipes=0 ic_pp_uring_n=0 ic_pp_skb_pairs=32 ic_pp_skb_n=64 ic_pp_skb_payload=7808 ic_pp_skb_step=128"
timeout 300 "$QEMU" -M virt -cpu cortex-a72 -smp 8 -m 4096 -nographic \
  -no-reboot \
  -kernel /d/kwork/pd2506_161132/kernel_image.bin \
  -initrd /d/kwork/pd2506_161132/reap132_skbprobe.cpio.gz \
  -append "$BASE $*" > "$LOG" 2>&1
echo "qemu rc=$?"
