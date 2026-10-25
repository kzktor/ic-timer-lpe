#!/bin/bash
# KASLR + gdb instrumented oracle loop.
# Boot without nokaslr, let init print runtime _text / target, pause 25s,
# attach gdb at slid addresses, then let the exploit run.
cd /d/kwork/icbuild || exit 1
QEMU=/c/Users/hyw/scoop/apps/qemu/11.1.0/qemu-system-aarch64.exe
GDB=/d/kwork/xpack-aarch64/xpack-aarch64-none-elf-gcc-15.2.1-1.1/bin/aarch64-none-elf-gdb.exe
RUNS=${1:-10}
for n in $(seq 1 "$RUNS"); do
  log=kaslrg$n.log
  rm -f "$log" gdb_kaslrg$n.cmd gdb_kaslrg$n.log
  "$QEMU" -M virt -cpu cortex-a72 -smp 4 -m 4096 -nographic -no-reboot -s \
    -kernel /d/kwork/pd2506_161150/new_kernel_image.bin \
    -initrd initramfs_reap.cpio.gz \
    -append "console=ttyAMA0 earlycon=pl011,0x9000000 rdinit=/init ic_root=1 ic_target=oracle ic_spray=packet ic_pc=0 ic_pkt_blocks=8192 ic_delay_ms=25000" \
    > "$log" 2>&1 &
  qpid=$!

  timeout 60 bash -c "tail -f -n +1 '$log' | grep --line-buffered -m1 'oracle target' >/dev/null"
  text=$(sed -n 's/.*sym _text=\(0x[0-9a-f]*\).*/\1/p' "$log" | head -1)
  T=$(sed -n 's/.*oracle target \(0x[0-9a-f]*\).*/\1/p' "$log" | head -1)
  echo "RUN $n text=$text T=$T"
  if [ -z "$text" ] || [ -z "$T" ]; then
    kill $qpid 2>/dev/null
    wait $qpid 2>/dev/null
    continue
  fi
  addrs=$(python -I -c "t=$text; b=0xffffffc008000000; print(hex(0xffffffc0081a1f68+t-b), hex(0xffffffc00906f004+t-b))")
  set -- $addrs
  EXIT=$1
  TQD=$2

  cat > gdb_kaslrg$n.cmd <<EOF
set pagination off
set confirm off
set architecture aarch64
set remotetimeout 120
target remote 127.0.0.1:1234
set \$A = 0
hbreak *$EXIT if *(unsigned long*)(\$x0+0x7a0) != 0 || *(unsigned long*)(\$x0+0x7b8) != 0 || *(unsigned long*)(\$x0+0x7d0) != 0
commands 1
  silent
  set \$tsk = \$x0
  set \$v = *(unsigned long*)(\$tsk+0x7a0)
  set \$p = *(unsigned long*)(\$tsk+0x7b8)
  set \$s = *(unsigned long*)(\$tsk+0x7d0)
  set \$A = \$s
  if \$A == 0
    set \$A = \$p
  end
  if \$A == 0
    set \$A = \$v
  end
  printf "\n=== CPU_TIMERS_EXIT tsk=%p comm=", \$tsk
  x/s \$tsk+0x848
  printf "  VIRT lm=%p PROF lm=%p SCHED lm=%p\n", \$v, \$p, \$s
  if \$A > 0xffffff0000000000
    printf "  A=%p a8k=0x%lx a4k=0x%lx mod78=%ld mod80=%ld\n", \$A, \$A & 0x1fff, \$A & 0xfff, (\$A - 0x78) % 264, (\$A - 0x80) % 264
    x/8gx \$A
    x/8gx \$A+0x20
  end
  continue
end
hbreak *$TQD if \$x1 == $T
commands 2
  silent
  printf "\n=== BAD TQD node==T head=%p node=%p\n", \$x0, \$x1
  info registers
  bt
  continue
end
hbreak *$TQD if \$x1 == \$A
commands 3
  silent
  printf "\n=== TQD stale node head=%p node=%p pc=%p right=%p left=%p\n", \$x0, \$x1, *(unsigned long*)\$x1, *(unsigned long*)(\$x1+8), *(unsigned long*)(\$x1+0x10)
  continue
end
continue
EOF

  timeout 200 "$GDB" -batch -x gdb_kaslrg$n.cmd > gdb_kaslrg$n.log 2>&1
  echo "RUN $n gdb=$?"
  kill $qpid 2>/dev/null
  wait $qpid 2>/dev/null
  grep -aE "CPU_TIMERS_EXIT|A=|TQD|BAD|boot_id|exploit target|Unable to handle|Kernel panic" gdb_kaslrg$n.log "$log" | head -25
done
