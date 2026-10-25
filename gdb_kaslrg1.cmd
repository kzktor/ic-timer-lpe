set pagination off
set confirm off
set architecture aarch64
set remotetimeout 120
target remote 127.0.0.1:1234
set $A = 0
hbreak *0xffffffe4b23a1f68 if *(unsigned long*)($x0+0x7a0) != 0 || *(unsigned long*)($x0+0x7b8) != 0 || *(unsigned long*)($x0+0x7d0) != 0
commands 1
  silent
  set $tsk = $x0
  set $v = *(unsigned long*)($tsk+0x7a0)
  set $p = *(unsigned long*)($tsk+0x7b8)
  set $s = *(unsigned long*)($tsk+0x7d0)
  set $A = $s
  if $A == 0
    set $A = $p
  end
  if $A == 0
    set $A = $v
  end
  printf "\n=== CPU_TIMERS_EXIT tsk=%p comm=", $tsk
  x/s $tsk+0x848
  printf "  VIRT lm=%p PROF lm=%p SCHED lm=%p\n", $v, $p, $s
  if $A > 0xffffff0000000000
    printf "  A=%p a8k=0x%lx a4k=0x%lx mod78=%ld mod80=%ld\n", $A, $A & 0x1fff, $A & 0xfff, ($A - 0x78) % 264, ($A - 0x80) % 264
    x/8gx $A
    x/8gx $A+0x20
  end
  continue
end
hbreak *0xffffffe4b326f004 if $x1 == 0xffffffe4b467eed8
commands 2
  silent
  printf "\n=== BAD TQD node==T head=%p node=%p\n", $x0, $x1
  info registers
  bt
  continue
end
hbreak *0xffffffe4b326f004 if $x1 == $A
commands 3
  silent
  printf "\n=== TQD stale node head=%p node=%p pc=%p right=%p left=%p\n", $x0, $x1, *(unsigned long*)$x1, *(unsigned long*)($x1+8), *(unsigned long*)($x1+0x10)
  continue
end
continue
