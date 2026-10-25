set pagination off
set confirm off
set architecture aarch64
set remotetimeout 120
target remote 127.0.0.1:1234
set $A = 0

# posix_cpu_timers_exit (nokaslr link address)
# stop whenever any of the three per-task cpu timer queues is non-empty at cleanup
hbreak *0xffffffc0081a1f68 if *(unsigned long*)($x0+0x7a0) != 0 || *(unsigned long*)($x0+0x7b8) != 0 || *(unsigned long*)($x0+0x7d0) != 0
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
  printf "  VIRT  tq=%p root=%p lm=%p\n", $tsk+0x798, *(unsigned long*)($tsk+0x798), $v
  printf "  PROF  tq=%p root=%p lm=%p\n", $tsk+0x7b0, *(unsigned long*)($tsk+0x7b0), $p
  printf "  SCHED tq=%p root=%p lm=%p\n", $tsk+0x7c8, *(unsigned long*)($tsk+0x7c8), $s
  if $A > 0xffffff0000000000
    printf "  A=%p page_off=0x%lx node: ", $A, $A & 0xfff
    x/4gx $A
    printf "  A-0x20:\n"
    x/8gx $A-0x20
    printf "  A+0x20:\n"
    x/8gx $A+0x20
  end
  continue
end

# any timerqueue_del whose node is the runtime oracle target (bad case)
hbreak *0xffffffc00906f004 if $x1 == 0xffffffc00a47eed8
commands 2
  silent
  printf "\n=== TQD with node==TARGET (BAD) head=%p node=%p\n", $x0, $x1
  info registers
  bt
  continue
end

# first timerqueue_del on our captured stale node
hbreak *0xffffffc00906f004 if $x1 == $A
commands 3
  silent
  printf "\n=== TQD stale node head=%p node=%p pc=%p right=%p left=%p\n", $x0, $x1, *(unsigned long*)$x1, *(unsigned long*)($x1+8), *(unsigned long*)($x1+0x10)
  continue
end

continue
