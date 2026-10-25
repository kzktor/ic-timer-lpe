#ifndef INFINITYCORE_ANDROID_COMPAT_H
#define INFINITYCORE_ANDROID_COMPAT_H

#if defined(__aarch64__)
#define IC_AARCH64 1
#elif defined(__x86_64__)
#define IC_X86_64 1
#else
#error "unsupported architecture"
#endif

#if defined(__ANDROID__)
#define IC_ANDROID 1
#define IC_BIONIC 1
#else
#define IC_ANDROID 0
#define IC_BIONIC 0
#endif

#ifndef __NR_futex
#define __NR_futex 98
#endif
#ifndef __NR_futex_time64
#define __NR_futex_time64 422
#endif

#ifndef FUTEX_WAIT_PRIVATE
#define FUTEX_WAIT_PRIVATE 128
#endif
#ifndef FUTEX_WAKE_PRIVATE
#define FUTEX_WAKE_PRIVATE 129
#endif
#ifndef FUTEX_LOCK_PI
#define FUTEX_LOCK_PI 6
#endif
#ifndef FUTEX_UNLOCK_PI
#define FUTEX_UNLOCK_PI 7
#endif

#ifndef MFD_CLOEXEC
#define MFD_CLOEXEC 0x0001U
#endif

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

#ifndef SYS_io_setup
#if defined(__aarch64__)
#define SYS_io_setup 0
#define SYS_io_destroy 1
#define SYS_io_submit 2
#define SYS_timer_create 107
#define SYS_timer_settime 110
#define SYS_timer_gettime 108
#define SYS_timer_getoverrun 109
#define SYS_timer_delete 111
#define SYS_memfd_create 279
#define SYS_execveat 281
#define SYS_tgkill 131
#define SYS_gettid 178
#define SYS_sendfile 71
#define SYS_newfstatat 79
#define SYS_openat 56
#define SYS_fchmod 52
#define SYS_unlinkat 35
#define SYS_mprotect 226
#define SYS_mincore 232
#define SYS_rt_sigpending 136
#define SYS_setuid 146
#define SYS_setgid 144
#define SYS_setresuid 147
#define SYS_setresgid 149
#define SYS_rt_tgsigqueueinfo 240
#define SYS_rt_sigtimedwait 137
#define SYS_wait4 260
#define SYS_getpid 172
#define SYS_clone 220
#define SYS_ptrace 117
#define SYS_io_destroy 1
#define SYS_prctl 167
#define SYS_getcpu 168
#define SYS_sched_setaffinity 122
#define SYS_sched_getaffinity 123
#define SYS_sched_setattr 274
#define SYS_sched_getattr 275
#define SYS_membarrier 283
#define SYS_process_vm_readv 270
#define SYS_process_vm_writev 271
#define SYS_keyctl 219
#define SYS_bpf 280
#define SYS_perf_event_open 241
#endif
#endif

static inline long ic_syscall6(long n, long a, long b, long c, long d, long e, long f)
{
#if defined(__aarch64__)
	register long x8 __asm__("x8") = n;
	register long x0 __asm__("x0") = a;
	register long x1 __asm__("x1") = b;
	register long x2 __asm__("x2") = c;
	register long x3 __asm__("x3") = d;
	register long x4 __asm__("x4") = e;
	register long x5 __asm__("x5") = f;
	__asm__ volatile("svc #0"
			 : "+r"(x0)
			 : "r"(x8), "r"(x1), "r"(x2), "r"(x3), "r"(x4), "r"(x5)
			 : "memory", "cc");
	return x0;
#else
	return -1;
#endif
}

static inline long ic_syscall0(long n)
{
	return ic_syscall6(n, 0, 0, 0, 0, 0, 0);
}

static inline long ic_syscall1(long n, long a)
{
	return ic_syscall6(n, a, 0, 0, 0, 0, 0);
}

static inline long ic_syscall2(long n, long a, long b)
{
	return ic_syscall6(n, a, b, 0, 0, 0, 0);
}

static inline long ic_syscall3(long n, long a, long b, long c)
{
	return ic_syscall6(n, a, b, c, 0, 0, 0);
}

static inline unsigned long ic_read_cntvct(void)
{
#if defined(__aarch64__)
	unsigned long v;
	__asm__ volatile("isb; mrs %0, cntvct_el0" : "=r"(v));
	return v;
#else
	return 0;
#endif
}

static inline unsigned long ic_read_cntfrq(void)
{
#if defined(__aarch64__)
	unsigned long v;
	__asm__ volatile("mrs %0, cntfrq_el0" : "=r"(v));
	return v;
#else
	return 0;
#endif
}

static inline void ic_cpu_relax(void)
{
#if defined(__aarch64__)
	__asm__ volatile("yield" ::: "memory");
#else
	__asm__ volatile("pause" ::: "memory");
#endif
}

static inline void ic_memory_barrier(void)
{
#if defined(__aarch64__)
	__asm__ volatile("dmb ish" ::: "memory");
#else
	__asm__ volatile("mfence" ::: "memory");
#endif
}

static inline void ic_instruction_barrier(void)
{
#if defined(__aarch64__)
	__asm__ volatile("isb" ::: "memory");
#else
	__asm__ volatile("lfence" ::: "memory");
#endif
}

static inline void ic_cache_flush(const void *addr, unsigned long len)
{
#if defined(__aarch64__)
	unsigned long line = 64;
	unsigned long start = (unsigned long)addr & ~(line - 1);
	unsigned long end = ((unsigned long)addr + len + line - 1) & ~(line - 1);
	unsigned long p;

	for (p = start; p < end; p += line)
		__asm__ volatile("dc cvau, %0" ::"r"(p) : "memory");
	__asm__ volatile("dsb ish" ::: "memory");
	for (p = start; p < end; p += line)
		__asm__ volatile("ic ivau, %0" ::"r"(p) : "memory");
	__asm__ volatile("dsb ish" ::: "memory");
	__asm__ volatile("isb" ::: "memory");
#else
	(void)addr;
	(void)len;
#endif
}

#endif
