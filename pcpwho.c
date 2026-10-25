/*
 * pcpwho: which CPU's pageset receives the order-1 slab page that the
 * posix_timers_cache discards when a whole slab's timers are deleted?
 *
 * posix-timers.c frees the k_itimer through call_rcu() (release_posix_timer
 * -> k_itimer_rcu_free), so the slab discard runs from the RCU callback and
 * the two pages land on whatever CPU executes it, not necessarily the CPU
 * that called timer_delete().  The exploit sprays kmalloc-256 slabs from one
 * pinned CPU and depends on that page coming back there, so this probe
 * measures the destination directly and harmlessly: create timers, delete
 * them, watch every CPU's Normal-zone pcp count (/proc/zoneinfo is readable
 * by uid 2000) for the +2 bumps, and log posix_timers_cache's slab count.
 *
 * No UAF, no reap, no kernel risk: the timers are plain SIGEV_NONE timers and
 * everything is deleted before exit.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/syscall.h>

#define MAXCPU 16

static int zfd = -1, sfd = -1;
static char zbuf[1 << 20];

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

/* Per-CPU Normal-zone pageset counts.  Returns the number of CPUs found. */
static int read_counts(unsigned int *cnt)
{
	ssize_t n;
	size_t off = 0;
	char *p;
	int cpu = -1, in_normal = 0, in_sets = 0, found = 0;

	memset(cnt, 0, sizeof(unsigned int) * MAXCPU);
	if (zfd < 0)
		zfd = open("/proc/zoneinfo", O_RDONLY);
	if (zfd < 0)
		return -1;
	if (lseek(zfd, 0, SEEK_SET) < 0)
		return -1;
	while (off < sizeof(zbuf) - 1) {
		n = read(zfd, zbuf + off, sizeof(zbuf) - 1 - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	zbuf[off] = 0;

	for (p = zbuf; *p; ) {
		char *e = strchr(p, '\n');

		if (!e)
			break;
		*e = 0;
		if (!strncmp(p, "Node ", 5)) {
			char *z = strstr(p, "zone");

			in_normal = z && strstr(z, "Normal") ? 1 : 0;
			in_sets = 0;
			cpu = -1;
		} else if (in_normal && strstr(p, "pagesets")) {
			in_sets = 1;
		} else if (in_sets) {
			int c;
			unsigned int v;

			if (sscanf(p, " cpu: %d", &c) == 1) {
				cpu = c;
				if (c >= 0 && c < MAXCPU && !(found & (1 << c)))
					found |= 1 << c;
			} else if (cpu >= 0 && cpu < MAXCPU &&
				   sscanf(p, " count: %u", &v) == 1) {
				cnt[cpu] = v;
			}
		}
		p = e + 1;
	}
	return found ? 32 : -1;
}

/* posix_timers_cache total objects ("<name> active total ..."). */
static long posix_total(void)
{
	static char buf[1 << 20];
	size_t off = 0;
	ssize_t n;
	char *p;

	if (sfd < 0)
		sfd = open("/proc/slabinfo", O_RDONLY);
	if (sfd < 0)
		return -1;
	if (lseek(sfd, 0, SEEK_SET) < 0)
		return -1;
	while (off < sizeof(buf) - 1) {
		n = read(sfd, buf + off, sizeof(buf) - 1 - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	buf[off] = 0;
	p = strstr(buf, "posix_timers_cache");
	if (!p)
		return -1;
	{
		unsigned long a, t;

		if (sscanf(p, "%*s %lu %lu", &a, &t) != 2)
			return -1;
		return (long)t;
	}
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

int main(int argc, char **argv)
{
	int ntim = argc > 1 ? atoi(argv[1]) : 496;
	int delete_cpu = argc > 2 ? atoi(argv[2]) : 0;
	int id[4096];
	unsigned int base[MAXCPU], pre[MAXCPU], cur[MAXCPU];
	long t0, pre_slab, last_slab;
	int i, ncpu = -1, printed = 0, print_every = 20;

	if (ntim > 4096)
		ntim = 4096;
	if (read_counts(base) != 32) {
		fprintf(stderr, "cannot read zoneinfo counts\n");
		return 1;
	}
	for (i = 0; i < MAXCPU; i++)
		if (base[i])
			ncpu = i;

	pin_cpu(delete_cpu);
	fprintf(stderr, "[pcpwho] cpu=%d creating %d timers\n",
		sched_getcpu(), ntim);
	for (i = 0; i < ntim; i++) {
		struct sigevent ev;
		int t = -1;

		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		if (syscall(SYS_timer_create, 1 /* MONOTONIC */, &ev, &t)) {
			fprintf(stderr, "timer_create %d: %s\n", i,
				strerror(errno));
			ntim = i;
			break;
		}
		id[i] = t;
	}
	{
		struct timespec ts = { .tv_nsec = 300000000 };

		nanosleep(&ts, NULL);
	}
	read_counts(pre);
	pre_slab = posix_total();
	fprintf(stderr, "[pcpwho] start delete on cpu=%d slab_total=%ld\n",
		sched_getcpu(), pre_slab);
	t0 = now_ms();
	for (i = 0; i < ntim; i++)
		(void)syscall(SYS_timer_delete, id[i]);
	fprintf(stderr, "[pcpwho] deletes issued at t=%ld ms\n", now_ms() - t0);

	last_slab = pre_slab;
	while (now_ms() - t0 < 800) {
		struct timespec ts = { .tv_nsec = 1500000 };
		long el = now_ms() - t0;
		long slab;

		read_counts(cur);
		slab = posix_total();
		for (i = 0; i <= ncpu; i++) {
			long d = (long)cur[i] - (long)pre[i];

			if (d)
				fprintf(stderr,
					"[pcpwho] t=%3ldms cpu%d count %u->%u (%+ld)\n",
					el, i, pre[i], cur[i], d);
		}
		if (slab != last_slab) {
			fprintf(stderr,
				"[pcpwho] t=%3ldms slab_total %ld->%ld\n",
				el, last_slab, slab);
			last_slab = slab;
			printed++;
		}
		nanosleep(&ts, NULL);
	}
	read_counts(cur);
	{
		long el = now_ms() - t0;

		fprintf(stderr, "[pcpwho] final t=%ldms\n", el);
		for (i = 0; i <= ncpu; i++)
			fprintf(stderr, "  cpu%d: %u -> %u (%+ld)\n", i, pre[i],
				cur[i], (long)cur[i] - (long)pre[i]);
		fprintf(stderr, "  slab_total %ld -> %ld\n", pre_slab,
			(long)posix_total());
	}
	return 0;
}
