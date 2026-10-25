/*
 * pcp2: can an order-1 UNMOVABLE slab allocation (kmalloc-256, the cache the
 * mcast psl spray uses) reclaim the pages that posix_timers_cache discards?
 *
 * Phase 1 opens 4096 /dev/null files (struct file is a kmalloc-256 object,
 * 32 per order-1 slab) and keeps them, so a later burst must come from fresh
 * slab pages.  Phase 2 creates N timers and deletes them from cpu0; the RCU
 * callbacks free whole slabs into cpu0's pageset (each discard = +2 pages on
 * that pageset's count, visible in /proc/zoneinfo).  Phase 3 opens another
 * burst of files on cpu0: if those fresh kmalloc-256 slabs pop the discarded
 * pages out of the pageset, the count falls by ~2 per slab; if the pages sit
 * on a different migratetype list, the count does not.
 *
 * Harmless: plain timers and plain opens, all released at exit.
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
#define NFILE1 4096
#define NFILE2 2048
#define NTIMER 4096

static int zfd = -1, sfd = -1;
static char zbuf[1 << 20];
static char sbuf[1 << 20];

static long now_ms(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

static void pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	(void)sched_setaffinity(0, sizeof(set), &set);
}

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
				if (c >= 0 && c < MAXCPU)
					found |= 1 << c;
			} else if (cpu >= 0 && cpu < MAXCPU &&
				   sscanf(p, " count: %u", &v) == 1) {
				cnt[cpu] = v;
			}
		}
		p = e + 1;
	}
	return found ? 0 : -1;
}

/* "<name> active total ..." -> total objects, or -1 */
static long slab_total(const char *name)
{
	size_t off = 0;
	ssize_t n;
	char *p;

	if (sfd < 0)
		sfd = open("/proc/slabinfo", O_RDONLY);
	if (sfd < 0)
		return -1;
	if (lseek(sfd, 0, SEEK_SET) < 0)
		return -1;
	while (off < sizeof(sbuf) - 1) {
		n = read(sfd, sbuf + off, sizeof(sbuf) - 1 - off);
		if (n <= 0)
			break;
		off += (size_t)n;
	}
	sbuf[off] = 0;
	p = strstr(sbuf, name);
	if (!p)
		return -1;
	{
		unsigned long a, t;

		if (sscanf(p, "%*s %lu %lu", &a, &t) != 2)
			return -1;
		return (long)t;
	}
}

static void show(const char *tag, const unsigned int *c)
{
	fprintf(stderr, "[pcp2] %-9s", tag);
	for (int i = 0; i < 8; i++)
		fprintf(stderr, " c%d=%u", i, c[i]);
	fprintf(stderr, " | posix=%ld km256=%ld\n", slab_total("posix_timers_cache"),
		slab_total("kmalloc-256 "));
	fflush(stderr);
}

int main(int argc, char **argv)
{
	unsigned int c0[MAXCPU], c1[MAXCPU], c2[MAXCPU];
	static int fds[NFILE1 + NFILE2 + 16];
	static int tid[NTIMER];
	int nf1 = 0, nf2 = 0, nt = 0, i, cpu = 0;
	long t0;

	if (argc > 1)
		cpu = atoi(argv[1]);
	pin_cpu(cpu);
	fprintf(stderr, "[pcp2] cpu=%d\n", sched_getcpu());

	/* Phase 1: exhaust kmalloc-256's free slots with file objects. */
	for (i = 0; i < NFILE1; i++) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0)
			break;
		fds[nf1++] = fd;
	}
	fprintf(stderr, "[pcp2] phase1 files=%d\n", nf1);

	/* Phase 2: timers, then delete them. */
	for (i = 0; i < NTIMER; i++) {
		struct sigevent ev;
		int t = -1;

		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		if (syscall(SYS_timer_create, 1, &ev, &t))
			break;
		tid[nt++] = t;
	}
	fprintf(stderr, "[pcp2] timers=%d\n", nt);
	{
		struct timespec ts = { .tv_nsec = 100000000 };

		nanosleep(&ts, NULL);
	}
	read_counts(c0);
	show("pre-del", c0);
	t0 = now_ms();
	for (i = 0; i < nt; i++)
		(void)syscall(SYS_timer_delete, tid[i]);
	{
		struct timespec ts = { .tv_nsec = 120000000 };

		nanosleep(&ts, NULL);
	}
	read_counts(c1);
	show("post-del", c1);
	fprintf(stderr, "[pcp2] del took %ld ms\n", now_ms() - t0);

	/* Phase 3: fresh kmalloc-256 slab pages on the same CPU. */
	t0 = now_ms();
	for (i = 0; i < NFILE2; i++) {
		int fd = open("/dev/null", O_RDONLY);

		if (fd < 0)
			break;
		fds[nf1 + nf2] = fd;
		nf2++;
	}
	read_counts(c2);
	show("post-file", c2);
	fprintf(stderr, "[pcp2] phase3 files=%d in %ld ms\n", nf2,
		now_ms() - t0);

	fprintf(stderr, "[pcp2] delta del:  ");
	for (i = 0; i < 8; i++)
		fprintf(stderr, " c%d=%+ld", i, (long)c1[i] - (long)c0[i]);
	fprintf(stderr, "\n[pcp2] delta file: ");
	for (i = 0; i < 8; i++)
		fprintf(stderr, " c%d=%+ld", i, (long)c2[i] - (long)c1[i]);
	fprintf(stderr, "\n");
	return 0;
}
