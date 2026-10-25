/* pcp2: does an order-1 slab allocation come from the per-CPU page list?
 *
 * Benign (timers only).  All on one pinned CPU:
 *   1. mmap+touch 8 MB: page faults pop order-0 pages off the pcp so the
 *      pageset count starts low (the mapping is kept, so it stays low).
 *   2. create 31*S timers -> S order-1 slabs.
 *   3. delete them all, wait for the RCU frees: the discarded slabs show up
 *      as +2 pages each on the pcp if frees use the pcp at all.
 *   4. create 31*S timers again: if order-1 allocations also use the pcp,
 *      the count falls back by the same amount; if allocations bypass the
 *      pcp (buddy only), the count stays elevated.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <time.h>
#include <unistd.h>

#define MAXC 64

struct zstat {
	unsigned count, high, batch;
};

static int first_cpu(void)
{
	cpu_set_t s;
	int i;

	CPU_ZERO(&s);
	if (sched_getaffinity(0, sizeof(s), &s))
		return 0;
	for (i = 0; i < CPU_SETSIZE; i++)
		if (CPU_ISSET(i, &s))
			return i;
	return 0;
}

static void pin_cpu(int cpu)
{
	cpu_set_t s;

	CPU_ZERO(&s);
	CPU_SET(cpu, &s);
	if (sched_setaffinity(0, sizeof(s), &s))
		fprintf(stderr, "setaffinity(%d): %s\n", cpu, strerror(errno));
}

static int zone_count(int cpu, struct zstat *z)
{
	FILE *f = fopen("/proc/zoneinfo", "r");
	char line[256];
	int in_normal = 0, in_sets = 0, cur = -1, got = 0;

	if (!f)
		return -1;
	z->count = z->high = z->batch = 0;
	while (fgets(line, sizeof(line), f)) {
		if (!strncmp(line, "Node ", 5)) {
			in_normal = strstr(line, "zone   Normal") ||
				    strstr(line, "zone Normal") ? 1 : 0;
			in_sets = 0;
			cur = -1;
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
		if (sscanf(line, " cpu: %d", &cur) == 1)
			continue;
		if (cur != cpu)
			continue;
		if (sscanf(line, " count: %u", &z->count) == 1)
			got |= 1;
		else if (sscanf(line, " high: %u", &z->high) == 1)
			got |= 2;
		else if (sscanf(line, " batch: %u", &z->batch) == 1)
			got |= 4;
	}
	fclose(f);
	return got == 7 ? 0 : -1;
}

struct sstat {
	unsigned active, total, per_slab, active_slabs, num_slabs;
};

static int slab_stat(struct sstat *s)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[512];
	int ok = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char name[64];
		unsigned a, t, osz, ps, pps, lim, bcnt, sf, as, ns, sa;

		if (sscanf(line,
			   "%63s %u %u %u %u %u : tunables %u %u %u : slabdata %u %u %u",
			   name, &a, &t, &osz, &ps, &pps, &lim, &bcnt, &sf,
			   &as, &ns, &sa) != 12)
			continue;
		if (strcmp(name, "posix_timers_cache"))
			continue;
		s->active = a;
		s->total = t;
		s->per_slab = ps;
		s->active_slabs = as;
		s->num_slabs = ns;
		ok = 0;
		break;
	}
	fclose(f);
	return ok;
}

/* sample the pageset count a few times; report min/median/max */
static void sample(int cpu, const char *tag)
{
	unsigned v[MAXC];
	int i, n = 0;
	struct zstat z = { 0, 0, 0 };

	for (i = 0; i < MAXC; i++) {
		if (zone_count(cpu, &z))
			break;
		v[n++] = z.count;
	}
	/* insertion sort */
	for (i = 1; i < n; i++) {
		unsigned k = v[i];
		int j = i - 1;

		while (j >= 0 && v[j] > k) {
			v[j + 1] = v[j];
			j--;
		}
		v[j + 1] = k;
	}
	if (n)
		fprintf(stderr,
			"%-10s count min=%u med=%u max=%u high=%u (n=%d, cpu=%d)\n",
			tag, v[0], v[n / 2], v[n - 1], z.high, n,
			sched_getcpu());
}

static void slab_dump(const char *tag)
{
	struct sstat s;

	if (slab_stat(&s))
		fprintf(stderr, "%-10s slab?\n", tag);
	else
		fprintf(stderr,
			"%-10s slab act=%u tot=%u slabs=%u/%u\n", tag,
			s.active, s.total, s.active_slabs, s.num_slabs);
}

int main(int argc, char **argv)
{
	unsigned slabs = 600;
	unsigned per = 31;
	unsigned n, i;
	size_t hold = 8u << 20;
	char *mem;
	int cpu;
	timer_t *t;
	struct sigevent sev;

	if (argc > 1)
		slabs = (unsigned)strtoul(argv[1], NULL, 0);
	n = slabs * per;

	cpu = first_cpu();
	pin_cpu(cpu);
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;

	mem = mmap(NULL, hold, PROT_READ | PROT_WRITE,
		   MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return 1;
	}
	t = calloc(n, sizeof(*t));
	if (!t)
		return 1;

	sample(cpu, "base");
	slab_dump("base");

	/* 1. pop the pcp with page faults, keep the mapping */
	for (i = 0; i < hold; i += 4096)
		mem[i] = (char)i;
	sample(cpu, "afterfault");
	slab_dump("afterfault");

	/* 2. S slabs */
	fprintf(stderr, "creating %u timers\n", n);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t[i])) {
			fprintf(stderr, "timer_create #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
	}
	sample(cpu, "created");
	slab_dump("created");

	/* 3. delete, wait for the discards to show up in slabinfo */
	slab_dump("pre-del");
	for (i = 0; i < n; i++)
		timer_delete(t[i]);
	for (i = 0; i < 100; i++) {
		struct sstat s;
		static unsigned last;

		usleep(10000);
		if (slab_stat(&s))
			continue;
		if (s.num_slabs == last && i > 5)
			break;
		last = s.num_slabs;
	}
	sample(cpu, "deleted");
	slab_dump("deleted");

	/* 4. same number of slabs again */
	fprintf(stderr, "re-creating %u timers\n", n);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t[i])) {
			fprintf(stderr, "timer_create2 #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
	}
	sample(cpu, "refill");
	slab_dump("refill");
	usleep(200000);
	sample(cpu, "refill+");
	slab_dump("refill+");

	for (i = 0; i < n; i++)
		timer_delete(t[i]);
	fprintf(stderr, "done\n");
	return 0;
}
