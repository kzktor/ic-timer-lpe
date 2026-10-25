/* pcptest: measure whether order-1 slab pages freed by posix_timers_cache
 * discards are retrievable by the next order-1 slab allocation.
 *
 * Benign: only timer_create/timer_delete with SIGEV_NONE (no stale nodes,
 * no UAF).  Pins to one CPU, then:
 *   1. create N = 31*S timers, resolve slabinfo geometry
 *   2. delete them, wait for the RCU frees, record slab + pcp counts
 *   3. create the same number again and record pcp counts
 * If the pcp count drops by 2*S during step 3 the allocator served the new
 * slabs from the pcp; if it stays flat the pages were parked in the pcp and
 * the slabs came from the buddy instead.
 *
 * build: zig cc -D_GNU_SOURCE -target aarch64-linux-musl -static -O2
 */
#define _GNU_SOURCE
#include <errno.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

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
		if (sscanf(line, " count: %u", &z->count) == 1) {
			got |= 1;
			continue;
		}
		if (sscanf(line, " high: %u", &z->high) == 1) {
			got |= 2;
			continue;
		}
		if (sscanf(line, " batch: %u", &z->batch) == 1) {
			got |= 4;
			continue;
		}
	}
	fclose(f);
	return got == 7 ? 0 : -1;
}

struct sstat {
	unsigned active, total, objsize, per_slab, pages_per_slab,
		 active_slabs, num_slabs;
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
		s->objsize = osz;
		s->per_slab = ps;
		s->pages_per_slab = pps;
		s->active_slabs = as;
		s->num_slabs = ns;
		ok = 0;
		break;
	}
	fclose(f);
	return ok;
}

static void dump(const char *tag, int cpu)
{
	struct zstat z;
	struct sstat s;
	char zb[64], sb[96];

	if (zone_count(cpu, &z))
		snprintf(zb, sizeof(zb), "zone?");
	else
		snprintf(zb, sizeof(zb), "pcp count=%u high=%u batch=%u",
			 z.count, z.high, z.batch);
	if (slab_stat(&s))
		snprintf(sb, sizeof(sb), "slab?");
	else
		snprintf(sb, sizeof(sb),
			 "slab act=%u tot=%u slabs=%u/%u (%u obj @%u, %u pages)",
			 s.active, s.total, s.active_slabs, s.num_slabs,
			 s.per_slab, s.objsize, s.pages_per_slab);
	fprintf(stderr, "%-12s cpu=%d %s | %s\n", tag, sched_getcpu(), zb, sb);
}

int main(int argc, char **argv)
{
	unsigned slabs = 48;
	unsigned per = 31;
	unsigned n, i;
	int cpu;
	timer_t *t1, *t2;
	struct sigevent sev;

	if (argc > 1)
		slabs = (unsigned)strtoul(argv[1], NULL, 0);
	if (argc > 2)
		per = (unsigned)strtoul(argv[2], NULL, 0);
	n = slabs * per;

	cpu = first_cpu();
	pin_cpu(cpu);

	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;

	t1 = calloc(n, sizeof(*t1));
	t2 = calloc(n, sizeof(*t2));
	if (!t1 || !t2)
		return 1;

	dump("base", cpu);

	fprintf(stderr, "creating %u timers (want %u slabs)\n", n, slabs);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t1[i])) {
			fprintf(stderr, "timer_create #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
	}
	dump("created", cpu);

	for (i = 0; i < n; i++)
		timer_delete(t1[i]);
	fprintf(stderr, "deleted %u timers, waiting for RCU\n", n);
	usleep(400000);
	dump("deleted", cpu);
	usleep(400000);
	dump("deleted+", cpu);

	fprintf(stderr, "re-creating %u timers\n", n);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t2[i])) {
			fprintf(stderr, "timer_create2 #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
	}
	dump("refill0", cpu);
	dump("refill1", cpu);

	for (i = 0; i < n; i++)
		timer_delete(t2[i]);
	fprintf(stderr, "done\n");
	return 0;
}
