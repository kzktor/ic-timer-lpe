/* mcast_probe: does MCAST_MSFILTER (IPv6 source list) give us a
 * kmalloc-256 object with 224 bytes of user-chosen, getsockopt-readable
 * data on this kernel?
 *
 * Run as init in QEMU: prints [mcast] lines with errno and slabinfo.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define MCAST_JOIN_GROUP 42
#define MCAST_MSFILTER 48
#define MCAST_INCLUDE 1
#define NSRC 14

struct ic_gf {
	uint32_t gf_interface;
	struct sockaddr_storage gf_group;
	uint32_t gf_fmode;
	uint32_t gf_numsrc;
	struct sockaddr_storage gf_slist[NSRC];
};

struct ic_greq {
	uint32_t gr_interface;
	struct sockaddr_storage gr_group;
};

static int made;

static void slab_line(const char *name)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[512], n[128];

	if (!f) {
		printf("[mcast] slabinfo open fail %s\n", strerror(errno));
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		unsigned long a, b, c, d, e;

		if (sscanf(line, "%127s %lu %lu %lu %lu %lu", n, &a, &b, &c, &d,
			   &e) < 6)
			continue;
		if (!strcmp(n, name)) {
			printf("[mcast] slab %s active=%lu num=%lu size=%lu "
			       "perslab=%lu pages=%lu\n", n, a, b, c, d, e);
			break;
		}
	}
	fclose(f);
}

static void slab_all(void)
{
	slab_line("kmalloc-128");
	slab_line("kmalloc-192");
	slab_line("kmalloc-256");
	slab_line("kmalloc-512");
}

static int lo_index(void)
{
	unsigned int i = if_nametoindex("lo");

	return i ? (int)i : 1;
}

static void make_group(struct ic_gf *gf, int ifindex)
{
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&gf->gf_group;

	memset(gf, 0, sizeof(*gf));
	gf->gf_interface = ifindex;
	sin->sin6_family = AF_INET6;
	sin->sin6_addr.s6_addr[0] = 0xff;
	sin->sin6_addr.s6_addr[1] = 0x02;
	sin->sin6_addr.s6_addr[15] = 0x01;
	sin->sin6_scope_id = ifindex;
}

/* fill each of the 14 sources with a repeatable 16-byte pattern */
static void fill_pattern(struct ic_gf *gf, unsigned int tag, int variant)
{
	unsigned int j;

	for (j = 0; j < NSRC; j++) {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&gf->gf_slist[j];
		uint64_t a = 0x4141414100000000ULL | ((uint64_t)tag << 16) | j;
		uint64_t b;

		if (variant == 0)
			b = 0;
		else if (variant == 1)
			b = 0xffffff80c0000000ULL | ((uint64_t)tag << 8) | j;
		else
			b = 0x1122334455667788ULL ^ ((uint64_t)tag << 32) ^ j;
		memset(sin, 0, sizeof(*sin));
		sin->sin6_family = AF_INET6;
		memcpy(&sin->sin6_addr, &a, 8);
		memcpy(&sin->sin6_addr.s6_addr[8], &b, 8);
	}
}

static int new_sock(const char *tag, unsigned int idx, int verbose)
{
	struct ic_gf gf;
	struct ic_greq req;
	int fd, err, ifindex = lo_index();
	socklen_t len = sizeof(gf);
	struct sockaddr_in6 *sin;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		if (verbose)
			printf("[mcast] %s socket fail %s\n", tag, strerror(errno));
		return -1;
	}
	make_group(&gf, ifindex);
	req.gr_interface = gf.gf_interface;
	memcpy(&req.gr_group, &gf.gf_group, sizeof(req.gr_group));
	err = setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_GROUP, &req, sizeof(req));
	if (err && verbose)
		printf("[mcast] %s join fail errno=%d %s\n", tag, errno,
		       strerror(errno));
	if (err) {
		close(fd);
		return -2;
	}
	fill_pattern(&gf, idx, 2);
	gf.gf_fmode = MCAST_INCLUDE;
	gf.gf_numsrc = NSRC;
	err = setsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, sizeof(gf));
	if (err) {
		if (verbose)
			printf("[mcast] %s msfilter fail errno=%d %s\n", tag,
			       errno, strerror(errno));
		close(fd);
		return -3;
	}
	if (verbose) {
		memset(&gf, 0, sizeof(gf));
		make_group(&gf, ifindex);
		gf.gf_fmode = MCAST_INCLUDE;
		gf.gf_numsrc = NSRC;
		err = getsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, &len);
		if (err) {
			printf("[mcast] %s get fail errno=%d %s\n", tag, errno,
			       strerror(errno));
		} else {
			struct sockaddr_in6 *s0 =
				(struct sockaddr_in6 *)&gf.gf_slist[0];
			uint64_t a, b;

			memcpy(&a, &s0->sin6_addr, 8);
			memcpy(&b, &s0->sin6_addr.s6_addr[8], 8);
			printf("[mcast] %s get ok len=%u numsrc=%u fmode=%u "
			       "fam=%u a=0x%llx b=0x%llx\n", tag,
			       (unsigned)len, gf.gf_numsrc, gf.gf_fmode,
			       s0->sin6_family, (unsigned long long)a,
			       (unsigned long long)b);
		}
	}
	made++;
	return fd;
}

static int check_all(int *fds, int n, unsigned int base)
{
	int i, j, bad = 0;

	for (i = 0; i < n; i++) {
		struct ic_gf gf;
		socklen_t len = sizeof(gf);
		struct sockaddr_in6 *sin;

		if (fds[i] < 0)
			continue;
		memset(&gf, 0, sizeof(gf));
		make_group(&gf, lo_index());
		gf.gf_fmode = MCAST_INCLUDE;
		gf.gf_numsrc = NSRC;
		if (getsockopt(fds[i], IPPROTO_IPV6, MCAST_MSFILTER, &gf, &len))
			continue;
		sin = (struct sockaddr_in6 *)&gf.gf_slist[0];
		for (j = 0; j < NSRC; j++) {
			uint64_t a, b, ea, eb;
			struct sockaddr_in6 *s =
				(struct sockaddr_in6 *)&gf.gf_slist[j];
			unsigned int tag = base + (unsigned int)i;

			ea = 0x4141414100000000ULL | ((uint64_t)tag << 16) | j;
			eb = 0x1122334455667788ULL ^ ((uint64_t)tag << 32) ^ j;
			memcpy(&a, &s->sin6_addr, 8);
			memcpy(&b, &s->sin6_addr.s6_addr[8], 8);
			if (a != ea || b != eb) {
				if (bad < 4)
					printf("[mcast] mismatch sock=%d src=%d "
					       "a=0x%llx/0x%llx b=0x%llx/0x%llx\n",
					       i, j, (unsigned long long)a,
					       (unsigned long long)ea,
					       (unsigned long long)b,
					       (unsigned long long)eb);
				bad++;
			}
		}
		if (sin == NULL)
			break;
	}
	return bad;
}

int main(void)
{
	int fds1[4], *bulk, i, fd, err;
	unsigned int n = 2000, created = 0, joined_fail = 0, ms_fail = 0;
	struct timeval t0, t1;

	mount("proc", "/proc", "proc", 0, NULL);
	printf("[mcast] start\n");
	slab_all();

	fd = new_sock("one", 0, 1);
	printf("[mcast] one fd=%d\n", fd);
	slab_line("kmalloc-256");

	/* membership required? */
	{
		struct ic_gf gf;
		int s = socket(AF_INET6, SOCK_DGRAM, 0);

		make_group(&gf, lo_index());
		gf.gf_fmode = MCAST_INCLUDE;
		gf.gf_numsrc = NSRC;
		fill_pattern(&gf, 999, 2);
		err = setsockopt(s, IPPROTO_IPV6, MCAST_MSFILTER, &gf,
				 sizeof(gf));
		printf("[mcast] nojoin msfilter errno=%d (%s)\n",
		       err ? errno : 0, err ? strerror(errno) : "ok");
		close(s);
	}

	slab_all();
	bulk = calloc(n, sizeof(int));
	if (!bulk) {
		printf("[mcast] calloc fail\n");
		return 0;
	}
	gettimeofday(&t0, NULL);
	for (i = 0; i < (int)n; i++) {
		bulk[i] = new_sock("bulk", 100 + i, 0);
		if (bulk[i] == -2)
			joined_fail++;
		else if (bulk[i] == -3)
			ms_fail++;
		else if (bulk[i] >= 0)
			created++;
	}
	gettimeofday(&t1, NULL);
	printf("[mcast] bulk n=%u created=%u joinfail=%u msfail=%u ms=%ld\n",
	       n, created, joined_fail, ms_fail,
	       (long)((t1.tv_sec - t0.tv_sec) * 1000 +
		      (t1.tv_usec - t0.tv_usec) / 1000));
	slab_all();

	printf("[mcast] verify bad=%d\n", check_all(bulk, (int)n, 100));
	slab_all();

	for (i = 0; i < (int)n; i++)
		if (bulk[i] >= 0)
			close(bulk[i]);
	if (fd >= 0)
		close(fd);
	(void)fds1;
	printf("[mcast] closed\n");
	slab_all();
	fflush(stdout);
	return 0;
}
