/* mcast_probe2: capacity test.  One fd can hold many group memberships,
 * each with its own kmalloc-256 source list.  Measures slab growth and
 * readback fidelity without exhausting the fd table.
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
#include <sys/resource.h>
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

static int ifidx;

static void slab_line(const char *name)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[512], n[128];

	if (!f)
		return;
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

static void set_group(struct sockaddr_storage *ss, unsigned int g, int scope)
{
	struct sockaddr_in6 *sin = (struct sockaddr_in6 *)ss;

	memset(sin, 0, sizeof(*sin));
	sin->sin6_family = AF_INET6;
	sin->sin6_addr.s6_addr[0] = 0xff;
	sin->sin6_addr.s6_addr[1] = 0x02;
	sin->sin6_addr.s6_addr[2] = (unsigned char)((g >> 24) & 0x7f);
	sin->sin6_addr.s6_addr[3] = (unsigned char)((g >> 16) & 0xff);
	sin->sin6_addr.s6_addr[4] = (unsigned char)((g >> 8) & 0xff);
	sin->sin6_addr.s6_addr[5] = (unsigned char)(g & 0xff);
	sin->sin6_scope_id = scope;
}

static void fill_pattern(struct ic_gf *gf, unsigned int tag)
{
	unsigned int j;

	for (j = 0; j < NSRC; j++) {
		struct sockaddr_in6 *sin = (struct sockaddr_in6 *)&gf->gf_slist[j];
		uint64_t a = 0x4141414100000000ULL | ((uint64_t)(tag & 0xffffff) << 8) | j;
		uint64_t b = 0x1122334455667788ULL ^ ((uint64_t)tag << 32) ^ j;

		memset(sin, 0, sizeof(*sin));
		sin->sin6_family = AF_INET6;
		memcpy(&sin->sin6_addr, &a, 8);
		memcpy(&sin->sin6_addr.s6_addr[8], &b, 8);
	}
}

/* join group g on fd and attach a fresh 14-source filter.  returns 0 ok */
static int make_one(int fd, unsigned int g, unsigned int tag)
{
	struct ic_gf gf;
	struct ic_greq req;
	socklen_t len = sizeof(gf);
	int err;

	memset(&gf, 0, sizeof(gf));
	gf.gf_interface = ifidx;
	set_group(&gf.gf_group, g, ifidx);
	req.gr_interface = ifidx;
	memcpy(&req.gr_group, &gf.gf_group, sizeof(req.gr_group));
	err = setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_GROUP, &req, sizeof(req));
	if (err) {
		printf("[mcast] join(%u) errno=%d %s\n", g, errno, strerror(errno));
		return -1;
	}
	fill_pattern(&gf, tag);
	gf.gf_fmode = MCAST_INCLUDE;
	gf.gf_numsrc = NSRC;
	err = setsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, sizeof(gf));
	if (err) {
		printf("[mcast] msf(%u) errno=%d %s\n", g, errno, strerror(errno));
		return -2;
	}
	(void)len;
	return 0;
}

static int verify_one(int fd, unsigned int g, unsigned int tag)
{
	struct ic_gf gf;
	socklen_t len = sizeof(gf);
	int j, bad = 0;

	memset(&gf, 0, sizeof(gf));
	gf.gf_interface = ifidx;
	set_group(&gf.gf_group, g, ifidx);
	gf.gf_numsrc = NSRC;
	if (getsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, &len)) {
		printf("[mcast] get(%u) errno=%d %s\n", g, errno, strerror(errno));
		return -1;
	}
	for (j = 0; j < NSRC; j++) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *)&gf.gf_slist[j];
		uint64_t a, b, ea, eb;

		ea = 0x4141414100000000ULL | ((uint64_t)(tag & 0xffffff) << 8) | j;
		eb = 0x1122334455667788ULL ^ ((uint64_t)tag << 32) ^ j;
		memcpy(&a, &s->sin6_addr, 8);
		memcpy(&b, &s->sin6_addr.s6_addr[8], 8);
		if (a != ea || b != eb)
			bad++;
	}
	return bad;
}

int main(int argc, char **argv)
{
	struct rlimit rl;
	unsigned int groups = 4000, per_fd_groups, nfd, total, k, nbad = 0;
	int fds[64];
	struct timeval t0, t1;
	unsigned int i;

	if (argc > 1)
		groups = (unsigned int)strtoul(argv[1], NULL, 0);
	mount("proc", "/proc", "proc", 0, NULL);
	rl.rlim_cur = rl.rlim_max = 65536;
	setrlimit(RLIMIT_NOFILE, &rl);
	getrlimit(RLIMIT_NOFILE, &rl);
	printf("[mcast] start groups=%u nofile=%lu/%lu\n", groups,
	       (unsigned long)rl.rlim_cur, (unsigned long)rl.rlim_max);
	ifidx = (int)if_nametoindex("lo");
	if (!ifidx)
		ifidx = 1;
	printf("[mcast] lo ifindex=%d\n", ifidx);
	slab_line("kmalloc-256");
	slab_line("kmalloc-512");

	per_fd_groups = 500;
	nfd = (groups + per_fd_groups - 1) / per_fd_groups;
	if (nfd > 64)
		nfd = 64;
	if (nfd < 1)
		nfd = 1;
	printf("[mcast] nfd=%u per_fd=%u\n", nfd, per_fd_groups);
	for (i = 0; i < nfd; i++) {
		int fd = socket(AF_INET6, SOCK_DGRAM, 0);

		if (fd < 0) {
			printf("[mcast] socket %u errno=%d %s\n", i, errno,
			       strerror(errno));
			fds[i] = -1;
			continue;
		}
		fds[i] = fd;
	}
	gettimeofday(&t0, NULL);
	total = 0;
	for (i = 0; i < nfd; i++) {
		if (fds[i] < 0)
			continue;
		for (k = 0; k < per_fd_groups && total < groups; k++, total++) {
			if (make_one(fds[i], 1 + total, total)) {
				printf("[mcast] stop at total=%u\n", total);
				goto done;
			}
		}
	}
done:
	gettimeofday(&t1, NULL);
	printf("[mcast] created=%u ms=%ld\n", total,
	       (long)((t1.tv_sec - t0.tv_sec) * 1000 +
		      (t1.tv_usec - t0.tv_usec) / 1000));
	slab_line("kmalloc-128");
	slab_line("kmalloc-192");
	slab_line("kmalloc-256");
	slab_line("kmalloc-512");

	/* verify a sample spread over the run */
	for (i = 0; i < total; i += (total / 16 ? total / 16 : 1)) {
		int fd = fds[i / per_fd_groups];
		int rc;

		if (total - i < 14)
			break;
		rc = verify_one(fd, 1 + i, i);
		if (rc)
			nbad += (unsigned)rc;
	}
	printf("[mcast] verify bad=%u\n", nbad);
	fflush(stdout);
	for (i = 0; i < nfd; i++)
		if (fds[i] >= 0)
			close(fds[i]);
	printf("[mcast] closed\n");
	slab_line("kmalloc-256");
	fflush(stdout);
	return 0;
}
