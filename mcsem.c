/* mcsem: psl edit semantics test, run as /init in the QEMU guest.
 *
 * Replays exactly what the exploit does to one psl: join, msfilter with 14
 * sources, getsockopt readback, delete-everything, append 14, and the failure
 * modes.  Prints fmode and the count after every step so a semantic surprise
 * shows up here instead of as a dead exploit run.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <netinet/in.h>

#define MCAST_JOIN_GROUP 42
#define MCAST_BLOCK_SOURCE 43
#define MCAST_UNBLOCK_SOURCE 44
#define MCAST_MSFILTER 48
#define NSRC 14

struct ss {
	unsigned short family;
	unsigned char pad[126];
} __attribute__((aligned(8)));

struct gf {
	uint32_t iface;
	struct ss group;
	uint32_t fmode;
	uint32_t numsrc;
	struct ss slist[NSRC];
};

struct greq {
	uint32_t iface;
	struct ss group;
};

struct gsr {
	uint32_t iface;
	struct ss group;
	struct ss source;
} __attribute__((aligned(8)));

static int ifidx;

static void set_group(struct ss *ss, unsigned int g)
{
	unsigned char *p = (unsigned char *)ss;

	memset(ss, 0, sizeof(*ss));
	p[0] = 10;
	p[8] = 0xff;
	p[9] = 0x02;
	p[10] = 0x01;
	p[21] = (unsigned char)(g >> 16);
	p[22] = (unsigned char)(g >> 8);
	p[23] = (unsigned char)g;
	*(uint32_t *)(p + 24) = (uint32_t)ifidx;
}

static int join(int fd, unsigned int g)
{
	struct greq r;

	memset(&r, 0, sizeof(r));
	r.iface = (uint32_t)ifidx;
	set_group(&r.group, g);
	return setsockopt(fd, IPPROTO_IPV6, MCAST_JOIN_GROUP, &r, sizeof(r));
}

static int msf(int fd, unsigned int g, uint32_t fmode, uint32_t numsrc)
{
	struct gf gf;

	memset(&gf, 0, sizeof(gf));
	gf.iface = (uint32_t)ifidx;
	set_group(&gf.group, g);
	gf.fmode = fmode;
	gf.numsrc = numsrc;
	return setsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, sizeof(gf));
}

static int get(int fd, unsigned int g, unsigned char img[NSRC][16],
	       uint32_t *mode, uint32_t *cnt)
{
	struct gf gf;
	socklen_t len = sizeof(gf);
	unsigned int k;

	memset(&gf, 0, sizeof(gf));
	gf.iface = (uint32_t)ifidx;
	set_group(&gf.group, g);
	gf.numsrc = NSRC;
	if (getsockopt(fd, IPPROTO_IPV6, MCAST_MSFILTER, &gf, &len))
		return errno ? -errno : -1;
	*mode = gf.fmode;
	*cnt = gf.numsrc;
	for (k = 0; k < NSRC; k++) {
		if (k < gf.numsrc)
			memcpy(img[k], (unsigned char *)&gf.slist[k] + 8, 16);
		else
			memset(img[k], 0, 16);
	}
	return 0;
}

static int edit(int fd, unsigned int g, int opt, const unsigned char *src)
{
	struct gsr r;

	memset(&r, 0, sizeof(r));
	r.iface = (uint32_t)ifidx;
	set_group(&r.group, g);
	((unsigned char *)&r.source)[0] = 10;
	memcpy((unsigned char *)&r.source + 8, src, 16);
	if (sizeof(r) != 264) {
		printf("[sem] BAD gsr size %zu\n", sizeof(r));
		return -1;
	}
	if (!setsockopt(fd, IPPROTO_IPV6, opt, &r, sizeof(r)))
		return 0;
	return errno ? -errno : -1;
}

static void pat(unsigned char (*img)[16], unsigned int k)
{
	memset(img[k], 0, 16);
	img[k][0] = 0x40 + k;
	img[k][15] = 0x80 + k;
}

int main(void)
{
	unsigned char img[NSRC][16], src[16];
	unsigned int g = 1, k;
	uint32_t mode = 0xdead, cnt = 0xdead;

	int fd, r;

	mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/sys", 0755);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	{
		int f = open("/sys/class/net/lo/ifindex", O_RDONLY);
		char b[16] = {0};

		if (f >= 0 && read(f, b, 15) > 0)
			ifidx = atoi(b);
		if (f >= 0)
			close(f);
	}
	if (ifidx <= 0)
		ifidx = 1;
	printf("[sem] start ifidx=%d af_inet6=%d sizeof(gf)=%zu\n", ifidx,
	       AF_INET6, sizeof(struct gf));
	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("[sem] socket errno=%d\n", errno);
		goto out;
	}
	r = join(fd, g);
	printf("[sem] join g=%u -> %d errno=%d\n", g, r, r ? errno : 0);
	r = msf(fd, g, 0, NSRC);
	printf("[sem] msfilter exclude numsrc=%d -> %d errno=%d\n", NSRC, r,
	       r ? errno : 0);
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem] get -> %d errno=%d mode=%u count=%u first=%02x%02x..\n",
	       r, r ? errno : 0, mode, cnt, img[0][0], img[0][1]);

	for (k = 0; k < NSRC; k++)
		pat(img, k);
	/* delete every zero source, printing the count each time */
	for (k = 0; k < NSRC; k++) {
		unsigned char z[16] = {0};
		uint32_t m2, c2;

		r = edit(fd, g, MCAST_UNBLOCK_SOURCE, z);
		if (r)
			printf("[sem] del %u -> %d errno=%d\n", k, r, -r);
		if (get(fd, g, img, &m2, &c2))
			printf("[sem]   get after del %u failed (group gone?)\n",
			       k);
		else
			printf("[sem]   del %u ok count=%u mode=%u\n", k, c2, m2);
		if (r)
			break;
	}
	/* append 14 distinct sources */
	for (k = 0; k < NSRC; k++) {
		memset(src, 0, 16);
		src[0] = 0x40 + k;
		src[15] = 0x80 + k;
		r = edit(fd, g, MCAST_BLOCK_SOURCE, src);
		if (r) {
			printf("[sem] add %u -> %d errno=%d\n", k, r, -r);
			break;
		}
	}
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem] after add: get -> %d mode=%u count=%u\n", r, mode, cnt);
	if (!r) {
		int bad = 0;

		for (k = 0; k < cnt; k++)
			if (img[k][0] != 0x40 + k || img[k][15] != 0x80 + k)
				bad++;
		printf("[sem] image mismatch=%d\n", bad);
	}
	/* duplicate add must be rejected without changing the count */
	memset(src, 0, 16);
	src[0] = 0x43;
	src[15] = 0x83;
	r = edit(fd, g, MCAST_BLOCK_SOURCE, src);
	printf("[sem] dup add -> %d errno=%d\n", r, -r);
	memset(src, 0, 16);
	src[0] = 0x99;
	src[15] = 0x99;
	r = edit(fd, g, MCAST_UNBLOCK_SOURCE, src);
	printf("[sem] missing del -> %d errno=%d\n", r, -r);
	/* delete one, add one back at sl_count 13, then count again */
	memset(src, 0, 16);
	src[0] = 0x40;
	src[15] = 0x80;
	r = edit(fd, g, MCAST_UNBLOCK_SOURCE, src);
	printf("[sem] del first -> %d\n", r);
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem]   count=%u first=%02x%02x\n", cnt, img[0][0], img[0][1]);
	r = edit(fd, g, MCAST_BLOCK_SOURCE, src);
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem] re-add -> count=%u last=%02x%02x\n", cnt, img[cnt - 1][0],
	       img[cnt - 1][15]);
	/* now empty it completely: EXCLUDE must keep the membership */
	for (k = 0; k < NSRC; k++) {
		unsigned char cur[16];
		uint32_t m3, c3;

		if (get(fd, g, img, &m3, &c3) || !c3)
			break;
		memcpy(cur, img[0], 16);
		r = edit(fd, g, MCAST_UNBLOCK_SOURCE, cur);
		if (r) {
			printf("[sem] drain del %u -> %d errno=%d\n", k, r, -r);
			break;
		}
	}
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem] drained: get -> %d mode=%u count=%u\n", r, mode, cnt);
	/* membership still there?  msfilter on it must succeed */
	r = msf(fd, g, 0, NSRC);
	printf("[sem] re-msfilter -> %d errno=%d\n", r, r ? errno : 0);
	/* INCLUDE mode must be refused on a set EXCLUDE filter */
	r = msf(fd, g, 1, NSRC);
	printf("[sem] msfilter include on exclude -> %d errno=%d\n", r,
	       r ? errno : 0);
	/* and an INCLUDE-mode edit must be refused too (we send EXCLUDE) */
	r = get(fd, g, img, &mode, &cnt);
	printf("[sem] final get -> mode=%u count=%u\n", mode, cnt);

out:
	fflush(stdout);
	sync();
	return 0;
}
