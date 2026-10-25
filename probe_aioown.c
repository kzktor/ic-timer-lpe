/* Probe: show the page_owner record of AIO ring pages.
 * Boot with page_owner=on stack_depot_disable=0.  Creates NCTX 1-event
 * io_setup contexts (one 4K ring page each), then walks
 * /sys/kernel/debug/page_owner one record per read(), printing every record
 * whose stack contains pagecache_get_page / find_or_create_page together with
 * its "Page allocated via order N, mask 0x..." header.  The mask tells us
 * whether __GFP_MOVABLE was set, i.e. whether a ring page can ever be taken
 * from the UNMOVABLE posix_timers slab. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <linux/aio_abi.h>

#define NCTX 64
#define REC 4096

int main(void)
{
	static char buf[REC];
	aio_context_t ctxs[NCTX];
	int fd, i, ok = 0;
	ssize_t n;
	unsigned long recs = 0, matches = 0;

	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/sys", 0755);
	mkdir("/sys/kernel", 0755);
	mkdir("/sys/kernel/debug", 0755);
	if (mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL))
		printf("[probe] debugfs mount errno=%d\n", errno);

	for (i = 0; i < NCTX; i++) {
		ctxs[i] = 0;
		if (syscall(SYS_io_setup, 1, &ctxs[i]))
			break;
		ok++;
	}
	printf("[probe] contexts=%d\n", ok);

	fd = open("/sys/kernel/debug/page_owner", O_RDONLY);
	if (fd < 0) {
		printf("[probe] page_owner open errno=%d\n", errno);
		goto out;
	}
	while ((n = read(fd, buf, REC)) > 0) {
		recs++;
		if (memmem(buf, (size_t)n, "pagecache_get_page", 18) ||
		    memmem(buf, (size_t)n, "find_or_create_page", 19)) {
			matches++;
			printf("[probe] === match %lu (rec %lu, n=%ld) ===\n",
			       matches, recs, (long)n);
			fwrite(buf, 1, (size_t)n, stdout);
			fputc('\n', stdout);
			fflush(stdout);
		}
	}
	close(fd);
	printf("[probe] records=%lu matches=%lu errno=%d\n", recs, matches,
	       errno);
out:
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	for (;;)
		pause();
	return 0;
}
