/* Probe: which buddy migratetype do AIO ring pages come from?
 * Dump /proc/pagetypeinfo, create 4096 one-event io_setup contexts (one ring
 * page each), dump again, power off.  A drop in the Movable free counts and
 * not in Unmovable means find_or_create_page() used GFP_HIGHUSER_MOVABLE and
 * the AIO ring can never split an UNMOVABLE posix_timers block. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <linux/aio_abi.h>

#define NCTX 4096

static aio_context_t ctxs[NCTX];

static void dump(const char *tag)
{
	FILE *f = fopen("/proc/pagetypeinfo", "r");
	char line[256];

	printf("[probe] === pagetypeinfo %s ===\n", tag);
	if (!f) {
		printf("[probe] open failed %d\n", errno);
		return;
	}
	while (fgets(line, sizeof(line), f)) {
		if (strstr(line, "Unmovable") || strstr(line, "Movable") ||
		    strstr(line, "Reclaimable") || strstr(line, "Reserve") ||
		    strstr(line, "CMA") || strstr(line, "Isolate") ||
		    strstr(line, "Type") || strstr(line, "Node") ||
		    strstr(line, "Free pages count"))
			fputs(line, stdout);
	}
	fclose(f);
	fflush(stdout);
}

int main(void)
{
	int i, ok = 0;

	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	dump("before");
	for (i = 0; i < NCTX; i++) {
		aio_context_t c = 0;

		if (syscall(SYS_io_setup, 1, &c)) {
			printf("[probe] io_setup %d errno=%d\n", i, errno);
			break;
		}
		ctxs[ok++] = c;
	}
	printf("[probe] contexts=%d\n", ok);
	dump("after");
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	for (;;)
		pause();
	return 0;
}
