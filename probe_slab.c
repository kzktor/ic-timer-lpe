/* Probe-only init: dump /proc/slabinfo (cache geometry) then power off.
 * Not part of the exploit deliverable; booted in QEMU with the same kernel
 * image so the numbers match the exploit runs. */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/reboot.h>
#include <linux/reboot.h>
#include <sys/mount.h>
#include <sys/stat.h>

static void dump(const char *path)
{
	FILE *f = fopen(path, "r");
	char line[512];

	if (!f) {
		printf("[probe] cannot open %s\n", path);
		return;
	}
	printf("[probe] === %s ===\n", path);
	while (fgets(line, sizeof(line), f))
		fputs(line, stdout);
	fclose(f);
	fflush(stdout);
}

int main(void)
{
	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	dump("/proc/slabinfo");
	dump("/proc/sys/fs/aio-max-nr");
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	for (;;)
		pause();
	return 0;
}
