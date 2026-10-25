/* Probe: is debugfs/page_owner readable here? */
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <linux/reboot.h>

int main(void)
{
	int fd;
	ssize_t n;
	static char buf[8192];
	struct stat st;
	DIR *d;

	mkdir("/proc", 0755);
	mount("proc", "/proc", "proc", 0, NULL);
	mkdir("/sys", 0755);
	mkdir("/sys/kernel", 0755);
	mkdir("/sys/kernel/debug", 0755);
	printf("[dbg] mount rc=%d errno=%d\n",
	       mount("debugfs", "/sys/kernel/debug", "debugfs", 0, NULL), errno);
	d = opendir("/sys/kernel/debug");
	if (d) {
		struct dirent *e;

		printf("[dbg] debugfs entries:");
		while ((e = readdir(d)))
			if (strstr(e->d_name, "page") || strstr(e->d_name, "stack"))
				printf(" %s", e->d_name);
		printf("\n");
		closedir(d);
	} else {
		printf("[dbg] opendir errno=%d\n", errno);
	}
	fd = open("/sys/kernel/debug/page_owner", O_RDONLY);
	printf("[dbg] open=%d errno=%d\n", fd, errno);
	if (fd >= 0) {
		if (!fstat(fd, &st))
			printf("[dbg] size=%lld mode=%o\n",
			       (long long)st.st_size, st.st_mode);
		n = read(fd, buf, 4096);
		printf("[dbg] read=%ld errno=%d\n", (long)n, errno);
		if (n > 0)
			fwrite(buf, 1, (size_t)n > 512 ? 512 : (size_t)n,
			       stdout);
		printf("\n");
		n = read(fd, buf, 4096);
		printf("[dbg] read2=%ld errno=%d\n", (long)n, errno);
		close(fd);
	}
	fflush(stdout);
	sync();
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	for (;;)
		pause();
	return 0;
}
