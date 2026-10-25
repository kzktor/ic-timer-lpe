/* Minimal init for the 13.2 kernel: mount fs, dump geometry, test io_setup. */
#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <signal.h>
#include <time.h>
#include <linux/aio_abi.h>

static void show(const char *p)
{
	char b[256];
	int fd = open(p, O_RDONLY);
	ssize_t n;

	if (fd < 0) {
		printf("%s: <open %d>\n", p, errno);
		return;
	}
	n = read(fd, b, sizeof(b) - 1);
	close(fd);
	if (n < 0)
		n = 0;
	b[n] = 0;
	for (int i = 0; i < n; i++)
		if (b[i] == '\n')
			b[i] = ' ';
	printf("%s: %s\n", p, b);
}

int main(void)
{
	aio_context_t ctx = 0;
	unsigned long i;
	int rc;

	mkdir("/proc", 0555);
	mkdir("/sys", 0555);
	mkdir("/dev", 0755);
	mkdir("/tmp", 0777);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	mount("tmpfs", "/tmp", "tmpfs", 0, "mode=1777,size=64M");

	printf("=== PROBE132 ===\n");
	show("/proc/version");
	show("/sys/devices/system/cpu/online");
	show("/sys/kernel/slab/posix_timers_cache/object_size");
	show("/sys/kernel/slab/posix_timers_cache/objs_per_slab");
	show("/sys/kernel/slab/posix_timers_cache/order");
	show("/sys/kernel/slab/posix_timers_cache/cpu_partial");
	show("/sys/kernel/slab/posix_timers_cache/objects");
	show("/sys/kernel/slab/posix_timers_cache/slabs");
	show("/sys/kernel/slab/kmalloc-512/order");
	show("/sys/kernel/slab/kmalloc-512/objs_per_slab");
	show("/proc/sys/fs/aio-max-nr");

	show("/sys/kernel/slab/posix_timers_cache/objects");
	rc = syscall(SYS_io_setup, 128, &ctx);
	printf("io_setup(128) rc=%d ctx=%#llx errno=%d\n", rc,
	       (unsigned long long)ctx, errno);
	show("/sys/kernel/slab/posix_timers_cache/objects");
	if (!rc) {
		syscall(SYS_io_destroy, ctx);
		printf("io_destroy ok\n");
	}

	/* timer_create allocates from posix_timers_cache */
	{
		struct sigevent ev;
		timer_t t = 0;

		memset(&ev, 0, sizeof(ev));
		ev.sigev_notify = SIGEV_NONE;
		rc = timer_create(CLOCK_MONOTONIC, &ev, &t);
		printf("timer_create rc=%d errno=%d\n", rc, errno);
		show("/sys/kernel/slab/posix_timers_cache/objects");
		if (!rc) {
			struct itimerspec its;

			memset(&its, 0, sizeof(its));
			its.it_value.tv_sec = 3600;
			rc = timer_settime(t, 0, &its, NULL);
			printf("timer_settime rc=%d errno=%d\n", rc, errno);
			show("/sys/kernel/slab/posix_timers_cache/objects");
			timer_delete(t);
		}
	}

	(void)i;
	printf("=== PROBE132 DONE ===\n");
	fflush(stdout);
	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
