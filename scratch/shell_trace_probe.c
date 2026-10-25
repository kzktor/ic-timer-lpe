/* shell_trace_probe.c -- run as /exploit under the shellboot harness, i.e.
 * as uid 2000 in u:r:shell:s0 with the device's policy enforcing, and report
 * which kernel-observation interfaces that identity can actually use.
 *
 * This decides the exploit's safety architecture: if the shell can own
 * kprobes on the allocator, the reclaim can be proven before the destructive
 * reap (the nezha design) instead of guessed with a fill.  Read-mostly: the
 * only writes are to tracefs control files inside the throwaway QEMU guest.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int try_open(const char *path, int flags)
{
	int fd = open(path, flags | O_CLOEXEC);

	fprintf(stderr, "[probe] open %-64s -> %d errno=%d (%s)\n",
		path, fd, fd < 0 ? errno : 0, fd < 0 ? strerror(errno) : "ok");
	return fd;
}

static void try_read(const char *path, size_t n)
{
	char buf[256];
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	ssize_t r;

	if (fd < 0) {
		fprintf(stderr, "[probe] read %-64s open errno=%d (%s)\n",
			path, errno, strerror(errno));
		return;
	}
	r = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (r < 0) {
		fprintf(stderr, "[probe] read %-64s errno=%d (%s)\n", path,
			errno, strerror(errno));
		return;
	}
	buf[r] = '\0';
	for (ssize_t i = 0; i < r; i++)
		if (buf[i] == '\n')
			buf[i] = ' ';
	fprintf(stderr, "[probe] read %-64s = \"%s\"\n", path, buf);
}

static void try_stat(const char *path)
{
	struct stat st;

	if (stat(path, &st)) {
		fprintf(stderr, "[probe] stat %-64s errno=%d (%s)\n", path,
			errno, strerror(errno));
		return;
	}
	fprintf(stderr, "[probe] stat %-64s mode=%04o uid=%u gid=%u\n",
		path, st.st_mode & 07777, st.st_uid, st.st_gid);
}

static void try_list(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *de;
	unsigned int n = 0;

	if (!d) {
		fprintf(stderr, "[probe] list %-64s errno=%d (%s)\n", path,
			errno, strerror(errno));
		return;
	}
	fprintf(stderr, "[probe] list %s:", path);
	while ((de = readdir(d)) && n < 40) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		fprintf(stderr, " %s", de->d_name);
		n++;
	}
	fprintf(stderr, "\n");
	closedir(d);
}

int main(void)
{
	char ctx[128];
	ssize_t n;
	int fd;
	const char *tr = "/sys/kernel/tracing";
	const char *logp = getenv("IC_LOG_PATH");

	/* First thing: prove the binary ran and find a channel that survives
	 * the policy.  /dev/ic-out is the null_device console clone. */
	{
		static const char *const outs[] = { "/dev/ic-out",
						    "/dev/ttyAMA0",
						    "/dev/console" };
		unsigned int o;

		for (o = 0; o < sizeof(outs) / sizeof(outs[0]); o++) {
			int t = open(outs[o], O_WRONLY | O_APPEND | O_CLOEXEC);

			if (t >= 0) {
				(void)write(t, "PROBE-START\n", 12);
				close(t);
			}
		}
		(void)write(1, "PROBE-START\n", 12);
		(void)write(2, "PROBE-START\n", 12);
	}

	/* The harness's shell child gets its stdio on a file init can no
	 * longer read once the policy is enforced; the null_device console
	 * clone is the channel that survives. */
	if (logp && *logp) {
		int lf = open(logp, O_WRONLY | O_APPEND | O_CLOEXEC);

		if (lf >= 0) {
			(void)dup2(lf, 1);
			(void)dup2(lf, 2);
			if (lf > 2)
				close(lf);
		}
	}

	n = readlink("/proc/self/attr/current", ctx, sizeof(ctx) - 1);
	if (n > 0) {
		ctx[n] = '\0';
	} else {
		int f = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);

		n = f >= 0 ? read(f, ctx, sizeof(ctx) - 1) : -1;
		if (f >= 0)
			close(f);
		if (n > 0)
			ctx[n] = '\0';
		else
			snprintf(ctx, sizeof(ctx), "?errno=%d", errno);
	}
	fprintf(stderr, "[probe] uid=%u euid=%u ctx=%s\n", (unsigned)getuid(),
		(unsigned)geteuid(), ctx);

	try_stat(tr);
	try_stat("/proc/slabinfo");
	try_stat("/sys/kernel/slab/posix_timers_cache");

	/* Read side of tracefs. */
	try_open("/sys/kernel/tracing/trace", O_RDONLY);
	try_open("/sys/kernel/tracing/trace_pipe", O_RDONLY | O_NONBLOCK);
	try_open("/sys/kernel/tracing/trace_pipe_raw", O_RDONLY | O_NONBLOCK);
	try_read("/sys/kernel/tracing/kprobe_profile", 0);

	/* Write side: the question that decides the architecture. */
	fd = try_open("/sys/kernel/tracing/kprobe_events", O_WRONLY | O_APPEND);
	if (fd >= 0) {
		const char *probe = "p:icprobe __arm64_sys_getpid\n";
		ssize_t w = write(fd, probe, strlen(probe));

		fprintf(stderr, "[probe] write probe -> %zd errno=%d (%s)\n", w,
			w < 0 ? errno : 0, w < 0 ? strerror(errno) : "ok");
		close(fd);
		if (w > 0) {
			try_read("/sys/kernel/tracing/kprobe_profile", 0);
			fd = open("/sys/kernel/tracing/events/kprobes/icprobe/enable",
				  O_WRONLY | O_CLOEXEC);
			fprintf(stderr,
				"[probe] open enable icprobe -> %d errno=%d\n",
				fd, fd < 0 ? errno : 0);
			if (fd >= 0)
				close(fd);
			fd = open("/sys/kernel/tracing/trace", O_WRONLY |
				  O_TRUNC | O_CLOEXEC);
			if (fd >= 0)
				close(fd);
			(void)getpid();
			usleep(50000);
			try_read("/sys/kernel/tracing/trace", 0);
			fd = open("/sys/kernel/tracing/kprobe_events",
				  O_WRONLY | O_APPEND | O_CLOEXEC);
			if (fd >= 0) {
				const char *del = "-:icprobe\n";
				ssize_t w2 = write(fd, del, strlen(del));

				fprintf(stderr,
					"[probe] remove probe -> %zd errno=%d\n",
					w2, w2 < 0 ? errno : 0);
				close(fd);
			}
		}
	}

	/* Slab geometry through sysfs (an oracle candidate). */
	try_read("/sys/kernel/slab/posix_timers_cache/objects", 0);
	try_read("/sys/kernel/slab/posix_timers_cache/slabs", 0);
	try_read("/sys/kernel/slab/posix_timers_cache/partial", 0);
	try_read("/sys/kernel/slab/posix_timers_cache/offset", 0);
	try_read("/proc/slabinfo", 0);

	/* Vendor allocator tracepoints. */
	try_list("/sys/kernel/tracing/events/vivo_rsc");
	try_list("/sys/kernel/tracing/events/kmem");

	try_read("/proc/timer_list", 0);
	try_read("/proc/zoneinfo", 0);

	fprintf(stderr, "[probe] done\n");
	return 0;
}
