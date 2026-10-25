/*
 * Minimal initramfs /init wrapper for offline probes.
 *
 * Mounts /proc and /dev, translates the kernel command line's ic_* tokens
 * into the corresponding upper-case environment variables (the same mapping
 * the production harness uses), then runs /exploit as a child and powers
 * off.  This keeps the probe binary unchanged while letting us pick any
 * IC_* knob from QEMU's -append.
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static void setup_env(void)
{
	int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);
	char buf[4096];
	ssize_t n;
	char *save = NULL;
	char *tok;

	if (fd < 0)
		return;
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return;
	buf[n] = '\0';
	for (tok = strtok_r(buf, " \t\n", &save); tok;
	     tok = strtok_r(NULL, " \t\n", &save)) {
		char name[64];
		const char *eq = strchr(tok, '=');
		size_t len = eq ? (size_t)(eq - tok) : strlen(tok);
		size_t i;

		if (strncmp(tok, "ic_", 3) && strncmp(tok, "IC_", 3))
			continue;
		if (len >= sizeof(name))
			len = sizeof(name) - 1;
		for (i = 0; i < len; i++) {
			char c = tok[i];

			name[i] = (c >= 'a' && c <= 'z') ? (char)(c - 32) : c;
		}
		name[len] = '\0';
		setenv(name, eq ? eq + 1 : "1", 1);
	}
}

static void write_sysctl(const char *path, const char *val)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	ssize_t n;

	if (fd < 0)
		return;
	n = write(fd, val, strlen(val));
	(void)n;
	close(fd);
}

int main(void)
{
	pid_t pid;
	int st;

	(void)mkdir("/proc", 0555);
	(void)mount("proc", "/proc", "proc", 0UL, NULL);
	(void)mkdir("/dev", 0755);
	(void)mount("devtmpfs", "/dev", "devtmpfs", 0UL, NULL);
	(void)mkdir("/tmp", 0777);
	(void)mkdir("/sys", 0755);
	(void)mount("sysfs", "/sys", "sysfs", 0UL, NULL);

	setup_env();

	{
		char cl[256] = "?";
		int fd = open("/proc/cmdline", O_RDONLY | O_CLOEXEC);

		if (fd >= 0) {
			ssize_t n = read(fd, cl, sizeof(cl) - 1);

			if (n > 0) {
				cl[n] = '\0';
			}
			close(fd);
		}
		fprintf(stderr, "[initwrap] cmdline=%s\n[initwrap] probe=%s dump=%s\n",
			cl, getenv("IC_PAGEPROBE") ? "set" : "NULL",
			getenv("IC_DUMPPT") ? "set" : "NULL");
		fflush(stderr);
	}

	{
		const char *v = getenv("IC_PERF_PARANOID");

		if (v)
			write_sysctl("/proc/sys/kernel/perf_event_paranoid", v);
		v = getenv("IC_AIO_MAXNR");
		if (v)
			write_sysctl("/proc/sys/fs/aio-max-nr", v);
	}

	pid = fork();
	if (pid == 0) {
		char *const argv[] = { (char *)"exploit", NULL };

		(void)execv("/exploit", argv);	/* inherits the ic_* env */
		_exit(127);
	}
	if (pid > 0)
		(void)waitpid(pid, &st, 0);

	sync();
	(void)reboot(RB_POWER_OFF);
	for (;;)
		pause();
	return 0;
}
