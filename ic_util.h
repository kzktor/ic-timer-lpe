#ifndef INFINITYCORE_ANDROID_UTIL_H
#define INFINITYCORE_ANDROID_UTIL_H

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "ic_compat.h"
#include "ic_target.h"

static inline int ic_pin_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	return sched_setaffinity(0, sizeof(set), &set);
}

static inline int ic_cpu_count(void)
{
	long n = sysconf(_SC_NPROCESSORS_ONLN);

	return n > 0 ? (int)n : 1;
}

static inline void ic_futex_wait(int *p, int expected)
{
	ic_syscall6(SYS_futex, (long)p, FUTEX_WAIT_PRIVATE, expected, 0, 0, 0);
}

static inline void ic_futex_wake(int *p, int n)
{
	ic_syscall6(SYS_futex, (long)p, FUTEX_WAKE_PRIVATE, n, 0, 0, 0);
}

static inline uint64_t ic_now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static inline void ic_spin_until_ns(uint64_t deadline)
{
	while (ic_now_ns() < deadline)
		ic_cpu_relax();
}

static inline void ic_die(const char *what)
{
	perror(what);
	exit(EXIT_FAILURE);
}

static inline void *ic_map_rw(size_t len)
{
	void *p = mmap(NULL, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_POPULATE, -1, 0);

	if (p == MAP_FAILED)
		return NULL;
	return p;
}

static inline void *ic_map_rw_fixed(void *addr, size_t len)
{
	void *p = mmap(addr, len, PROT_READ | PROT_WRITE,
		       MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED_NOREPLACE, -1, 0);

	if (p == MAP_FAILED)
		return NULL;
	return p;
}

static inline int ic_write_all(int fd, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = write(fd, p + done, len - done);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!n)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

static inline int ic_read_all(int fd, void *buf, size_t len)
{
	unsigned char *p = buf;
	size_t done = 0;

	while (done < len) {
		ssize_t n = read(fd, p + done, len - done);

		if (n < 0) {
			if (errno == EINTR)
				continue;
			return -1;
		}
		if (!n)
			return -1;
		done += (size_t)n;
	}
	return 0;
}

static inline int ic_copy_self(int out_fd)
{
	int in = open("/proc/self/exe", O_RDONLY | O_CLOEXEC);
	unsigned char buf[65536];

	if (in < 0)
		return -1;
	for (;;) {
		ssize_t n = read(in, buf, sizeof(buf));

		if (n < 0) {
			if (errno == EINTR)
				continue;
			close(in);
			return -1;
		}
		if (!n)
			break;
		if (ic_write_all(out_fd, buf, (size_t)n)) {
			close(in);
			return -1;
		}
	}
	close(in);
	return 0;
}

static inline int ic_make_staging_path(char *out, size_t out_len,
				       const char *tag)
{
	const char *dir = IC_STAGING_DIR_DEFAULT;
	int n;

	if (access(dir, W_OK) != 0)
		dir = "/data/local/tmp";
	n = snprintf(out, out_len, "%s/.ic-%s-%d", dir, tag, (int)getpid());
	return n > 0 && (size_t)n < out_len ? 0 : -1;
}

static inline void ic_launch_root_shell(void)
{
	char *const argv[] = { (char *)"sh", (char *)"-i", NULL };

	setuid(0);
	setgid(0);
	setresuid(0, 0, 0);
	setresgid(0, 0, 0);
	execve(IC_SHELL_BINARY, argv, NULL);
	execve("/system/bin/sh", argv, NULL);
	execve("/bin/sh", argv, NULL);
}

static inline int ic_is_root(void)
{
	return syscall(SYS_getuid) == 0;
}

static inline void ic_zero_cred_fields(void *cred_base)
{
	unsigned char *c = cred_base;

	*(uint32_t *)(c + OFF_CRED_UID) = 0;
	*(uint32_t *)(c + OFF_CRED_GID) = 0;
	*(uint32_t *)(c + OFF_CRED_EUID) = 0;
	*(uint32_t *)(c + OFF_CRED_EGID) = 0;
	*(uint32_t *)(c + OFF_CRED_SUID) = 0;
	*(uint32_t *)(c + OFF_CRED_SGID) = 0;
	*(uint32_t *)(c + OFF_CRED_FSUID) = 0;
	*(uint32_t *)(c + OFF_CRED_FSGID) = 0;
	*(uint64_t *)(c + OFF_CRED_CAP_INHERITABLE) = ~0ULL;
	*(uint64_t *)(c + OFF_CRED_CAP_PERMITTED) = ~0ULL;
	*(uint64_t *)(c + OFF_CRED_CAP_EFFECTIVE) = ~0ULL;
}

static inline int ic_kernel_pointer(uint64_t v)
{
	uint64_t tagged = v & KERNEL_POINTER_TAG_MASK;

	return (tagged >= KERNEL_LOGICAL_BASE) && !(v & 0x7);
}

static inline int ic_write_file(const char *path, const char *data)
{
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	size_t len = strlen(data);

	if (fd < 0)
		return -1;
	if (ic_write_all(fd, data, len)) {
		close(fd);
		return -1;
	}
	close(fd);
	return 0;
}

#endif