#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int main(int argc, char **argv)
{
	char buf[256];
	int fd, n;

	(void)argc;
	(void)argv;
	printf("[seltest] euid=%d egid=%d\n", (int)geteuid(), (int)getegid());
	fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
	if (fd >= 0) {
		n = (int)read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (n > 0) {
			buf[n] = '\0';
			printf("[seltest] context=%s", buf);
		}
	} else {
		printf("[seltest] attr/current open errno=%d\n", errno);
	}
	fflush(stdout);
	return 0;
}
