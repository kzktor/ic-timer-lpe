/* Minimal payload for the shellboot harness: prove where stdout goes, what
 * the process label/uid is, and whether the harness dumps the log after a
 * clean exit.  Runs as uid 2000 in u:r:shell:s0 with enforcement on. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>

int main(void)
{
	char buf[256] = {0};
	int fd, i;

	printf("stub start uid=%d euid=%d\n", (int)getuid(), (int)geteuid());
	fflush(stdout);
	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd >= 0) {
		ssize_t n = read(fd, buf, sizeof(buf) - 1);

		if (n > 0)
			buf[n - 1] = 0;
		close(fd);
		printf("stub label=%s\n", buf);
	} else {
		printf("stub label open errno=%d\n", errno);
	}
	fflush(stdout);
	for (i = 0; i < 5; i++) {
		printf("stub tick %d\n", i);
		fflush(stdout);
		sleep(1);
	}
	printf("stub exit\n");
	fflush(stdout);
	return 0;
}
