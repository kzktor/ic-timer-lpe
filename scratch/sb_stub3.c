/* Output channel probe: write to the UART after exec under enforcing. */
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
int main(void)
{
	char buf[128] = {0};
	int fd, i, n;
	fd = open("/proc/self/attr/current", O_RDONLY);
	if (fd >= 0) { n = read(fd, buf, sizeof(buf) - 1); if (n > 0) buf[n-1] = 0; close(fd); }
	printf("stub3 uid=%d euid=%d label=%s\n", (int)getuid(), (int)geteuid(), buf);
	fflush(stdout);
	fd = open("/dev/ttyAMA0", O_WRONLY);
	printf("stub3 uart_open=%d errno=%d\n", fd, fd < 0 ? errno : 0);
	fflush(stdout);
	if (fd >= 0) { char m[] = "stub3 direct uart write\n"; write(fd, m, sizeof(m) - 1); }
	for (i = 0; i < 3; i++) { printf("stub3 tick %d\n", i); fflush(stdout); sleep(1); }
	return 0;
}
