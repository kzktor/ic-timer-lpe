/* Does a shell-domain process get to write a null_device char node? */
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
int main(void)
{
	int fd = open("/dev/ic-out", O_WRONLY);
	if (fd < 0) return 10;
	write(fd, "stub4 hello from shell domain\n", 30);
	sleep(2);
	write(fd, "stub4 bye\n", 10);
	close(fd);
	return 0;
}
