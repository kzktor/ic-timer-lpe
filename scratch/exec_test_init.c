/* exec_test_init.c -- minimal initrd /init that runs the payload image the
 * way the drop path does (argv[0]="timer-poc", IC_SCAN_FD on the console),
 * so the escalated-image startup can be checked without a full chain.
 * Build with -DFAKE_UID to run it with the fake cred shape (euid 0,
 * ruid 0xffffff80).  Test harness only; nothing here touches a device. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

int main(void)
{
	int rc;

	write(2, "TEST pre\n", 9);
#ifdef FAKE_UID
	rc = setresuid((uid_t)0xffffff80u, 0, 0);
	dprintf(2, "TEST setresuid rc=%d errno=%d uid=%u euid=%u\n", rc, errno,
		(unsigned)getuid(), (unsigned)geteuid());
#endif
	{
		char *const envp[] = { (char *)"PATH=/sbin:/bin",
				       (char *)"IC_SCAN_FD=1", NULL };
		char *const argv[] = { (char *)"timer-poc", NULL };

		execve("/exploit", argv, envp);
	}
	dprintf(2, "TEST exec errno=%d\n", errno);
	for (;;)
		sleep(1000);
}
