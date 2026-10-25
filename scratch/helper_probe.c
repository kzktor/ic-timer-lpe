/* Freestanding aarch64 probe used as /tmp/ic-exec-helper in the harness.
 *
 * The exploit's fork-child (fake cred: ruid -128, euid 0) execs this file.
 * It uses no libc at all, so it reports the state that any exec'd image
 * sees at its very first instruction: if its marker never shows up the
 * exec itself is what kills the image, not musl startup.
 *
 * Only raw syscalls: write(2), getresuid, openat, exit.
 */

static long sc(long n, long a, long b, long c, long d)
{
	register long x0 asm("x0") = a;
	register long x1 asm("x1") = b;
	register long x2 asm("x2") = c;
	register long x3 asm("x3") = d;
	register long x8 asm("x8") = n;

	asm volatile("svc #0"
		     : "+r"(x0)
		     : "r"(x1), "r"(x2), "r"(x3), "r"(x8)
		     : "memory", "x4", "x5", "x6", "x7");
	return x0;
}

static long slen(const char *s)
{
	long n = 0;

	while (s[n])
		n++;
	return n;
}

static void sw(const char *s)
{
	sc(64 /* write */, 2, (long)s, slen(s), 0);
}

static void shex(unsigned int v)
{
	static const char hex[] = "0123456789abcdef";
	char b[9];
	int i;

	for (i = 0; i < 8; i++)
		b[i] = hex[(v >> (28 - 4 * i)) & 0xf];
	b[8] = 0;
	sw(b);
}

void _start(void)
{
	unsigned int ruid = 0, euid = 0, suid = 0;
	long fd;

	sw("HELPER-RAN uid=");
	sc(148 /* getresuid */, (long)&ruid, (long)&euid, (long)&suid, 0);
	shex(ruid);
	sw("/");
	shex(euid);
	sw("/");
	shex(suid);
	sw("\n");

	fd = sc(56 /* openat */, -100, (long)"/tmp/probe-ok",
		0x241 /* O_WRONLY|O_CREAT|O_TRUNC */, 0666);
	if (fd >= 0) {
		sc(64, fd, (long)"PROBE-OK\n", 9, 0);
		sc(57 /* close */, fd, 0, 0, 0);
	}
	for (;;)
		sc(93 /* exit */, 0, 0, 0, 0);
}
