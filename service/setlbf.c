#include <stdio.h>

static void __attribute__((constructor)) setlbf(void)
{
	setbuf(stdout, NULL);
}
