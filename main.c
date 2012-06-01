#include <getopt.h>
#include "procd.h"

int debug = 0;

static int usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [options]\n"
		"Options:\n"
		"    -s <path>:		Path to ubus socket\n"
		"    -d:		Enable debug messages\n"
		"\n", prog);
	return 1;
}

int main(int argc, char **argv)
{
	int ch;

	while ((ch = getopt(argc, argv, "ds:")) != -1) {
		switch (ch) {
		case 's':
			ubus_socket = optarg;
			break;
		case 'd':
			debug++;
			break;
		default:
			return usage(argv[0]);
		}
	}
	uloop_init();
	procd_connect_ubus();
	uloop_run();

	return 0;
}
