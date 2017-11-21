
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <signal.h>
#include <limits.h>

#include "arpinger.h"
#include "log.h"


static size_t sig_table[NSIG] = { 0 };
static size_t sig_count = 0;

static void sig_handler(int sig)
{
	if (sig >= 0 && (size_t )sig < sizeof sig_table / sizeof sig_table[0]) {
		sig_table[sig] ++;
		sig_count ++;
	}
}

int main(int ac, char **av)
{
	int ret = 1;
	const char *dev = (ac >= 2) ? av[1] : NULL;
	const char *from = (ac >= 3) ? av[2] : NULL;
	const char *to = (ac >= 4) ? av[3] : NULL;
	const char *req_delay_str = (ac >= 5) ? av[4] : NULL;
	int i;
	int stop_main_loop = 0;
	long req_delay_ms;
	struct arpinger arpinger;

	for (i = 1 ; i < ac ; i++) {
		if (strcmp(av[i], "-help") == 0 || strcmp(av[i], "--help") == 0) {
		usage:
			fprintf(stderr, "Usage : %s [device] [from] [to]\n", av[0]);
			return 1;
		}
	}

	if (req_delay_str == NULL)
		req_delay_ms = 1000;
	else {

		char *ptr;
		long long l;

		errno = 0;
		l = strtoll(req_delay_str, &ptr, 0);
		if (l > LONG_MAX || l < 0 || *ptr != 0 || errno != 0) {
			err("Invalid req_delay_str : %s (%m)\n", req_delay_str);
			abort();
			goto usage;
		}

		req_delay_ms = (long )l;
	}

	if (arpinger_init(&arpinger, dev, from, to, req_delay_ms, 4, 16) < 0)
		goto err;

	signal(SIGHUP, sig_handler);
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	while (!stop_main_loop) {
		ssize_t changed;

		changed = arpinger_loop(&arpinger);
		if (changed < 0)
			goto err;

		if (changed > 0) {
			char *res = NULL;

			printf("+++\n");

			printf("+ Table changed\n");
			if (arp_table_dump(&arpinger.table, &res, "+ ", "\n") > 0 && res != NULL) {
				printf("%s", res);
				free(res);
			} else
				printf("Empty");
			printf("+++\n");
		}


		for (size_t idx = 0 ; sig_count > 0 && idx < sizeof sig_table / sizeof sig_table[0] ; idx++) {

			while (sig_count > 0 && sig_table[idx] > 0) {

				switch (idx) {
				default:
					wrn("Got SIG%zd\n", idx);
					break;

				case SIGHUP:
				{
					char *res = NULL;

					printf("+++\n");
					if (arp_table_dump(&arpinger.table, &res, "+ ", "\n") > 0 && res != NULL) {
						printf("%s", res);
						free(res);
					} else
						printf("Empty");
					printf("+++\n");

					break;
				}

				case SIGTERM:
				case SIGINT:
					stop_main_loop = 1;
					break;
				}

				sig_table[idx]--;
				sig_count--;
			}
		}
	}

	arpinger_free(&arpinger);
	ret = 0;
err:
	return ret;
}
