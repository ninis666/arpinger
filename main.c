
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <signal.h>

#include "arp_dev.h"
#include "arp_frame.h"
#include "arp_table.h"
#include "log.h"
#include "time_utils.h"
#include "arp_net.h"

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
	const char *dev = (ac >= 2) ? av[1] : "eth0";
	const char *from = (ac >= 3) ? av[2] : NULL;
	const char *to = (ac >= 4) ? av[3] : NULL;
	int i;
	struct arp_dev info;
	struct arp_table table;
	struct in_addr daddr_from;
	struct in_addr daddr_to;
	long delay_ms = 1000;
	long expire_ms;
	long poll_ms;
	struct arp_net net;
	int stop_main_loop = 0;

	for (i = 1 ; i < ac ; i++) {
		if (strcmp(av[i], "-help") == 0 || strcmp(av[i], "--help") == 0) {
		usage:
			fprintf(stderr, "Usage : %s [device] [from] [to]\n", av[0]);
			return 1;
		}
	}

	if (arp_dev_init(-1, &info, dev) < 0)
		goto err;

	if (from == NULL)
		memset(&daddr_from, 0, sizeof daddr_from);
	else {
		if (inet_aton(from, &daddr_from) == 0) {
			err("Invalid from : %s\n", from);
			goto usage;
		}
	}

	if (to == NULL)
		memset(&daddr_to, 0, sizeof daddr_to);
	else {
		if (inet_aton(to, &daddr_to) == 0) {
			err("Invalid to : %s\n", to);
			goto usage;
		}
	}

	if (is_dbg()) {
		char *res;

		if (arp_dev_dump(&info, &res) > 0) {
			dbg("Using :\n%s\n", res);
			free(res);
		}
	}

	if (arp_net_init(&net, &info, daddr_from, daddr_to) < 0)
		goto err;

	if (arp_table_init(&table, 1, 1) < 0)
		goto err;

	expire_ms = 4 * delay_ms * (htonl(net.to.s_addr) - htonl(net.from.s_addr)); /* Enough time to discover all the network */
	poll_ms = (delay_ms <= 1) ? 1 : delay_ms / 2;

	signal(SIGHUP, sig_handler);

	while (!stop_main_loop) {

		if (arp_net_loop(&net, delay_ms, poll_ms, &table) < 0)
			goto err;

		arp_table_check_expired(&table, expire_ms);


		for (size_t idx = 0 ; sig_count > 0 && idx < sizeof sig_table / sizeof sig_table[0] ; idx++) {

			while (sig_count > 0 && sig_table[idx] > 0) {

				switch (idx) {
				default:
					wrn("Got SIG%zd\n", idx);
					break;

				case SIGHUP:
					arp_table_dump(&table);
					break;

				case SIGINT:
					stop_main_loop = 1;
					break;
				}

				sig_table[idx]--;
				sig_count--;
			}
		}
	}

	arp_dev_deinit(&info);

	ret = 0;
err:
	return ret;
}
