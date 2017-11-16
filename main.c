
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <stdlib.h>

#include "arp_dev.h"
#include "arp_frame.h"
#include "arp_table.h"
#include "log.h"
#include "time_utils.h"
#include "arp_net.h"

int main(int ac, char **av)
{
	int ret = 1;
	const char *dev = (ac >= 2) ? av[1] : "eth0";
	const char *from = (ac >= 3) ? av[2] : NULL;
	const char *to = (ac >= 4) ? av[3] : NULL;
	int i;
	struct arp_dev info;
	int sock;
	struct sockaddr_ll saddr;
	struct arp_frame req;
	struct arp_table table;
	struct in_addr daddr_from;
	struct in_addr daddr_to;
	long delay_ms = 1000;
	long expire_ms;
	long poll_ms;
	struct in_addr current_dest;
	struct timespec last_stat;
	struct timespec last_req;

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
		daddr_from.s_addr = (info.addr.s_addr & info.netmask.s_addr) + htonl(1);
	else {
		if (inet_aton(from, &daddr_from) == 0) {
			err("Invalid from : %s\n", from);
			goto usage;
		}
	}

	if (to == NULL)
		daddr_to.s_addr = info.broadcast.s_addr - htonl(1);
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

	sock = arp_socket(&info, &saddr);
	if (sock < 0)
		goto err;

	arp_frame_req(&info, &req);
	arp_table_init(&table, 1, 1);

	memset(&last_req, 0, sizeof last_req);
	memset(&last_stat, 0, sizeof last_stat);
	current_dest = daddr_from;
	expire_ms = delay_ms * (htonl(daddr_to.s_addr) - htonl(daddr_from.s_addr)) * 8; /* Enough time to discover all the network */
	poll_ms = (delay_ms <= 1) ? 1 : delay_ms / 2;

	for (;;) {
		struct timespec now, dt;
		int ret;

		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		chk(ret >= 0);
		timespec_sub(&now, &last_req, &dt);
		if (timespec_to_ms(&dt) >= delay_ms) {
			if (arp_send(sock, &saddr, &req, daddr_from, daddr_to, &current_dest) < 0)
				goto err;
			last_req = now;
		}

		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		chk(ret >= 0);
		timespec_sub(&now, &last_stat, &dt);
		if (timespec_to_ms(&dt) >= expire_ms) {
			arp_table_check_expired(&table, &now, expire_ms);
			arp_table_dump(&table);
			last_stat = now;
		}

		if (arp_recv(sock, poll_ms, &table) < 0)
			goto err;
	}

	arp_dev_deinit(&info);

	ret = 0;
err:
	return ret;
}
