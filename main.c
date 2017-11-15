
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <time.h>
#include <stdlib.h>

#include "arp_dev.h"
#include "arp_frame.h"
#include "arp_table.h"
#include "log.h"
#include "time_utils.h"

int arp_socket(const struct arp_dev *dev, struct sockaddr_ll *daddr)
{
	int sock = -1;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sock < 0) {
		err("socket SOCK_RAW : %m\n");
		goto err;
	}

	memset(daddr, 0, sizeof daddr[0]);
	daddr->sll_ifindex = dev->index;
	daddr->sll_family = AF_PACKET;
	memcpy(daddr->sll_addr, dev->hwaddr, sizeof dev->hwaddr);
	daddr->sll_halen = sizeof dev->hwaddr;

err:
	return sock;
}

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
	struct pollfd fds;
	struct arp_table table;
	struct in_addr daddr_from;
	struct in_addr daddr_to;
	long delay_ms = 1000;
	long expire_ms;
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
		daddr_to.s_addr = info.broadcast.s_addr - 1;
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

	fds.fd = sock;
	fds.events = POLLIN | POLLERR;
	fds.revents = 0;
	memset(&last_req, 0, sizeof last_req);
	memset(&last_stat, 0, sizeof last_stat);
	current_dest = daddr_from;
	expire_ms = delay_ms * (htonl(daddr_to.s_addr) - htonl(daddr_from.s_addr)) * 8; /* Enough time to discover all the network */

	arp_table_init(&table, 1, 1);

	for (;;) {
		struct arp_frame resp;
		ssize_t resp_len;
		struct timespec now, dt;
		int ret;

		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		chk(ret >= 0);
		timespec_sub(&now, &last_req, &dt);
		if (timespec_to_ms(&dt) >= delay_ms) { /* Convert in ms ! */

			arp_frame_set_target_addr(&req, current_dest);
			vrb("ARP_REQ %s\n", inet_ntoa(arp_frame_get_target_addr(&req)));

			if (sendto(sock, &req, sizeof req, 0, (struct sockaddr *)&saddr, sizeof saddr) <= 0) {
				err("sendto : %m\n");
				goto err;
			}

			current_dest.s_addr += htonl(1);
			if (current_dest.s_addr > daddr_to.s_addr)
				current_dest = daddr_from;
			last_req = now;
		}

		ret = clock_gettime(CLOCK_MONOTONIC, &now);
		chk(ret >= 0);
		timespec_sub(&now, &last_stat, &dt);
		if (timespec_to_ms(&dt) >= expire_ms) {
			arp_table_check_expired(&table, &now, expire_ms);
			arp_table_dump_seen(&table);
			last_stat = now;
		}

		i = poll(&fds, 1, (delay_ms <= 1) ? 1 : delay_ms / 2);
		if (i < 0) {
			err("poll : %m\n");
			goto err;
		}

		if (i > 0) {

			resp_len = recvfrom(sock, &resp, sizeof resp, MSG_DONTWAIT, NULL, 0);
			if (resp_len < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
				err("recvfrom : %m\n");
				goto err;
			}

			if ((size_t )resp_len >= sizeof resp && arp_frame_check(&resp)) {

				if (is_vrb()) {
					char *res;
					if (arp_frame_dump(&resp, &res) > 0) {
						vrb("ARP_RSP :\n%s\n", res);
						free(res);
					}
				}

				arp_table_add(&table, arp_frame_get_source_addr(&resp), arp_frame_get_source_hwaddr(&resp), &now);
			}
		}
	}

	arp_dev_deinit(&info);

	ret = 0;
err:
	return ret;
}
