
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <time.h>
#include <stdlib.h>

#include "arp_dev.h"
#include "arp_frame.h"
#include "log.h"
#include "arp_table.h"

#define timespec_sub(a, b, res) set_normalized_timespec((res), (a)->tv_sec - (b)->tv_sec, (a)->tv_nsec - (b)->tv_nsec)

void set_normalized_timespec(struct timespec *ts, const time_t sec, const long nsec)
{
	const long nsec_per_sec = (1 * 1000 * 1000 * 1000);

	ts->tv_sec = sec;
	ts->tv_nsec = nsec;

	while (ts->tv_nsec >= nsec_per_sec) {
		ts->tv_nsec -= nsec_per_sec;
		++ts->tv_sec;
	}

	while (ts->tv_nsec < 0) {
		ts->tv_nsec += nsec_per_sec;
		--ts->tv_sec;
	}
}

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
	struct timespec last;
	struct arp_table table;
	struct in_addr daddr_from;
	struct in_addr daddr_to;

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
	memset(&last, 0, sizeof last);

	arp_table_init(&table, 2, 2);

	long delay_ms = 1000;
	struct in_addr current_dest = daddr_from;

	for (;;) {
		struct arp_frame resp;
		ssize_t resp_len;
		struct timespec now, dt;

		if (clock_gettime(CLOCK_MONOTONIC, &now) < 0) {
			err("clock_gettime : %m\n");
			goto err;
		}

		timespec_sub(&now, &last, &dt);
		if (dt.tv_sec * 1000 + dt.tv_nsec / (1000 * 1000) >= delay_ms) { /* Convert in ms ! */

			arp_frame_set_target_addr(&req, current_dest);

			if (is_vrb()) {
				char *res;
				if (arp_frame_dump(&req, &res) > 0) {
					vrb("ARP_REQ :\n%s\n", res);
					free(res);
				}
			} else if (is_dbg())
				dbg("ARP_REQ %s\n", inet_ntoa(arp_frame_get_target_addr(&req)));

			if (sendto(sock, &req, sizeof req, 0, (struct sockaddr *)&saddr, sizeof saddr) <= 0) {
				err("sendto : %m\n");
				goto err;
			}

			current_dest.s_addr += htonl(1);
			if (current_dest.s_addr > daddr_to.s_addr)
				current_dest = daddr_from;

			last = now;

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

			if (resp_len >= sizeof resp && arp_frame_check(&resp)) {

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
