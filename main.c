
#include <string.h>
#include <sys/socket.h>
#include <net/if_arp.h>
#include <linux/if_packet.h>
#include <poll.h>
#include <time.h>

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
	const char *dev;
	const char *dest;
	int i;
	struct arp_dev info;
	int sock;
	struct sockaddr_ll saddr;
	struct in_addr daddr;
	struct arp_frame req;
	struct pollfd fds;
	struct timespec last;
	struct arp_table table;

	dest = NULL;
	dev = NULL;
	for (i = 1 ; i < ac ; i++) {
		if (strcmp(av[i], "-dev") == 0) {
			if (i + 1 >= ac)
				goto no_arg;
			dev = av[i + 1];
			i++;
		} else
			dest = av[i];
		continue;

	no_arg:
		fprintf(stderr, "No argument for %s option\n", av[i]);
	usage:
		fprintf(stderr, "Usage : %s [-dev [device_name]] [dest]\n", av[0]);
		return 1;
	}

	if (dev == NULL)
		goto usage;

	if (dest == NULL)
		goto usage;

	if (inet_aton(dest, &daddr) == 0) {
		err("Invalid dest : %s\n", dest);
		goto usage;
	}

	if (arp_dev_init(-1, &info, dev) < 0)
		goto err;

	arp_dev_dump(&info);

	sock = arp_socket(&info, &saddr);
	if (sock < 0)
		goto err;

	arp_frame_req(&info, daddr, &req);

	fds.fd = sock;
	fds.events = POLLIN | POLLERR;
	fds.revents = 0;
	memset(&last, 0, sizeof last);

	arp_table_init(&table, 2, 2);

	long delay_ms = 1000;
	struct in_addr current_dest = daddr;

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
			printf("REQ %s\n", inet_ntoa(arp_frame_get_target_addr(&req)));
			if (sendto(sock, &req, sizeof req, 0, (struct sockaddr *)&saddr, sizeof saddr) <= 0) {
				err("sendto : %m\n");
				goto err;
			}

			current_dest = arp_frame_get_target_addr(&req);
			current_dest.s_addr = htonl(htonl(current_dest.s_addr) + 1);
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
				//arp_frame_dump(&resp);
				arp_table_add(&table, arp_frame_get_source_addr(&resp), arp_frame_get_source_hwaddr(&resp), &now);
			}
		}
	}

	arp_dev_deinit(&info);

	ret = 0;
err:
	return ret;
}
