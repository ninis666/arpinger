
#include <string.h>
#include <poll.h>

#include "arp_net.h"
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

int arp_send(int sock, struct sockaddr_ll *saddr, struct arp_frame *req, const struct in_addr from, const struct in_addr to, struct in_addr *current)
{
	int ret = -1;

	arp_frame_set_target_addr(req, *current);
	dbg("ARP_REQ %s\n", inet_ntoa(arp_frame_get_target_addr(req)));

	if (sendto(sock, req, sizeof req[0], 0, (struct sockaddr *)saddr, sizeof saddr[0]) <= 0) {
		err("sendto : %m\n");
		goto err;
	}

	current->s_addr += htonl(1);
	if (current->s_addr > to.s_addr)
		*current = from;

	ret = 0;
err:
	return ret;
}

ssize_t arp_recv(int sock, const long poll_ms, struct arp_table *table)
{
	ssize_t done = 0;
	struct pollfd fds;
	struct timespec start;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &start);
	chk(res >= 0);

	fds.fd = sock;
	fds.events = POLLIN | POLLERR;
	fds.revents = 0;

	res = poll(&fds, 1, poll_ms);
	if (res < 0) {
		err("poll : %m\n");
		goto err;
	}

	if (res == 0)
		goto end;

	for (;;) {
		struct timespec now;
		struct timespec dt;
		struct arp_frame resp;
		ssize_t resp_len;

		resp_len = recvfrom(sock, &resp, sizeof resp, MSG_DONTWAIT, NULL, 0);
		if (resp_len < 0) {
			if (errno != EAGAIN && errno != EWOULDBLOCK) {
				err("recvfrom : %m\n");
				goto err;
			}

			resp_len = 0;
		}

		if (resp_len == 0)
			break;

		res = clock_gettime(CLOCK_MONOTONIC, &now);
		chk(res >= 0);

		if ((size_t )resp_len >= sizeof resp && arp_frame_check(&resp)) {

			if (is_vrb()) {
				char *res;
				if (arp_frame_dump(&resp, &res) > 0) {
					vrb("ARP_RSP :\n%s\n", res);
					free(res);
				}
			}

			if (arp_table_add(table, arp_frame_get_source_addr(&resp), arp_frame_get_source_hwaddr(&resp), &now) == NULL)
				goto err;
			done ++;
		}

		timespec_sub(&now, &start, &dt);
		if (timespec_to_ms(&dt) >= poll_ms)
			break;
	}

end:
	return done;

err:
	return -1;
}
