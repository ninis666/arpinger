
#include <string.h>
#include <poll.h>
#include <unistd.h>

#include "arp_net.h"
#include "log.h"
#include "time_utils.h"

int arp_net_init(struct arp_net *net, const struct arp_dev *dev, const struct in_addr from, const struct in_addr to)
{
	memset(net, 0, sizeof net[0]);

	net->sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (net->sock < 0) {
		err("socket SOCK_RAW : %m\n");
		goto err;
	}

	net->saddr.sll_ifindex = dev->index;
	net->saddr.sll_family = AF_PACKET;
	memcpy(net->saddr.sll_addr, dev->hwaddr, sizeof dev->hwaddr);
	net->saddr.sll_halen = sizeof dev->hwaddr;

	if (from.s_addr == 0)
		net->from.s_addr = (dev->addr.s_addr & dev->netmask.s_addr) + htonl(1);
	else
		net->from = from;

	if (to.s_addr == 0)
		net->to.s_addr = dev->broadcast.s_addr - htonl(1);
	else
		net->to = to;

	if (htonl(net->to.s_addr) < htonl(net->from.s_addr)) {
		const struct in_addr tmp = net->to;

		net->to = net->from;
		net->from = tmp;
	}

	arp_frame_req(dev, &net->req);

	return 0;

err:
	return -1;
}

static int arp_send(struct arp_net *net)
{
	if (unlikely(net->current.s_addr == 0 || net->current.s_addr > net->to.s_addr))
		net->current = net->from;

	arp_frame_set_target_addr(&net->req, net->current);
	dbg("ARP_REQ %s\n", inet_ntoa(arp_frame_get_target_addr(&net->req)));

	if (sendto(net->sock, &net->req, sizeof net->req, 0, (struct sockaddr *)&net->saddr, sizeof net->saddr) <= 0) {
		err("sendto : %m\n");
		goto err;
	}

	net->current.s_addr += htonl(1);
	if (net->current.s_addr > net->to.s_addr)
		net->current = net->from;

	return 0;
err:
	return -1;
}

static ssize_t arp_recv(struct arp_net *net, const long poll_delay_ms, struct arp_table *table)
{
	ssize_t done = 0;
	struct pollfd fds;
	struct timespec start;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &start);
	chk(res >= 0);

	fds.fd = net->sock;
	fds.events = POLLIN | POLLERR;
	fds.revents = 0;

	res = poll(&fds, 1, poll_delay_ms);
	if (res < 0) {
		if (errno != EINTR) {
			err("poll : %m\n");
			goto err;
		}
		res = 0;
	}

	if (res == 0)
		goto end;

	for (;;) {
		struct timespec now;
		struct timespec dt;
		struct arp_frame resp;
		ssize_t resp_len;

		resp_len = recvfrom(net->sock, &resp, sizeof resp, MSG_DONTWAIT, NULL, 0);
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
		if (timespec_to_ms(&dt) >= poll_delay_ms)
			break;
	}

end:
	return done;

err:
	return -1;
}

int arp_net_loop(struct arp_net *net, const long req_delay_ms, const long poll_delay_ms, struct arp_table *table)
{
	struct timespec now, dt;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &now);
	chk(res >= 0);
	timespec_sub(&now, &net->last_req, &dt);
	if (timespec_to_ms(&dt) >= req_delay_ms) {
		if (arp_send(net) < 0)
			goto err;
		net->last_req = now;
	}

	if (arp_recv(net, poll_delay_ms, table) < 0)
		goto err;

	return 0;
err:
	return -1;
}


void arp_net_free(struct arp_net *net)
{
	if (net->sock >= 0) {
		close(net->sock);
		net->sock = -1;
	}
}

