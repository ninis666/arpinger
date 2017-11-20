
#include <string.h>

#include "log.h"
#include "arpinger.h"

int arpinger_init(struct arpinger *arp, const char *dev, const char *from, const char *to, const long req_delay_ms, const long max_lost)
{
	struct in_addr addr_from;
	struct in_addr addr_to;

	memset(arp, 0, sizeof arp[0]);

	if (arp_dev_init(-1, &arp->dev, (dev == NULL || dev[0] == 0) ? "eth0" : dev) < 0)
		goto err;

	if (from == NULL || from[0] == 0)
		memset(&addr_from, 0, sizeof addr_from);
	else {
		if (inet_aton(from, &addr_from) == 0) {
			err("Invalid from : %s\n", from);
			goto free_dev_err;
		}
	}

	if (to == NULL || to[0] == 0)
		memset(&addr_to, 0, sizeof addr_to);
	else {
		if (inet_aton(to, &addr_to) == 0) {
			err("Invalid to : %s\n", to);
			goto free_dev_err;
		}
	}

	if (arp_net_init(&arp->net, &arp->dev, addr_from, addr_to) < 0)
		goto free_dev_err;

	if (arp_table_init(&arp->table, 1, 1) < 0)
		goto free_net_err;

	arp->expire_ms = max_lost * ((req_delay_ms == 0) ? 1 : req_delay_ms) * (htonl(arp->net.to.s_addr) - htonl(arp->net.from.s_addr)); /* Enough time to discover all the network */
	arp->poll_ms = (req_delay_ms <= 1) ? 1 : req_delay_ms / 2;
	arp->req_delay_ms = req_delay_ms;
	return 0;

free_net_err:
	arp_net_free(&arp->net);
free_dev_err:
	arp_dev_deinit(&arp->dev);
err:
	return -1;
}

ssize_t arpinger_loop(struct arpinger *arp)
{
	int changed;

	changed = arp_net_loop(&arp->net, arp->req_delay_ms, arp->poll_ms, &arp->table);
	if (changed < 0)
		goto err;

	if (arp_table_check_expired(&arp->table, arp->expire_ms) != 0)
		changed ++;

err:
	return changed;
}

void arpinger_free(struct arpinger *arp)
{
	arp_net_free(&arp->net);
	arp_dev_deinit(&arp->dev);
	arp_table_free(&arp->table);
}
