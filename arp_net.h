
#ifndef __arp_net_h_666__
# define __arp_net_h_666__

# include <linux/if_packet.h>

# include "arp_dev.h"
# include "arp_frame.h"
# include "arp_table.h"

struct arp_net {
	int sock;
	struct sockaddr_ll saddr;
	struct arp_frame req;

	struct in_addr current;
	struct in_addr from;
	struct in_addr to;

	struct timespec last_req;
	struct timespec last_check;
};

int arp_net_init(struct arp_net *net, const struct arp_dev *dev, const struct in_addr from, const struct in_addr to);
void arp_net_free(struct arp_net *net);
ssize_t arp_net_loop(struct arp_net *net, const long req_delay_ms, const long poll_delay_ms, struct arp_table *table, struct arp_event_list *event);

#endif
