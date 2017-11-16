
#ifndef __arp_net_h__
# define __arp_net_h__

# include <linux/if_packet.h>

# include "arp_dev.h"
# include "arp_frame.h"
# include "arp_table.h"

int arp_socket(const struct arp_dev *dev, struct sockaddr_ll *daddr);
int arp_send(int sock, struct sockaddr_ll *saddr, struct arp_frame *req, const struct in_addr from, const struct in_addr to, struct in_addr *current);
ssize_t arp_recv(int sock, const long poll_ms, struct arp_table *table);

#endif
