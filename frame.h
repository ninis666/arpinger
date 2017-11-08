
#ifndef __frame_h_666__
# define __frame_h_666__

#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "ifinfo.h"

struct arp_frame {
	struct ether_header eth;
	struct ether_arp arp;
} __attribute__ ((__packed__));

void arp_frame_req(const struct if_info *dev, const struct in_addr dest, struct arp_frame *req);
int arp_frame_check(const struct arp_frame *frame);
void arp_frame_dump(const struct arp_frame *frame);

#endif
