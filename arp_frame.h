
#ifndef __frame_h_666__
# define __frame_h_666__

#include <netinet/if_ether.h>
#include <netinet/in.h>

#include "arp_dev.h"

struct arp_frame {
	struct ether_header eth;
	struct ether_arp arp;
} __attribute__ ((__packed__));

void arp_frame_req(const struct arp_dev *dev, struct arp_frame *req);
int arp_frame_check(const struct arp_frame *frame);
size_t arp_frame_dump(const struct arp_frame *frame, char **res);

struct in_addr arp_frame_get_target_addr(const struct arp_frame *frame);
void arp_frame_set_target_addr(struct arp_frame *frame, const struct in_addr addr);

struct in_addr arp_frame_get_source_addr(const struct arp_frame *frame);
const uint8_t *arp_frame_get_source_hwaddr(const struct arp_frame *frame);

#endif
