
#ifndef __arp_dev_h_666__
# define __arp_dev_h_666__

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>

struct arp_dev {
	int index;
	short flags;
	short private_flags;
	struct in_addr addr;
	struct in_addr broadcast;
	struct in_addr netmask;
	uint8_t hwaddr[ETH_ALEN];
	char *name;
};

int arp_dev_init(int sock, struct arp_dev *res, const char *name);
void arp_dev_deinit(struct arp_dev *info);
ssize_t arp_dev_discover(struct arp_dev **res);
void arp_dev_dump(const struct arp_dev *info);

#endif
