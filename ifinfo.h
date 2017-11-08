
#ifndef __if_info_h_666__
# define __if_info_h_666__

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <net/if.h>

struct if_info {
	int index;
	short flags;
	short private_flags;
	struct in_addr addr;
	struct in_addr broadcast;
	struct in_addr netmask;
	uint8_t hwaddr[ETH_ALEN];
	char *name;
};

int if_info_init(int sock, struct if_info *res, const char *name);
void if_info_deinit(struct if_info *info);
ssize_t if_info_discover(struct if_info **res);
void if_info_dump(const struct if_info *info);

#endif
