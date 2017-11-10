
#ifndef __arptable_h_666__
# define __arptable_h_666__

#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <time.h>

struct arp_entry {
	struct in_addr addr;
	uint8_t hwaddr[ETH_ALEN];
	struct timespec first_seen;
	struct timespec last_seen;
	struct arp_entry *next;
	struct arp_entry *prev;
};

struct arp_hash_node {
	const struct arp_entry *entry;
	struct arp_hash_node *next;
	struct arp_hash_node *prev;
};

struct arp_table {
	struct arp_entry *pool;

	struct arp_hash_node **addr_hash;
	size_t addr_max_hash;

	struct arp_hash_node **hwaddr_hash;
	size_t hwaddr_max_hash;
};

int arp_table_init(struct arp_table *table, const size_t addr_max_hash, const size_t hwaddr_max_hash);
struct arp_entry *arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now);

#endif
