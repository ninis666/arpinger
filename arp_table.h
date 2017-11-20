
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
	struct {
		struct arp_entry *next;
		struct arp_entry *prev;
	} pool_node, addr_node, hwaddr_node, seen_node;
};

struct arp_list {
	struct arp_entry *first;
	struct arp_entry *last;
};

struct arp_table {
	struct timespec initial_clock;
	struct timeval initial_time;

	struct arp_list pool_list;

	struct arp_list *addr_list;
	size_t addr_max_hash;

	struct arp_list *hwaddr_list;
	size_t hwaddr_max_hash;
};

int arp_table_init(struct arp_table *table, const size_t addr_max_hash, const size_t hwaddr_max_hash);
void arp_table_free(struct arp_table *table);

typedef enum {
	arp_table_add_error = -1,
	arp_table_add_nochange = 0,
	arp_table_add_new,
	arp_table_add_addr_changed,
	arp_table_add_hwaddr_changed,
} arp_table_add_t;

arp_table_add_t arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now, struct arp_entry **res);
size_t arp_table_check_expired(struct arp_table *table, const long expired_ms);

size_t arp_table_dump(const struct arp_table *table, char **res, const char *pfx, const char *sfx);

#endif
