
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "arp_table.h"
#include "log.h"

int arp_table_init(struct arp_table *table, const size_t addr_max_hash, const size_t hwaddr_max_hash)
{
	memset(table, 0, sizeof table[0]);

	table->addr_hash = calloc(addr_max_hash, sizeof table->addr_hash[0]);
	if (table->addr_hash == NULL) {
		err("calloc : %m\n");
		goto err;
	}
	table->addr_max_hash = addr_max_hash;

	table->hwaddr_hash = calloc(hwaddr_max_hash, sizeof table->hwaddr_hash[0]);
	if (table->hwaddr_hash == NULL) {
		err("calloc : %m\n");
		goto free_err;
	}
	table->hwaddr_max_hash = hwaddr_max_hash;

	return 0;

free_err:
	free(table->addr_hash);
err:
	memset(table, 0, sizeof table[0]);
	return -1;
}

static struct arp_entry *entry_alloc(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
{
	struct arp_entry *entry = NULL;

	entry = calloc(1, sizeof entry[0]);
	if (entry == NULL) {
		err("calloc : %m\n");
		goto err;
	}

	entry->addr = addr;
	memcpy(&entry->hwaddr, hwaddr, sizeof entry->hwaddr);
	entry->first_seen = *now;
	entry->last_seen = *now;

	entry->pool.prev = NULL;
	entry->pool.next = table->pool_first;
	if (table->pool_first != NULL)
		table->pool_first->pool.prev = entry;
	table->pool_first = entry;
err:
	return entry;
}

static void __attribute__((unused)) entry_free(struct arp_table *table, struct arp_entry *entry)
{

	if (entry->pool.next != NULL)
		entry->pool.next->pool.prev = entry->pool.prev;

	if (entry->pool.prev != NULL)
		entry->pool.prev->pool.next = entry->pool.next;
	else
		table->pool_first = entry->pool.next;

	free(entry);
}

#define DO_LINK(f, e, what) do {		\
		struct arp_entry *first = *(f);	\
						\
		(e)->what.prev = NULL;		\
		(e)->what.next = first;		\
		if (first != NULL)		\
			first->what.prev = (e);	\
		first = (e);			\
		*(f) = first;			\
	} while (0)

static void node_link_addr(struct arp_entry **first_ptr, struct arp_entry *entry)
{
	DO_LINK(first_ptr, entry, addr_hash);
}

static void node_link_hwaddr(struct arp_entry **first_ptr, struct arp_entry *entry)
{
	DO_LINK(first_ptr, entry, hwaddr_hash);
}

#undef DO_LINK

#define DO_UNLINK(f, e, what) do {					\
		if ((e)->what.next != NULL)				\
			(e)->what.next->what.prev = (e)->what.prev;	\
									\
		if ((e)->what.prev != NULL)				\
			(e)->what.prev->what.next = (e)->what.next;	\
		else							\
			*(f) = (e)->what.next;				\
		(e)->what.next = NULL;					\
		(e)->what.prev = NULL;					\
	} while (0)

static void node_unlink_addr(struct arp_entry **first_ptr, struct arp_entry *entry)
{
	DO_UNLINK(first_ptr, entry, addr_hash);
}

static void node_unlink_hwaddr(struct arp_entry **first_ptr, struct arp_entry *entry)
{
	DO_UNLINK(first_ptr, entry, hwaddr_hash);
}

void arp_table_dump(const struct arp_table *table)
{
	for (struct arp_entry *node = table->pool_first ; node != NULL ; node = node->pool.next) {
		fprintf(stderr, "%s %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(node->addr),
			node->hwaddr[0], node->hwaddr[1], node->hwaddr[2], node->hwaddr[3], node->hwaddr[4], node->hwaddr[5]);
	}
}

static struct arp_entry *node_lookup_addr(struct arp_entry *first, const struct in_addr addr)
{
	struct arp_entry *node;

	for (node = first ; node != NULL ; node = node->addr_hash.next) {
		if (node->addr.s_addr == addr.s_addr)
			break;
	}

	return node;
}

static struct arp_entry *node_lookup_hwaddr(struct arp_entry *first, const uint8_t *hwaddr)
{
	struct arp_entry *node;

	for (node = first ; node != NULL ; node = node->hwaddr_hash.next) {
		if (memcmp(node->hwaddr, hwaddr, sizeof node->hwaddr) == 0)
			break;
	}

	return node;
}

# define hwaddr_hash(table, hwaddr) ((hwaddr[5] & 0xF) % table->hwaddr_max_hash)
# define addr_hash(table, addr)     ((addr.s_addr & 0xF) % table->addr_max_hash)

struct arp_entry *arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
{
	const size_t addr_hash = addr_hash(table, addr);
	const size_t hwaddr_hash = hwaddr_hash(table, hwaddr);
	struct arp_entry *addr_node;
	struct arp_entry *hwaddr_node;
	struct arp_entry *entry = NULL;

	addr_node = node_lookup_addr(table->addr_hash[addr_hash], addr);
	hwaddr_node = node_lookup_hwaddr(table->hwaddr_hash[hwaddr_hash], hwaddr);

	if (addr_node == NULL && hwaddr_node == NULL) {

		entry = entry_alloc(table, addr, hwaddr, now);
		if (entry == NULL)
			goto err;

		node_link_addr(&table->addr_hash[addr_hash], entry);
		node_link_hwaddr(&table->hwaddr_hash[hwaddr_hash], entry);

		dbg("IP %s added to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

	} else if (addr_node != NULL && hwaddr_node == NULL) {
		size_t old_hwaddr_hash;
		struct arp_entry *old_hwaddr_node;

		entry = addr_node;

		wrn("HW %02x:%02x:%02x:%02x:%02x:%02x stolled IP %s (previously holded by HW %02x:%02x:%02x:%02x:%02x:%02x)\n",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			inet_ntoa(addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

		/*
		 * Add a new hwaddr with the addr entry and remove the old one
		 */

		old_hwaddr_hash = hwaddr_hash(table, entry->hwaddr);
		old_hwaddr_node = node_lookup_hwaddr(table->hwaddr_hash[old_hwaddr_hash], entry->hwaddr);
		chk(old_hwaddr_node == entry);

		node_unlink_hwaddr(&table->hwaddr_hash[old_hwaddr_hash], old_hwaddr_node);
		node_link_hwaddr(&table->hwaddr_hash[hwaddr_hash], entry);
		memcpy(entry->hwaddr, hwaddr, sizeof entry->hwaddr);

		dbg("IP %s updated to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);


	} else if (addr_node == NULL && hwaddr_node != NULL) {
		size_t old_addr_hash;
		struct arp_entry *old_addr_node;
		char tmp[sizeof "xxx.xxx.xxx.xxx"];

		entry = hwaddr_node;

		snprintf(tmp, sizeof tmp, "%s", inet_ntoa(entry->addr));
		wrn("IP %s stolled HW %02x:%02x:%02x:%02x:%02x:%02x (previously holded by IP %s)\n",
			inet_ntoa(addr),
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			tmp);

		/*
		 * Add a new addr with the hwaddr entry and remove the old one
		 */

		old_addr_hash = addr_hash(table, entry->addr);
		old_addr_node = node_lookup_addr(table->addr_hash[old_addr_hash], entry->addr);
		chk(old_addr_node == entry);

		node_unlink_addr(&table->addr_hash[old_addr_hash], old_addr_node);
		node_link_addr(&table->addr_hash[addr_hash], entry);
		entry->addr = addr;

		dbg("HW %02x:%02x:%02x:%02x:%02x:%02x updated to IP %s\n",
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5],
			inet_ntoa(entry->addr));

	} else {

		chk(addr_node == hwaddr_node);
		entry = addr_node;
	}

	entry->last_seen = *now;
	return entry;

err:
	return NULL;
}
