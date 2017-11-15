
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "arp_table.h"
#include "log.h"
#include "time_utils.h"

int arp_table_init(struct arp_table *table, const size_t addr_max_hash, const size_t hwaddr_max_hash)
{
	memset(table, 0, sizeof table[0]);

	table->addr_list = calloc(addr_max_hash, sizeof table->addr_list[0]);
	if (table->addr_list == NULL) {
		err("calloc : %m\n");
		goto err;
	}
	table->addr_max_hash = addr_max_hash;

	table->hwaddr_list = calloc(hwaddr_max_hash, sizeof table->hwaddr_list[0]);
	if (table->hwaddr_list == NULL) {
		err("calloc : %m\n");
		goto free_err;
	}
	table->hwaddr_max_hash = hwaddr_max_hash;

	return 0;

free_err:
	free(table->addr_list);
err:
	memset(table, 0, sizeof table[0]);
	return -1;
}

#define node_link(l, e, what) do {			\
		(e)->what.next = NULL;			\
		(e)->what.prev = (l)->last;		\
		if ((l)->last != NULL)			\
			(l)->last->what.next = (e);	\
		else					\
			(l)->first = (e);		\
		(l)->last = (e);			\
	} while (0)

#define node_unlink(l, e, what) do {					\
		if ((e)->what.next != NULL)				\
			(e)->what.next->what.prev = (e)->what.prev;	\
		else							\
			(l)->last = (e)->what.prev;			\
									\
		if ((e)->what.prev != NULL)				\
			(e)->what.prev->what.next = (e)->what.next;	\
		else							\
			(l)->first = (e)->what.next;			\
									\
		(e)->what.next = NULL;					\
		(e)->what.prev = NULL;					\
	} while (0)

#define node_is_linked(e, what) (e->what.next != NULL || e->what.prev != NULL)

static size_t hwaddr_hash(const struct arp_table *table, const uint8_t *hwaddr)
{
	return (hwaddr[5] & 0xF) % table->hwaddr_max_hash;
}

static size_t addr_hash(const struct arp_table *table, const struct in_addr addr)
{
	return (addr.s_addr & 0xF) % table->addr_max_hash;
}

static struct arp_list *arp_list_addr(const struct arp_table *table, const struct in_addr addr)
{
	return &table->addr_list[addr_hash(table, addr)];
}

static struct arp_list *arp_list_hwaddr(const struct arp_table *table, const uint8_t *hwaddr)
{
	return &table->hwaddr_list[hwaddr_hash(table, hwaddr)];
}

static void node_link_addr(struct arp_list *list, struct arp_entry *entry)
{
	node_link(list, entry, addr_node);
}

static void node_link_hwaddr(struct arp_list *list, struct arp_entry *entry)
{
	node_link(list, entry, hwaddr_node);
}

static void node_unlink_addr(struct arp_list *list, struct arp_entry *entry)
{
	node_unlink(list, entry, addr_node);
}

static void node_unlink_hwaddr(struct arp_list *list, struct arp_entry *entry)
{
	node_unlink(list, entry, hwaddr_node);
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

	node_link(&table->pool_list, entry, pool_node);

err:
	return entry;
}

static void entry_free(struct arp_table *table, struct arp_entry *entry)
{
	if (node_is_linked(entry, pool_node))
		node_unlink(&table->pool_list, entry, pool_node);

	if (node_is_linked(entry, addr_node))
		node_unlink_addr(arp_list_addr(table, entry->addr), entry);

	if (node_is_linked(entry, hwaddr_node))
		node_unlink_hwaddr(arp_list_hwaddr(table, entry->hwaddr), entry);

	if (node_is_linked(entry, seen_node))
		node_unlink(&table->seen_list, entry, seen_node);

	free(entry);
}

void arp_table_dump(const struct arp_table *table)
{
	for (struct arp_entry *node = table->pool_list.first ; node != NULL ; node = node->pool_node.next) {
		fprintf(stderr, "%s %02x:%02x:%02x:%02x:%02x:%02x, first = { %lds, %ldns }, last = { %lds, %ldns }\n", inet_ntoa(node->addr),
			node->hwaddr[0], node->hwaddr[1], node->hwaddr[2], node->hwaddr[3], node->hwaddr[4], node->hwaddr[5],
			node->first_seen.tv_sec, node->first_seen.tv_nsec,
			node->last_seen.tv_sec, node->last_seen.tv_nsec);
	}
}

void arp_table_dump_seen(const struct arp_table *table)
{
	for (struct arp_entry *node = table->seen_list.first ; node != NULL ; node = node->seen_node.next) {
		fprintf(stderr, "%s %02x:%02x:%02x:%02x:%02x:%02x, first = { %lds, %ldns }, last = { %lds, %ldns }\n", inet_ntoa(node->addr),
			node->hwaddr[0], node->hwaddr[1], node->hwaddr[2], node->hwaddr[3], node->hwaddr[4], node->hwaddr[5],
			node->first_seen.tv_sec, node->first_seen.tv_nsec,
			node->last_seen.tv_sec, node->last_seen.tv_nsec);
	}
}

static struct arp_entry *node_lookup_addr(const struct arp_list *list, const struct in_addr addr)
{
	struct arp_entry *node;

	for (node = list->first ; node != NULL ; node = node->addr_node.next) {
		if (node->addr.s_addr == addr.s_addr)
			break;
	}

	return node;
}

static struct arp_entry *node_lookup_hwaddr(struct arp_list *list, const uint8_t *hwaddr)
{
	struct arp_entry *node;

	for (node = list->first ; node != NULL ; node = node->hwaddr_node.next) {
		if (memcmp(node->hwaddr, hwaddr, sizeof node->hwaddr) == 0)
			break;
	}

	return node;
}

struct arp_entry *arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
{
	struct arp_list *addr_list;
	struct arp_list *hwaddr_list;
	struct arp_entry *addr_node;
	struct arp_entry *hwaddr_node;
	struct arp_entry *entry = NULL;

	addr_list = arp_list_addr(table, addr);
	hwaddr_list = arp_list_hwaddr(table, hwaddr);
	addr_node = node_lookup_addr(addr_list, addr);
	hwaddr_node = node_lookup_hwaddr(hwaddr_list, hwaddr);

	if (addr_node == NULL && hwaddr_node == NULL) {

		entry = entry_alloc(table, addr, hwaddr, now);
		if (entry == NULL)
			goto err;

		node_link_addr(addr_list, entry);
		node_link_hwaddr(hwaddr_list, entry);

		dbg("IP %s added to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

	} else if (addr_node != NULL && hwaddr_node == NULL) {
		struct arp_list *old_hwaddr_list;
		struct arp_entry *old_hwaddr_node;

		entry = addr_node;

		wrn("HW %02x:%02x:%02x:%02x:%02x:%02x stolled IP %s (previously holded by HW %02x:%02x:%02x:%02x:%02x:%02x)\n",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			inet_ntoa(addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

		/*
		 * Add a new hwaddr with the addr entry and remove the old one
		 */

		old_hwaddr_list = &table->hwaddr_list[hwaddr_hash(table, entry->hwaddr)];
		old_hwaddr_node = node_lookup_hwaddr(old_hwaddr_list, entry->hwaddr);
		chk(old_hwaddr_node == entry);

		node_unlink_hwaddr(old_hwaddr_list, old_hwaddr_node);
		node_link_hwaddr(hwaddr_list, entry);
		memcpy(entry->hwaddr, hwaddr, sizeof entry->hwaddr);

		dbg("IP %s updated to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);


	} else if (addr_node == NULL && hwaddr_node != NULL) {
		struct arp_list *old_addr_list;
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
		old_addr_list = &table->addr_list[addr_hash(table, entry->addr)];
		old_addr_node = node_lookup_addr(old_addr_list, entry->addr);
		chk(old_addr_node == entry);

		node_unlink_addr(old_addr_list, old_addr_node);
		node_link_addr(addr_list, entry);
		entry->addr = addr;

		dbg("HW %02x:%02x:%02x:%02x:%02x:%02x updated to IP %s\n",
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5],
			inet_ntoa(entry->addr));

	} else {

		chk(addr_node == hwaddr_node);
		entry = addr_node;

		vrb("IP %s still binded to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

	}

	entry->last_seen = *now;

	if (node_is_linked(entry, seen_node))
		node_unlink(&table->seen_list, entry, seen_node);
	node_link(&table->seen_list, entry, seen_node);

	return entry;

err:
	return NULL;
}

size_t arp_table_check_expired(struct arp_table *table, const struct timespec *now, const long expired_ms)
{
	struct arp_entry *node;
	size_t count = 0;

	node = table->seen_list.first;
	while (node != NULL) {
		struct arp_entry *next = node->seen_node.next;
		struct timespec dt;

		timespec_sub(now, &node->last_seen, &dt);
		if (timespec_to_ms(&dt) < expired_ms)
			break;

		wrn("IP %s binded to HW %02x:%02x:%02x:%02x:%02x:%02x expired since %ldms\n",
			inet_ntoa(node->addr),
			node->hwaddr[0], node->hwaddr[1], node->hwaddr[2], node->hwaddr[3], node->hwaddr[4], node->hwaddr[5],
			timespec_to_ms(&dt));

		entry_free(table, node);
		count ++;

		node = next;
	}

	return count;
}
