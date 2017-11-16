
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

#define node_link(l, e, what) do {				\
		struct arp_list *__l_link = (l);		\
		struct arp_entry *__e_link = (e);		\
								\
		__e_link->what.next = NULL;			\
		__e_link->what.prev = __l_link->last;		\
		if (__l_link->last != NULL)			\
			__l_link->last->what.next = __e_link;	\
		else						\
			__l_link->first = __e_link;		\
		__l_link->last = __e_link;			\
	} while (0)

#define node_unlink(l, e, what) do {					\
		struct arp_list *__l_unlink = (l);			\
		struct arp_entry *__e_unlink = (e);			\
									\
		if (__e_unlink->what.next != NULL)			\
			__e_unlink->what.next->what.prev = __e_unlink->what.prev; \
		else							\
			__l_unlink->last = __e_unlink->what.prev;	\
									\
		if (__e_unlink->what.prev != NULL)			\
			__e_unlink->what.prev->what.next = __e_unlink->what.next; \
		else							\
			__l_unlink->first = __e_unlink->what.next;	\
									\
		__e_unlink->what.next = NULL;				\
		__e_unlink->what.prev = NULL;				\
	} while (0)

#define node_is_linked(l, e, what) ((l)->first == (e) || (l)->last == (e) || (e)->what.next != NULL || (e)->what.prev != NULL)

#define node_try_unlink(l, e, what) do {				\
		struct arp_list *__l_try_unlink = (l);			\
		struct arp_entry *__e_try_unlink = (e);			\
									\
		if (node_is_linked(__l_try_unlink, __e_try_unlink, what)) \
			node_unlink(__l_try_unlink, __e_try_unlink, what); \
	} while (0)

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

static struct arp_entry *entry_alloc(const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
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
err:
	return entry;
}

static void entry_free(struct arp_table *table, struct arp_entry *entry)
{
	node_try_unlink(&table->pool_list, entry, pool_node);
	node_try_unlink(arp_list_addr(table, entry->addr), entry, addr_node);
	node_try_unlink(arp_list_hwaddr(table, entry->hwaddr), entry, hwaddr_node);
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

		entry = entry_alloc(addr, hwaddr, now);
		if (entry == NULL)
			goto err;

		node_link(&table->pool_list, entry, pool_node);
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

		dbg("IP %s still binded to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

	}

	entry->last_seen = *now;

	node_unlink(&table->pool_list, entry, pool_node);
	node_link(&table->pool_list, entry, pool_node);

	return entry;

err:
	return NULL;
}

static size_t do_check(struct arp_table *table, const struct timespec *now, const long expired_delay_ms)
{
	struct arp_entry *node;
	size_t count = 0;

	node = table->pool_list.first;
	while (node != NULL) {
		struct arp_entry *next = node->pool_node.next;
		struct timespec dt;

		timespec_sub(now, &node->last_seen, &dt);
		if (timespec_to_ms(&dt) < expired_delay_ms)
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

size_t arp_table_check_expired(struct arp_table *table, const long expired_delay_ms)
{
	struct timespec now, dt;
	size_t count;
	int res;

	res = clock_gettime(CLOCK_MONOTONIC, &now);
	chk(res >= 0);
	timespec_sub(&now, &table->last_check, &dt);
	if (timespec_to_ms(&dt) >= expired_delay_ms) {
		count = do_check(table, &now, expired_delay_ms);
		arp_table_dump(table);
		table->last_check = now;
	}

	return count;
}
