
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "arp_table.h"
#include "err.h"

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

	entry->prev = NULL;
	entry->next = table->pool;
	if (table->pool != NULL)
		table->pool->prev = entry;
	table->pool = entry;
err:
	return entry;
}

static void entry_free(struct arp_table *table, struct arp_entry *entry)
{

	if (entry->next != NULL)
		entry->next->prev = entry->prev;

	if (entry->prev != NULL)
		entry->prev->next = entry->next;
	else
		table->pool = entry->next;

	free(entry);
}

static struct arp_hash_node *node_alloc(struct arp_hash_node **first_ptr, const struct arp_entry *entry)
{
	struct arp_hash_node *node;
	struct arp_hash_node *first = *first_ptr;

	node = calloc(1, sizeof node[0]);
	if (node == NULL) {
		err("calloc : %m\n");
		goto err;
	}

	node->prev = NULL;
	node->next = first;
	if (first != NULL)
		first->prev = node;
	first = node;
	node->entry = entry;
	*first_ptr = first;

err:
	return node;
}

static void node_free(struct arp_hash_node **first_ptr, struct arp_hash_node *node)
{
	if (node->next != NULL)
		node->next->prev = node->prev;

	if (node->prev != NULL)
		node->prev->next = node->next;
	else
		*first_ptr = node->next;

	free(node);
}

void arp_table_dump(const struct arp_table *table)
{
	for (struct arp_entry *node = table->pool ; node != NULL ; node = node->next) {
		fprintf(stderr, "%s %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(node->addr),
			node->hwaddr[0], node->hwaddr[1], node->hwaddr[2], node->hwaddr[3], node->hwaddr[4], node->hwaddr[5]);
	}
}

struct arp_entry *arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
{
	const size_t addr_hash = (addr.s_addr & 0xF) % table->addr_max_hash;
	const size_t hwaddr_hash = (hwaddr[5] & 0xF) % table->hwaddr_max_hash;
	struct arp_hash_node *addr_node;
	struct arp_hash_node *hwaddr_node;
	struct arp_entry *entry = NULL;

	for (addr_node = table->addr_hash[addr_hash] ; addr_node != NULL ; addr_node = addr_node->next) {
		if (addr_node->entry->addr.s_addr == addr.s_addr)
			break;
	}

	for (hwaddr_node = table->hwaddr_hash[hwaddr_hash] ; hwaddr_node != NULL ; hwaddr_node = hwaddr_node->next) {
		if (memcmp(hwaddr_node->entry->hwaddr, hwaddr, sizeof hwaddr_node->entry->hwaddr) == 0)
			break;
	}

	if (addr_node == NULL && hwaddr_node == NULL) {

		entry = entry_alloc(table, addr, hwaddr, now);
		if (entry == NULL)
			goto err;

		addr_node = node_alloc(&table->addr_hash[addr_hash], entry);
		if (addr_node == NULL) {
			entry_free(table, entry);
			goto err;
		}

		hwaddr_node = node_alloc(&table->hwaddr_hash[hwaddr_hash], entry);
		if (hwaddr_node == NULL) {
			node_free(&table->addr_hash[addr_hash], addr_node);
			entry_free(table, entry);
			goto err;
		}


		fprintf(stderr, "IP %s added %02x:%02x:%02x:%02x:%02x:%02x\n", inet_ntoa(entry->addr),
			entry->hwaddr[0], entry->hwaddr[1], entry->hwaddr[2], entry->hwaddr[3], entry->hwaddr[4], entry->hwaddr[5]);

	} else if (addr_node != NULL && hwaddr_node == NULL) {

		wrn("%02x:%02x:%02x:%02x:%02x:%02x stolled IP %s (previously holded by %02x:%02x:%02x:%02x:%02x:%02x)\n",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			inet_ntoa(addr),
			addr_node->entry->hwaddr[0], addr_node->entry->hwaddr[1], addr_node->entry->hwaddr[2], addr_node->entry->hwaddr[3], addr_node->entry->hwaddr[4], addr_node->entry->hwaddr[5]);

	} else if (addr_node == NULL && hwaddr_node != NULL) {
		char tmp[sizeof "xxx.xxx.xxx.xxx"];
		snprintf(tmp, sizeof tmp, "%s", inet_ntoa(hwaddr_node->entry->addr));

		wrn("IP %s stolled %02x:%02x:%02x:%02x:%02x:%02x (previously holded by IP %s)\n",
			inet_ntoa(addr),
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			tmp);

	} else {

		if (addr_node->entry != hwaddr_node->entry)
			die("Internal fuck\n");

		entry = (struct arp_entry *)addr_node->entry;
		entry->last_seen = *now;
	}

	arp_table_dump(table);
	return entry;

err:
	return NULL;
}
