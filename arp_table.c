
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>

#include "arp_table.h"
#include "log.h"
#include "time_utils.h"
#include "list_utils.h"

int arp_table_init(struct arp_table *table, const size_t addr_max_hash, const size_t hwaddr_max_hash)
{
	int res;

	memset(table, 0, sizeof table[0]);

	res = clock_gettime(CLOCK_MONOTONIC, &table->initial_clock);
	chk(res == 0);

	res = gettimeofday(&table->initial_time, NULL);
	chk(res == 0);

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

#define node_next(n) n->pool_node.next
#define node_prev(n) n->pool_node.prev

static void node_link_pool(struct arp_list *list, struct arp_entry *entry)
{
	node_link(list, entry);
}

static void node_unlink_pool(struct arp_list *list, struct arp_entry *entry)
{
	node_unlink(list, entry);
}

static void node_try_unlink_pool(struct arp_list *list, struct arp_entry *entry)
{
	node_try_unlink(list, entry);
}

#undef node_next
#undef node_prev

#define node_next(n) n->addr_node.next
#define node_prev(n) n->addr_node.prev

static void node_link_addr(struct arp_list *list, struct arp_entry *entry)
{
	node_link(list, entry);
}

static void node_unlink_addr(struct arp_list *list, struct arp_entry *entry)
{
	node_unlink(list, entry);
}

static void node_try_unlink_addr(struct arp_list *list, struct arp_entry *entry)
{
	node_try_unlink(list, entry);
}

#undef node_next
#undef node_prev

#define node_next(n) n->hwaddr_node.next
#define node_prev(n) n->hwaddr_node.prev

static void node_link_hwaddr(struct arp_list *list, struct arp_entry *entry)
{
	node_link(list, entry);
}

static void node_unlink_hwaddr(struct arp_list *list, struct arp_entry *entry)
{
	node_unlink(list, entry);
}

static void node_try_unlink_hwaddr(struct arp_list *list, struct arp_entry *entry)
{
	node_try_unlink(list, entry);
}

#undef node_next
#undef node_prev

static struct arp_entry *entry_alloc(const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now)
{
	struct arp_entry *entry = NULL;
	struct arp_entry_data *data;

	entry = calloc(1, sizeof entry[0]);
	if (entry == NULL) {
		err("calloc : %m\n");
		goto err;
	}
	data = &entry->data;

	data->addr = addr;
	memcpy(&data->hwaddr, hwaddr, sizeof data->hwaddr);
	data->first_seen = *now;
	data->last_seen = *now;
err:
	return entry;
}

static void entry_free(struct arp_table *table, struct arp_entry *entry)
{
	struct arp_entry_data *data = &entry->data;

	node_try_unlink_pool(&table->pool_list, entry);
	node_try_unlink_addr(arp_list_addr(table, data->addr), entry);
	node_try_unlink_hwaddr(arp_list_hwaddr(table, data->hwaddr), entry);
	free(entry);
}

size_t arp_table_dump(const struct arp_table *table, char **res, const char *pfx, const char *sfx)
{
	FILE *fp;
	char *ptr = NULL;
	size_t size = 0;

	fp = open_memstream(&ptr, &size);
	if (fp == NULL) {
		err("open_memstream failed : %m\n");
		goto err;
	}

	for (struct arp_entry *entry = table->pool_list.first ; entry != NULL ; entry = entry->pool_node.next) {
		struct arp_entry_data *data = &entry->data;
		struct timespec first_dt;
		struct timespec last_dt;
		struct timeval first;
		struct timeval last;
		struct tm first_tm;
		struct tm last_tm;

		timespec_sub(&data->first_seen, &table->initial_clock, &first_dt);
		timespec_sub(&data->last_seen, &table->initial_clock, &last_dt);
		timeval_add_timespec(&table->initial_time, &first_dt, &first);
		timeval_add_timespec(&table->initial_time, &last_dt, &last);

		localtime_r(&first.tv_sec, &first_tm);
		localtime_r(&last.tv_sec, &last_tm);

		fprintf(fp, "%s%16s %02x:%02x:%02x:%02x:%02x:%02x, first = %02d_%02d_%02d %02d:%02d:%02d:%03ld, last = %02d_%02d_%02d %02d:%02d:%02d:%03ld%s",
			pfx ? pfx : "",
			inet_ntoa(data->addr),
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5],
			1900 + first_tm.tm_year, first_tm.tm_mon + 1, first_tm.tm_mday, first_tm.tm_hour, first_tm.tm_min, first_tm.tm_sec, first.tv_usec / 1000,
			1900 + last_tm.tm_year, last_tm.tm_mon + 1, last_tm.tm_mday, last_tm.tm_hour, last_tm.tm_min, last_tm.tm_sec,  last.tv_usec / 1000,
			sfx ? sfx : "");
	}

	fclose(fp);
err:
	*res = ptr;
	return size;
}

static struct arp_entry *node_lookup_addr(const struct arp_list *list, const struct in_addr addr)
{
	struct arp_entry *entry;

	for (entry = list->first ; entry != NULL ; entry = entry->addr_node.next) {
		if (entry->data.addr.s_addr == addr.s_addr)
			break;
	}

	return entry;
}

static struct arp_entry *node_lookup_hwaddr(struct arp_list *list, const uint8_t *hwaddr)
{
	struct arp_entry *entry;

	for (entry = list->first ; entry != NULL ; entry = entry->hwaddr_node.next) {
		if (memcmp(entry->data.hwaddr, hwaddr, sizeof entry->data.hwaddr) == 0)
			break;
	}

	return entry;
}

arp_table_add_t arp_table_add(struct arp_table *table, const struct in_addr addr, const uint8_t *hwaddr, const struct timespec *now, struct arp_entry **res)
{
	struct arp_list *addr_list;
	struct arp_list *hwaddr_list;
	struct arp_entry *addr_node;
	struct arp_entry *hwaddr_node;
	struct arp_entry *entry = NULL;
	arp_table_add_t ret = arp_table_add_error;

	addr_list = arp_list_addr(table, addr);
	hwaddr_list = arp_list_hwaddr(table, hwaddr);
	addr_node = node_lookup_addr(addr_list, addr);
	hwaddr_node = node_lookup_hwaddr(hwaddr_list, hwaddr);

	if (addr_node == NULL && hwaddr_node == NULL) {

		entry = entry_alloc(addr, hwaddr, now);
		if (entry == NULL)
			goto err;

		node_link_pool(&table->pool_list, entry);
		node_link_addr(addr_list, entry);
		node_link_hwaddr(hwaddr_list, entry);

		dbg("IP %s added to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(entry->data.addr),
			entry->data.hwaddr[0], entry->data.hwaddr[1], entry->data.hwaddr[2], entry->data.hwaddr[3], entry->data.hwaddr[4], entry->data.hwaddr[5]);

		ret = arp_table_add_new;

	} else if (addr_node != NULL && hwaddr_node == NULL) {
		struct arp_list *old_hwaddr_list;
		struct arp_entry *old_hwaddr_node;
		struct arp_entry_data *data;

		entry = addr_node;
		data = &entry->data;

		wrn("HW %02x:%02x:%02x:%02x:%02x:%02x stolled IP %s (previously holded by HW %02x:%02x:%02x:%02x:%02x:%02x)\n",
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			inet_ntoa(addr),
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5]);

		/*
		 * Add a new hwaddr with the addr entry and remove the old one
		 */

		old_hwaddr_list = &table->hwaddr_list[hwaddr_hash(table, data->hwaddr)];
		old_hwaddr_node = node_lookup_hwaddr(old_hwaddr_list, data->hwaddr);
		chk(old_hwaddr_node == entry);

		node_unlink_hwaddr(old_hwaddr_list, old_hwaddr_node);
		node_link_hwaddr(hwaddr_list, entry);
		memcpy(data->hwaddr, hwaddr, sizeof data->hwaddr);

		dbg("IP %s updated to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(data->addr),
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5]);

		ret = arp_table_add_hwaddr_changed;

	} else if (addr_node == NULL && hwaddr_node != NULL) {
		struct arp_list *old_addr_list;
		struct arp_entry *old_addr_node;
		struct arp_entry_data *data;
		char tmp[sizeof "xxx.xxx.xxx.xxx"];

		entry = hwaddr_node;
		data = &entry->data;

		snprintf(tmp, sizeof tmp, "%s", inet_ntoa(data->addr));
		wrn("IP %s stolled HW %02x:%02x:%02x:%02x:%02x:%02x (previously holded by IP %s)\n",
			inet_ntoa(addr),
			hwaddr[0], hwaddr[1], hwaddr[2], hwaddr[3], hwaddr[4], hwaddr[5],
			tmp);

		/*
		 * Add a new addr with the hwaddr entry and remove the old one
		 */
		old_addr_list = &table->addr_list[addr_hash(table, data->addr)];
		old_addr_node = node_lookup_addr(old_addr_list, data->addr);
		chk(old_addr_node == entry);

		node_unlink_addr(old_addr_list, old_addr_node);
		node_link_addr(addr_list, entry);
		data->addr = addr;

		dbg("HW %02x:%02x:%02x:%02x:%02x:%02x updated to IP %s\n",
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5],
			inet_ntoa(data->addr));

		ret = arp_table_add_addr_changed;

	} else {
		struct arp_entry_data *data;

		chk(addr_node == hwaddr_node);
		entry = addr_node;
		data = &entry->data;

		dbg("IP %s still binded to HW %02x:%02x:%02x:%02x:%02x:%02x\n",
			inet_ntoa(data->addr),
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5]);

		ret = arp_table_add_nochange;
	}

	entry->data.last_seen = *now;
	node_unlink_pool(&table->pool_list, entry);
	node_link_pool(&table->pool_list, entry);

	if (res != NULL)
		*res = entry;
err:
	return ret;
}

size_t arp_table_check_expired(struct arp_table *table, const long expired_delay_ms)
{
	struct arp_entry *entry;
	int res;
	struct timespec now;
	size_t count = 0;

	res = clock_gettime(CLOCK_MONOTONIC, &now);
	chk(res >= 0);

	entry = table->pool_list.first;
	while (entry != NULL) {
		struct arp_entry *next = entry->pool_node.next;
		struct arp_entry_data *data = &entry->data;
		struct timespec dt;

		timespec_sub(&now, &data->last_seen, &dt);
		if (timespec_to_ms(&dt) < expired_delay_ms)
			break;

		wrn("IP %s binded to HW %02x:%02x:%02x:%02x:%02x:%02x expired since %ldms\n",
			inet_ntoa(data->addr),
			data->hwaddr[0], data->hwaddr[1], data->hwaddr[2], data->hwaddr[3], data->hwaddr[4], data->hwaddr[5],
			timespec_to_ms(&dt));

		entry_free(table, entry);
		count ++;

		entry = next;
	}

	return count;
}

void arp_table_free(struct arp_table *table)
{
	for (;;) {
		struct arp_entry *node;
		node = table->pool_list.first;
		if (node == NULL)
			break;
		entry_free(table, node);
	}

	free(table->addr_list);
	free(table->hwaddr_list);
	memset(table, 0, sizeof table[0]);
}
