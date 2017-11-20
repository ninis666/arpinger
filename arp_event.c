
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "arp_event.h"
#include "list_utils.h"

void arp_event_list_init(struct arp_event_list *list, const size_t event_max)
{
	memset(list, 0, sizeof list[0]);
	list->event_max = event_max;
}

static struct arp_event_entry *event_entry_alloc(const struct arp_entry_data *old, const struct arp_entry_data *current)
{
	struct arp_event_entry *entry;

	entry = calloc(1, sizeof entry[0]);
	if (entry == NULL) {
		err("calloc : %m\n");
		goto err;
	}

	entry->old_data = *old;
	entry->current_data = *current;

err:
	return entry;
}

#define node_next(n) n->next
#define node_prev(n) n->prev

static void node_event_link(struct arp_event_list *list, struct arp_event_entry *entry)
{
	node_link(list, entry);
}

static void node_event_unlink(struct arp_event_list *list, struct arp_event_entry *entry)
{
	node_unlink(list, entry);
}

#undef node_next
#undef node_prev

static void event_entry_free(struct arp_event_list *list, struct arp_event_entry *entry)
{
	node_event_unlink(list, entry);
	free(entry);
}

struct arp_event_entry *arp_event_list_add(struct arp_event_list *list, const struct arp_entry_data *old, const struct arp_entry_data *current)
{
	struct arp_event_entry *entry;

	if ((list->event_count + 1) >= list->event_max) {
		wrn("Already %zu entries, removing oldest entry\n", list->event_max);
		event_entry_free(list, list->first);
	}

	entry = event_entry_alloc(old, current);
	if (entry == NULL)
		goto err;
	node_event_link(list, entry);

	list->event_count ++;

err:
	return entry;
}

int arp_event_list_get(struct arp_event_list *list, struct arp_entry_data *old, struct arp_entry_data *current)
{
	struct arp_event_entry *entry;
	int ret = 0;

	entry = list->first;
	if (entry != NULL) {
		if (old != NULL)
			*old = entry->old_data;
		if (current != NULL)
			*current = entry->current_data;

		chk(list->event_count > 0);
		list->event_count --;
		event_entry_free(list, entry);

		ret = 1;
	}

	return ret;
}
