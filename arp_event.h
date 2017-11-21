
#ifndef __arp_event_h_666__
# define __arp_event_h_666__

# include "arp_table.h"

struct arp_event_entry {
	struct arp_entry_data current_data;
	struct arp_entry_data old_data;
	struct arp_event_entry *next;
	struct arp_event_entry *prev;
};

struct arp_event_list {
	struct arp_event_entry *first;
	struct arp_event_entry *last;
	size_t event_max;
	size_t event_count;
};

void arp_event_list_init(struct arp_event_list *list, const size_t event_max);
void arp_event_list_free(struct arp_event_list *list);

int arp_event_list_get(struct arp_event_list *list, struct arp_entry_data *old, struct arp_entry_data *current);
struct arp_event_entry *arp_event_list_add(struct arp_event_list *list, const struct arp_entry_data *old, const struct arp_entry_data *current);

#endif
