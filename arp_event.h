
#ifndef __arp_event_h_666__
# define __arp_event_h_666__

# include "arp_table.h"

typedef enum arp_event_entry_data_flags {
	arp_event_entry_data_have_old = (1 << 0),
	arp_event_entry_data_have_current = (1 << 1),
} arp_event_entry_data_flags_t;

struct arp_event_entry_data {
	struct arp_entry_data current;
	struct arp_entry_data old;
	arp_event_entry_data_flags_t flags;
};

struct arp_event_entry {
	struct arp_event_entry_data data;
	struct arp_event_entry *next;
	struct arp_event_entry *prev;
};

struct arp_event_list {
	struct arp_event_entry *first;
	struct arp_event_entry *last;
	size_t event_max;
	size_t event_count;
};

struct arp_event_res {

	struct {
		struct arp_entry_net_info info;
		struct timeval first;
		struct timeval last;
	} current, old;

	arp_event_entry_data_flags_t flags;
};

void arp_event_list_init(struct arp_event_list *list, const size_t event_max);
void arp_event_list_free(struct arp_event_list *list);

int arp_event_list_get(struct arp_event_list *list, const struct arp_table *table, struct arp_event_res *res);
struct arp_event_entry *arp_event_list_add(struct arp_event_list *list, const struct arp_entry_data *old, const struct arp_entry_data *current);

#endif
