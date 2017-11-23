
#ifndef __arpinger_h_666__
# define __arpinger_h_666__

# include "arp_dev.h"
# include "arp_table.h"
# include "arp_net.h"
# include "arp_event.h"

struct arpinger {
	struct arp_dev dev;
	struct arp_net net;
	struct arp_table table;
	struct arp_event_list event;

	long req_delay_ms;
	long expire_ms;
	long poll_ms;
};

int arpinger_init(struct arpinger *arp, const char *dev, const char *from, const char *to, const long req_delay_ms, const long max_lost, const size_t max_event);
ssize_t arpinger_loop(struct arpinger *arp);
void arpinger_free(struct arpinger *arp);

#endif
