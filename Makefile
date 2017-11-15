
DEP_FILE = .$(shell pwd | sed 's|/||g').depend

ARP_CFLAGS = -DARP_DEBUG=1
ARP_CFLAGS += -DARP_CHECK=1

EXE = arpinger
CFLAGS = -g -Wall -Werror -Wextra $(ARP_CFLAGS)
LDFLAGS = $(ARP_LDFLAGS)

all: $(DEP_FILE) $(EXE)

arpinger: main.o arp_dev.o arp_frame.o arp_table.o time_utils.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *~ $(EXE) $(DEP_FILE)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

$(DEP_FILE) depend dep: Makefile
	$(CC) -MM -MG $(CFLAGS) *.c > $(DEP_FILE)

ifeq ($(DEP_FILE),$(wildcard $(DEP_FILE)))
include $(DEP_FILE)
endif
