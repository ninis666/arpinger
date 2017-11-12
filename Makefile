
ARP_CFLAGS = -DARP_DEBUG=1

EXE = arpinger
CFLAGS = -g -Wall -Werror $(ARP_CFLAGS)
LDFLAGS = $(ARP_LDFLAGS)

all: $(EXE)

arpinger: main.o arp_dev.o arp_frame.o arp_table.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *~ $(EXE)

%.o: %.c Makefile
	$(CC) $(CFLAGS) -c $< -o $@

main.o: main.c arp_dev.h arp_frame.h log.h arp_table.h
arp_table.o: arp_table.c arp_table.h log.h
arp_frame.o: arp_frame.c arp_frame.h arp_dev.h
arp_dev.o: arp_dev.c arp_dev.h log.h
