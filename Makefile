
EXE = arpinger
CFLAGS = -g -Wall -Werror

all: $(EXE)


arpinger: main.o arp_dev.o arp_frame.o arp_table.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *~ $(EXE)

main.o: main.c arp_dev.h arp_frame.h err.h arp_table.h
arp_table.o: arp_table.c arp_table.h err.h
arp_frame.o: arp_frame.c arp_frame.h arp_dev.h
arp_dev.o: arp_dev.c arp_dev.h err.h
