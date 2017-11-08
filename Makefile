
EXE = arpinger
CFLAGS = -g -Wall -Werror

all: $(EXE)


arpinger: arpinger.o ifinfo.o frame.o arptable.o
	$(CC) $(LDFLAGS) $^ -o $@

clean:
	rm -f *.o *~ $(EXE)

arpinger.o: arpinger.c ifinfo.h frame.h err.h arptable.h
arptable.o: arptable.c arptable.h err.h
frame.o: frame.c frame.h ifinfo.h
ifinfo.o: ifinfo.c ifinfo.h err.h
