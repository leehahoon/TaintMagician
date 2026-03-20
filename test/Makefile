CC = gcc

PROGS = simple1 simple2 simple3 simple4

.PHONY: all clean

all: ${PROGS}

${PROGS}: example.o

example.o: example.c example.h
	${CC} -c example.c -o example.o

.c:
	${CC} -o $@ $@.c example.o

clean:
	rm -f ${PROGS} example.o