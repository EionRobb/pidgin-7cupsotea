
COMPILER = gcc

LIBPURPLE_CFLAGS += $(shell pkg-config --cflags glib-2.0 json-glib-1.0 purple)
LIBPURPLE_LIBS += $(shell pkg-config --libs glib-2.0 json-glib-1.0 purple)

7CUP_SOURCES = \
	7cup_connection.c \
	lib7cup.c 

.PHONY:	all clean install
all: lib7cup.so
clean:
	rm -f lib7cup.so

lib7cup.so: ${7CUP_SOURCES}
	${COMPILER} -Wall -I. -g -O2 -fPIC -pipe ${7CUP_SOURCES} -o $@ ${LIBPURPLE_CFLAGS} ${LIBPURPLE_LIBS} -shared
