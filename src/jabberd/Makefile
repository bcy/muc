
CC=gcc
CFLAGS:=$(CFLAGS) -O0 -Wall -I. -I../../include `pkg-config --cflags glib-2.0` -D_REENTRANT -DLIBIDN -g3
LIBS=

JCOMP_LIB_OBJECTS=expat.o \
	jid.o \
	jpacket.o \
	jutil.o \
	pool.o \
	sha.o \
	snprintf.o \
	str.o \
	xmlnode.o 


all: $(JCOMP_LIB_OBJECTS)
	ar rv ../libjcomp.a $(JCOMP_LIB_OBJECTS)
	ranlib ../libjcomp.a


clean:
	rm -f $(JCOMP_LIB_OBJECTS) ../libjcomp.a

