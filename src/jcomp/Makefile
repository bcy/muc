
#  $Id: Makefile,v 1.1 2005/12/06 14:48:49 peregrine Exp $
CC=gcc
CFLAGS:=$(CFLAGS) -O2 -Wall -I../../include -I. `pkg-config --cflags glib-2.0` -D_REENTRANT
LIBS=

JCOMP_OBJECTS=jcr_xdb.o \
	jcr_log.o \
	jcr_deliver.o \
	jcr_elements.o \
	jcr_main_stream_error.o \
	jcr_shutdown.o \
	jcr_compatibility.o \
	jcr_base_connect.o


all: $(JCOMP_OBJECTS) main.o
	gcc -g $(JCOMP_OBJECTS) main.o ../libjcomp.a `pkg-config --libs gthread-2.0` `pkg-config --libs glib-2.0` -o main

lib: $(JCOMP_OBJECTS)
	@ar rv ../libjcomp.a $(JCOMP_OBJECTS)
	@ranlib ../libjcomp.a

clean:
	rm -f $(JCOMP_OBJECTS)

