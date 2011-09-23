CC:=gcc
CFLAGS:=$(CFLAGS) -O2 -Wall -I../../lib -I../include `pkg-config --cflags glib-2.0` -D_JCOMP -D_REENTRANT -DLIBIDN
#CFLAGS:=$(CFLAGS) -O2 -Wall -I../../lib -I../include `pkg-config --cflags glib-2.0` -D_JCOMP -D_REENTRANT -DLIBIDN -DHAVE_MYSQL
LIBS:=$(LIBS) -ljcomp -lm `pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0` -lexpat -lidn
#LIBS:=$(LIBS) -ljcomp -lm `pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0` -lexpat -lidn `mysql_config --libs`
LDFLAGS:=-L.

# Debug/Experimental
#CFLAGS:=$(CFLAGS) -pipe -Os -I../../jabberd -I../include 
#LIBS:=$(LIBS) /usr/local/lib/ccmalloc-gcc.o -lccmalloc 
#LIBS:=$(LIBS) -lmemusage
#LIBS:=$(LIBS) -lmcheck

conference_OBJECTS=libjcomp.a conference.o conference_room.o conference_user.o utils.o xdata.o admin.o roles.o xdb.o hash.o iq.o main.o mysql.o 

all: mu-conference

mu-conference: $(conference_OBJECTS)
	$(CC) $(CFLAGS) $(MCFLAGS) -o mu-conference $(conference_OBJECTS) $(LDFLAGS) $(LIBS)

libjcomp.a:
	cd jabberd ; $(MAKE)
	cd jcomp ; $(MAKE) lib

static: $(conference_OBJECTS)

single: $(conference_OBJECTS)

clean:
	rm -f $(conference_OBJECTS) mu-conference *~
	cd jcomp ; $(MAKE) clean
	cd jabberd ; $(MAKE) clean
