AM_CFLAGS = -O2 -Wall -I../../lib -I../include `PKG_CONFIG_PATH=/opt/local/lib/pkgconfig pkg-config --cflags glib-2.0` -D_JCOMP -D_REENTRANT -DLIBIDN -g

noinst_LIBRARIES = libjcomp.a
libjcomp_a_SOURCES = jabberd/expat.c jabberd/jid.c jabberd/jpacket.c jabberd/jutil.c jabberd/pool.c jabberd/sha.c jabberd/snprintf.c jabberd/str.c jabberd/xmlnode.c jcomp/jcr_base_connect.c jcomp/jcr_compatibility.c jcomp/jcr_deliver.c jcomp/jcr_elements.c jcomp/jcr_log.c jcomp/jcr_main_stream_error.c jcomp/jcr_shutdown.c jcomp/jcr_xdb.c

bin_PROGRAMS = muc
muc_SOURCES = admin.c conference.c conference_room.c conference_user.c hash.c iq.c main.c mysql.c ndn.c roles.c utils.c xdata.c xdb.c
muc_LDADD = libjcomp.a \
	    -L. -ljcomp

clean-local:
	rm -f *~
