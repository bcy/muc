#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.52])
AC_INIT([ndn-muc], [0.0], [redmine.irl@gmail.com])
AC_CONFIG_SRCDIR([include/conference.h])
AC_CONFIG_HEADERS([config.h])
AM_INIT_AUTOMAKE([ndn-muc],[0.0])

# Checks for programs.
AC_PROG_CC
AC_PROG_CXX
AC_PROG_RANLIB

dnl helper macros
sinclude(m4/ac_define_dir.m4)

LDFLAGS="$LDFLAGS -L/usr/lib -L/usr/local/lib -L/opt/local/lib"

# Checks for libraries.
AC_CHECK_LIB([crypto], [SHA1_Init], [], [libcrypto=no])
if test "$libcrypto" == "no"; then
	AC_MSG_ERROR([Could not find required libcrypto installation])
fi

#AC_ARG_WITH([ccnx], [AS_HELP_STRING([--with-ccnx],
#	    [Where to find ccnx, defaults to /usr/local])],
#	    [LIBS="${LIBS} -L$withval/lib -lccn", CFLAGS="${CFLAGS} -I$withval/include/ccn", libccn=yes],
#	    [])
AC_CHECK_LIB([ccn], [ccn_run], [], [libccn=no])
if test "$libccn" == "no"; then
	AC_MSG_ERROR([Could not find required libccn installation])
fi

AC_CHECK_LIB([expat], [XML_Parse], [], [libexpat=no])
if test "$libexpat" == "no"; then
	AC_MSG_ERROR([Could not find required libexpat installation])
fi

AC_CHECK_LIB([idn], [stringprep], [], [libidn=no])
if test "$libidn" == "no"; then
	AC_MSG_ERROR([Could not find required libidn installation])
fi

AC_CHECK_LIB([gthread-2.0], [g_thread_init], [libgthread=yes], [libgthread=no])
if test "$libgthread" == "no"; then
	AC_MSG_ERROR([Could not find required libgthread-2.0 installation])
fi

#AC_CHECK_LIB([pthread], [main])

AC_CHECK_LIB([glib-2.0], [g_str_hash], [libglib=yes], [libglib=no])
if test "$libglib" == "no"; then
	AC_MSG_ERROR([Could not find required libglib-2.0 installation])
fi

if test "$libgthread" == "yes" -a "$libglib" == "yes"; then
	LIBS="`pkg-config --libs glib-2.0` `pkg-config --libs gthread-2.0` $LIBS"
fi

AC_CHECK_LIB([m], [pow], [], [libm=no])
if test "$libm" == "no"; then
	AC_MSG_ERROR([Could not find required libm installation])
fi

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([bzero gethostbyname gethostname isascii memset mkdir modf socket strcasecmp strchr strdup strncasecmp strncpy strrchr strstr uname])

dnl define where the configuration file is located
AC_DEFINE_DIR(CONFIG_DIR,sysconfdir,[where the configuration file can be found])

AC_OUTPUT(
		[
		Makefile
		src/Makefile
		scripts/Makefile
		]
)

