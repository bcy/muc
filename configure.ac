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

LDFLAGS="$LDFLAGS -L/opt/local/lib -L/usr/lib -L/usr/local/lib"

# Checks for libraries.
# FIXME: Replace `main' with a function in `-lcrypto':
AC_CHECK_LIB([crypto], [SHA1_Init])
# FIXME: Replace `main' with a function in `-lccn':
AC_CHECK_LIB([ccn], [ccn_run])
# FIXME: Replace `main' with a function in `-lexpat':
AC_CHECK_LIB([expat], [XML_Parse])
# FIXME: Replace `main' with a function in `-lidn':
AC_CHECK_LIB([idn], [stringprep])

AC_CHECK_LIB([gthread-2.0], [g_thread_init])
#AC_CHECK_LIB([rt], [main])
#AC_CHECK_LIB([pthread], [main])
AC_CHECK_LIB([glib-2.0], [g_str_hash])

# FIXME: Replace `main' with a function in `-lm':
#AC_CHECK_LIB([m], [pow])

# Checks for header files.
AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdlib.h string.h strings.h sys/param.h sys/socket.h sys/time.h syslog.h unistd.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_FORK
AC_FUNC_MALLOC
AC_FUNC_MKTIME
AC_CHECK_FUNCS([bzero gethostbyname gethostname isascii memset mkdir modf socket strcasecmp strchr strdup strncasecmp strndup strrchr strstr uname])

dnl define where the configuration file is located
AC_DEFINE_DIR(CONFIG_DIR,sysconfdir,[where the configuration file can be found])

AC_OUTPUT(
		[
		Makefile
		src/Makefile
		scripts/Makefile
		]
)

