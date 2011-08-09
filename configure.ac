#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.56)
sinclude(acx_nlnetlabs.m4)
CFLAGS="$CFLAGS"

AC_INIT(dnssec-trigger, 0.1, labs@nlnetlabs.nl, dnssec-trigger)
AC_AIX
AC_C_CONST
AC_LANG_C

dnl
dnl By default set prefix to /usr/local
dnl
case "$prefix" in
        NONE)
		prefix="/usr/local"
        ;;
esac

AC_DEFINE(WINVER, 0x0502, [the version of the windows API enabled])
dnl compute package version for windows res files, the first four numbers.
[
wnvs=`echo $PACKAGE_VERSION | sed -e 's/^[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\).*$/\1,\2,\3,\4/' -e 's/^[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*$/\1,\2,\3,0/' `
]
AC_DEFINE_UNQUOTED(RSRC_PACKAGE_VERSION, [$wnvs], [version number for resource files])

ACX_DEPFLAG
ACX_DETERMINE_EXT_FLAGS_UNBOUND

AC_CHECK_HEADERS([getopt.h time.h],,, [AC_INCLUDES_DEFAULT])

# MinGW32 tests
AC_CHECK_HEADERS([winsock2.h ws2tcpip.h],,, [AC_INCLUDES_DEFAULT])
# end mingw32 tests

# flag warnings.
AC_ARG_ENABLE(debug, AC_HELP_STRING([--enable-debug], [Enable debug warnings, asserts, makefile-dependencies]))
debug_enabled="$enable_debug"
AC_SUBST(debug_enabled)
case "$enable_debug" in
        yes)
		ACX_CHECK_COMPILER_FLAG(W, [CFLAGS="$CFLAGS -W"])
		ACX_CHECK_COMPILER_FLAG(Wall, [CFLAGS="$CFLAGS -Wall"])
		ACX_CHECK_COMPILER_FLAG(Wextra, [CFLAGS="$CFLAGS -Wextra"])
		ACX_CHECK_COMPILER_FLAG(Wdeclaration-after-statement, [CFLAGS="$CFLAGS -Wdeclaration-after-statement"])
		AC_DEFINE([DO_DEBUG], [], [define this to enable debug checks.])
		;;
	no|*)
		# nothing to do.
		;;
esac

AC_C_INLINE
ACX_CHECK_FORMAT_ATTRIBUTE
ACX_CHECK_UNUSED_ATTRIBUTE

if test "$srcdir" != "."; then
	CPPFLAGS="$CPPFLAGS -I$srcdir"
fi

AC_CHECK_TOOL(STRIP, strip)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h stdbool.h netinet/in.h sys/param.h sys/socket.h sys/uio.h sys/resource.h arpa/inet.h syslog.h netdb.h sys/wait.h],,, [AC_INCLUDES_DEFAULT])

# check for types
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(int32_t, int)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(uint32_t, unsigned int)
AC_CHECK_TYPE(uint64_t, unsigned long long)
AC_TYPE_SIZE_T
AC_CHECK_TYPE(ssize_t, int)
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_OFF_T
AC_CHECK_TYPE(u_char, unsigned char)
ACX_TYPE_RLIM_T
ACX_TYPE_SOCKLEN_T
ACX_TYPE_IN_ADDR_T
ACX_TYPE_IN_PORT_T

# check to see if libraries are needed for these functions.
AC_SEARCH_LIBS([inet_pton], [nsl])
AC_SEARCH_LIBS([socket], [socket])

# set static linking if requested
AC_SUBST(staticexe)
staticexe=""
AC_ARG_ENABLE(staticexe, AC_HELP_STRING([--enable-static-exe],
	[ enable to compile executables statically against libs, for debug purposes ]), 
	, )
if test x_$enable_static_exe = x_yes; then
	staticexe="-static"
fi

AC_FUNC_MALLOC
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_FUNC_FSEEKO
ACX_SYS_LARGEFILE

ACX_CHECK_GETADDRINFO_WITH_INCLUDES
if test "$USE_WINSOCK" = 1; then
	AC_DEFINE(UB_ON_WINDOWS, 1, [Use win32 resources and API])
	UB_ON_WINDOWS=yes
	AC_SUBST(UB_ON_WINDOWS)
	AC_CHECK_HEADERS([iphlpapi.h],,, [AC_INCLUDES_DEFAULT
#include <windows.h>
	])
	AC_CHECK_TOOL(WINDRES, windres)
	LIBS="$LIBS -liphlpapi"
else
	AC_DEFINE(USE_MINI_EVENT, 1, [Use builtin event system])
fi
if test $ac_cv_func_getaddrinfo = no; then
AC_LIBOBJ([fake-rfc2553])
fi

# check after getaddrinfo for its libraries
ACX_FUNC_IOCTLSOCKET

AC_CHECK_FUNCS([fcntl])

# dependencies from crypto, eventlibs for ldns, unbound.
ACX_WITH_SSL
ACX_LIB_SSL

# check this after all other compilation checks, since the linking of the lib
# may break checks after this.
AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=PATH], 
	[specify prefix of path of ldns library to use]), 
	[
	CPPFLAGS="-I$withval/include $CPPFLAGS"
	LDFLAGS="-L$withval -L$withval/lib $LDFLAGS"
	LIBS="-lldns $LIBS"
	ldnsdir="$withval"
	RUNTIME_PATH="$RUNTIME_PATH -Wl,--rpath=$withval/lib -Wl,--rpath=$withval/.libs"
	AC_SUBST(ldnsdir)
])

# add option to disable the evil rpath
ACX_ARG_RPATH
AC_SUBST(RUNTIME_PATH)

AC_DEFINE_UNQUOTED([MAXSYSLOGMSGLEN], [10240], [Define to the maximum message length to pass to syslog.])
AC_DEFINE_UNQUOTED([DNS_PORT], [53], [DNS port number])

AH_BOTTOM([
#ifndef DO_DEBUG
#  define NDEBUG
#endif

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <assert.h>

#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif

#ifdef HAVE_STDINT_H
#include <stdint.h>
#endif

#include <errno.h>

#if HAVE_SYS_PARAM_H
#include <sys/param.h>
#endif

#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif

#ifdef HAVE_SYS_UIO_H
#include <sys/uio.h>
#endif

#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#ifdef HAVE_WINSOCK2_H
#include <winsock2.h>
#endif

#ifdef HAVE_WS2TCPIP_H
#include <ws2tcpip.h>
#endif

#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif

#ifdef HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif

#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif

#ifdef HAVE_ATTR_FORMAT
#  define ATTR_FORMAT(archetype, string_index, first_to_check) \
    __attribute__ ((format (archetype, string_index, first_to_check)))
#else /* !HAVE_ATTR_FORMAT */
#  define ATTR_FORMAT(archetype, string_index, first_to_check) /* empty */
#endif /* !HAVE_ATTR_FORMAT */
#if defined(DOXYGEN)
#  define ATTR_UNUSED(x)  x
#elif defined(__cplusplus)
#  define ATTR_UNUSED(x)
#elif defined(HAVE_ATTR_UNUSED)
#  define ATTR_UNUSED(x)  x __attribute__((unused))
#else /* !HAVE_ATTR_UNUSED */
#  define ATTR_UNUSED(x)  x
#endif /* !HAVE_ATTR_UNUSED */
#ifndef HAVE_FSEEKO
#define fseeko fseek
#define ftello ftell
#endif /* HAVE_FSEEKO */
#if defined(HAVE_EVENT_H) && !defined(HAVE_EVENT_BASE_ONCE) && (defined(HAVE_PTHREAD) || defined(HAVE_SOLARIS_THREADS))
   /* using version of libevent that is not threadsafe. */
#  define LIBEVENT_SIGNAL_PROBLEM 1
#endif

#ifndef RAND_MAX
#define RAND_MAX	2147483647
#endif

#ifndef CHECKED_INET6
#  define CHECKED_INET6
#  ifdef AF_INET6
#    define INET6
#  else
#    define AF_INET6        28
#  endif
#endif /* CHECKED_INET6 */

#ifndef HAVE_GETADDRINFO
struct sockaddr_storage;
#include "compat/fake-rfc2553.h"
#endif

/* detect if we need to cast to unsigned int for FD_SET to avoid warnings */
#ifdef HAVE_WINSOCK2_H
#define FD_SET_T (u_int)
#else
#define FD_SET_T 
#endif

#include "ldns/ldns.h"
])

DATE=`date +%x`
AC_SUBST(DATE)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
