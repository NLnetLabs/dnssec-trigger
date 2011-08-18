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

AC_MSG_CHECKING([if -export-dynamic works])
bakld="$LDFLAGS"
LDFLAGS="$LDFLAGS -export-dynamic"
AC_LINK_IFELSE([AC_LANG_SOURCE([[
int main(void) {
	return 0;
}
]])], [
	AC_MSG_RESULT(yes)
	EXPORT_DYNAMIC="-export-dynamic"
], [AC_MSG_RESULT(no)])
LDFLAGS="$bakld"
AC_SUBST(EXPORT_DYNAMIC)

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
staticexe="no"
AC_ARG_ENABLE(static-exe, AC_HELP_STRING([--enable-static-exe],
	[ enable to compile executables statically against ldns and crypto libs ]), 
	, )
if test x_$enable_static_exe = x_yes; then
	staticexe="yes"
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

# see if daemon(3) exists, and if it is deprecated.
AC_CHECK_FUNCS([daemon])
if test $ac_cv_func_daemon = yes; then
        ACX_FUNC_DEPRECATED([daemon], [(void)daemon(0, 0);], [
#include <stdlib.h>
])
fi

AC_CHECK_FUNCS([strftime localtime_r fcntl setsid])

hooks="auto"
AC_ARG_WITH([hooks], AC_HELP_STRING([--with-hooks],
[Set the DHCP change hooks to use, default 'auto', can be 'osx', 'networkmanager', 'netconfig', or 'none']),,)
if test -n "$withval"; then
	hooks="$withval"
fi

# hook settings
networkmanager_dispatcher_dir="$sysconfdir/NetworkManager/dispatcher.d"
AC_ARG_WITH([networkmanager-dispatch], AC_HELP_STRING([--with-networkmanager-dispatch],
	[Set the networkmanager dhcp dispatcher dir, default tests prefix/etc/NetworkManager/dispatcher.d and /etc/NetworkManager/dispatcher.d]),
	, )
with_nm_dispatch="$withval"
AC_SUBST(networkmanager_dispatcher_dir)

netconfig_dispatcher_dir="$sysconfdir/netconfig.d"
AC_ARG_WITH([netconfig-dispatch], AC_HELP_STRING([--with-netconfig-dispatch],
	[Set the netconfig dhcp dispatcher dir, default tests prefix/etc/netconfig.d and /etc/netconfig.d]),
	, )
with_netconfig_dispatch="$withval"
AC_SUBST(netconfig_dispatcher_dir)

AC_MSG_CHECKING([for DHCP hooks])
if test "$hooks" != "auto"; then
	:
else
	if test -x "`which nmcli 2>&1`"; then
	hooks="networkmanager"
	else
		if test `uname` = "Darwin"; then
			hooks="osx"
		else
			if test -x /sbin/netconfig; then
				hooks="netconfig"
			else
				hooks="none"
			fi
		fi
	fi
fi
AC_MSG_RESULT([$hooks])
AC_SUBST(hooks)

if test "$hooks" = "networkmanager"; then
	AC_MSG_CHECKING([for NetworkManager dispatch])
	if test "$with_nm_dispatch" != ""; then
		networkmanager_dispatcher_dir="$with_nm_dispatch"
	else
		if test -d $networkmanager_dispatcher_dir ; then
			:
		else if test -d /etc/NetworkManager/dispatcher.d; then
			networkmanager_dispatcher_dir="/etc/NetworkManager/dispatcher.d"
			fi
		fi
	fi
	AC_MSG_RESULT([$networkmanager_dispatcher_dir])
fi
if test "$hooks" = "netconfig"; then
	AC_MSG_CHECKING([for netconfig.d])
	if test "$with_netconfig_dispatch" != ""; then
		netconfig_dispatcher_dir="$with_netconfig_dispatch"
	else
		if test -d $netconfig_dispatcher_dir ; then
			:
		else if test -d /etc/netconfig.d; then
			netconfig_dispatcher_dir="/etc/netconfig.d"
			fi
		fi
	fi
	AC_MSG_RESULT([$netconfig_dispatcher_dir])
fi
if test "$hooks" = "none"; then
	AC_MSG_WARN([have no DHCP hooks, cannot detect network changes])
fi

AC_ARG_WITH([keydir], AC_HELP_STRING([--with-keydir=path],
[Set the directory where ssl key files are kept, read by daemon and other tools, default prefix/etc]),,)
keydir=`eval echo "$sysconfdir"`
if test -n "$withval"; then
	keydir="$withval"
fi
ACX_ESCAPE_BACKSLASH($keydir, keydir_esc)
AC_DEFINE_UNQUOTED([KEYDIR], ["$keydir_esc"], [directory with ssl key files for dnssec-trigger])
AC_SUBST(keydir)

AC_ARG_WITH([uidir], AC_HELP_STRING([--with-uidir=path],
[Set the directory where ui files (icon,xml) are kept, default prefix/share/dnssec-trigger]),,)
uidir=`eval echo "$datadir/dnssec-trigger"`
if test -n "$withval"; then
	uidir="$withval"
fi
uidir2=`eval echo $uidir`
ACX_ESCAPE_BACKSLASH($uidir2, uidir_esc)
AC_DEFINE_UNQUOTED([UIDIR], ["$uidir_esc"], [directory with UI xml and png for dnssec-trigger])
AC_SUBST(uidir)

AC_ARG_WITH([configfile], AC_HELP_STRING([--with-configfile=path],
[set the configfile to use, default keydir/dnssec-trigger.conf]),,)
configfile="$keydir/dnssec-trigger.conf"
if test -n "$withval"; then
	configfile="$withval"
fi
ACX_ESCAPE_BACKSLASH($configfile, configfile_esc)
AC_DEFINE_UNQUOTED([CONFIGFILE], ["$configfile_esc"], [default config file name for dnssec-trigger])
AC_SUBST(configfile)

AC_ARG_WITH([pidfile], AC_HELP_STRING([--with-pidfile=path],
[set the pidfile to use, default /var/run/dnssec-trigger.pid]),,)
pidfile="/var/run/dnssec-trigger.pid"
if test -n "$withval"; then
	pidfile="$withval"
fi
ACX_ESCAPE_BACKSLASH($pidfile, pidfile_esc)
AC_DEFINE_UNQUOTED([PIDFILE], ["$pidfile_esc"], [default pidfile name for dnssec-trigger])
AC_SUBST(pidfile)

# dependencies from crypto, eventlibs for ldns, unbound.
ACX_WITH_SSL
ACX_LIB_SSL
AC_CHECK_HEADERS([openssl/conf.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/engine.h],,, [AC_INCLUDES_DEFAULT])
if test "$staticexe" = "yes"; then
	LIBS="`echo $LIBS | sed -e 's/ -lcrypto//'`"
	LIBS="$ssldir/lib/libssl.a $ssldir/lib/libcrypto.a $LIBS"
else
	LIBS="-lssl $LIBS"
fi

# GTK
GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
GTK_LIBS=`pkg-config --libs gtk+-2.0`
if test -z "$GTK_LIBS"; then
	AC_MSG_WARN([No gtk+-2.0 detected, please install glib-dev, gtk2-dev])
fi
AC_SUBST(GTK_CFLAGS)
AC_SUBST(GTK_LIBS)
# check for missing -lgthread-2.0 in the GTK_LIBS string.
case "$GTK_LIBS" in *-lgthread* ) ;;
*) AC_CHECK_LIB(gthread-2.0, g_thread_init, [GTK_LIBS="$GTK_LIBS -lgthread-2.0"]) esac

LDNSLIBS=""
AC_ARG_WITH(ldns, AC_HELP_STRING([--with-ldns=PATH], 
	[specify prefix of path of ldns library to use]), 
	[
	CPPFLAGS="-I$withval/include $CPPFLAGS"
	LDFLAGS="-L$withval -L$withval/lib $LDFLAGS"
	ldnsdir="$withval"
	if test "$staticexe" = "yes"; then
		LDNSLIBS="$ldnsdir/lib/libldns.a"
	else
		LDNSLIBS="-lldns"
		ACX_RUNTIME_PATH_ADD([$withval/lib])
	fi
	AC_SUBST(ldnsdir)
	AC_SUBST(LDNSLIBS)
	], [
	AC_CHECK_FUNCS([ldns_buffer_new],,[AC_MSG_ERROR([please install ldns-devel])])
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

if test "$hooks" = "none"; then
	echo "WARNING NO DHCP HOOKS DETECTED CANNOT SETUP TRIGGER"
fi
[
echo "configure completed with $hooks hooks, now you can"
echo "	make | make all		: compile the code"
echo "	make install 		: install files"
echo "	make uninstall 		: uninstall files"
]

