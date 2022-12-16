#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
AC_PREREQ(2.56)
sinclude(acx_nlnetlabs.m4)
CFLAGS="$CFLAGS"

AC_INIT(dnssec-trigger, 0.18, labs@nlnetlabs.nl, dnssec-trigger)
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
if test "$exec_prefix" == "NONE"; then
	exec_prefix="$prefix"
fi

# are we on MinGW?
if uname -s 2>&1 | grep MINGW32 >/dev/null; then on_mingw="yes"
else
	if echo $target | grep mingw32 >/dev/null; then on_mingw="yes"
	else on_mingw="no"; fi
fi

AC_DEFINE(WINVER, 0x0502, [the version of the windows API enabled])
dnl compute package version for windows res files, the first four numbers.
[
wnvs=`echo $PACKAGE_VERSION.0.0 | sed -e 's/^[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\).*$/\1,\2,\3,\4/' -e 's/^[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*\([0-9]\)[^0-9]*$/\1,\2,\3,0/' `
]
AC_DEFINE_UNQUOTED(RSRC_PACKAGE_VERSION, [$wnvs], [version number for resource files])

ACX_DEPFLAG
ACX_DETERMINE_EXT_FLAGS_UNBOUND

AC_CHECK_HEADERS([getopt.h time.h],,, [AC_INCLUDES_DEFAULT])

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

if test "$on_mingw" = "yes"; then
	# this flag is only really needed for GTK+ applications for its
	# linkback of event functions.
	EXPORT_DYNAMIC="-Wl,-export-all-symbols"
else
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
fi

AC_C_INLINE
ACX_CHECK_FORMAT_ATTRIBUTE
ACX_CHECK_UNUSED_ATTRIBUTE

AC_DEFUN([CHECK_NORETURN_ATTRIBUTE],
[AC_REQUIRE([AC_PROG_CC])
AC_MSG_CHECKING(whether the C compiler (${CC-cc}) accepts the "noreturn" attribute)
AC_CACHE_VAL(ac_cv_c_noreturn_attribute,
[ac_cv_c_noreturn_attribute=no
AC_TRY_COMPILE(
[ #include <stdio.h>
__attribute__((noreturn)) void f(int x) { printf("%d", x); }
], [
   f(1);
],
[ac_cv_c_noreturn_attribute="yes"],
[ac_cv_c_noreturn_attribute="no"])
])

AC_MSG_RESULT($ac_cv_c_noreturn_attribute)
if test $ac_cv_c_noreturn_attribute = yes; then
  AC_DEFINE(HAVE_ATTR_NORETURN, 1, [Whether the C compiler accepts the "noreturn" attribute])
  AC_DEFINE(ATTR_NORETURN, [__attribute__((__noreturn__))], [apply the noreturn attribute to a function that exits the program])
fi
])dnl End of CHECK_NORETURN_ATTRIBUTE

CHECK_NORETURN_ATTRIBUTE

if test "$srcdir" != "."; then
	CPPFLAGS="$CPPFLAGS -I$srcdir"
fi

AC_CHECK_TOOL(STRIP, strip)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([stdarg.h stdbool.h netinet/in.h sys/param.h sys/socket.h sys/uio.h sys/resource.h arpa/inet.h syslog.h netdb.h sys/wait.h],,, [AC_INCLUDES_DEFAULT])
# MinGW32 tests
if test "$on_mingw" = "yes"; then
	AC_CHECK_HEADERS([windows.h winsock2.h ws2tcpip.h],,,
		[AC_INCLUDES_DEFAULT])
fi
# end mingw32 tests

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
AC_CHECK_TYPE(u_char, , 
        [AC_DEFINE([u_char], [unsigned char], [Define to 'unsigned char' if not defined])], [
	AC_INCLUDES_DEFAULT
#ifdef HAVE_SYS_SOCKET_H
#  include <sys/socket.h>
#endif
#ifdef HAVE_WS2TCPIP_H
#  include <ws2tcpip.h>
#endif
])
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
	if test "$on_mingw" = yes; then
		staticexe="-all-static"
		# for static crosscompile, include gdi32 and zlib here.
		if test "`uname`" = "Linux"; then
			LIBS="$LIBS -lgdi32 -lz"
		fi
	fi
fi

ACX_FUNC_MALLOC([dnssectrigger])
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_TYPE_SIGNAL
AC_FUNC_FSEEKO
ACX_SYS_LARGEFILE

# check for OpenSSL
ACX_WITH_SSL
ACX_LIB_SSL
AC_CHECK_HEADERS([openssl/conf.h],,, [AC_INCLUDES_DEFAULT])
AC_CHECK_HEADERS([openssl/engine.h],,, [AC_INCLUDES_DEFAULT])
if test "$staticexe" = "yes"; then
	LIBS="`echo $LIBS | sed -e 's/ -lcrypto//'`"
	LIBS="`echo $LIBS | sed -e 's/^-lcrypto//'`"
	LIBS="$ssldir/lib/libssl.a $ssldir/lib/libcrypto.a $LIBS"
	# check if lz is needed
	AC_MSG_CHECKING([if static libcrypto needs -lz])
	AC_TRY_LINK(, [
		int SSL_library_init(void);
		(void)SSL_library_init();
	], [
		AC_MSG_RESULT(no)
	], [
		AC_MSG_RESULT(yes)
		if test `uname` = "Darwin" -a -f $ssldir/lib/libz.a; then
			LIBS="$LIBS $ssldir/lib/libz.a"
		else
			LIBS="$LIBS -lz"
		fi
	])
else
	LIBS="-lssl $LIBS"
fi
AC_SUBST(ssldir)

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
	AC_CHECK_FUNC([EVP_PKEY_CTX_new_id],,[AC_ERROR(Need newer openssl)])
	AC_CHECK_FUNCS([_beginthreadex])

	AC_MSG_CHECKING([for GetAdaptersAddresses])
	AC_LINK_IFELSE(
	[AC_LANG_SOURCE([[
#include <windows.h>
#include <iphlpapi.h>
int main(void) {
	(void)GetAdaptersAddresses(0, 0, NULL, NULL, NULL);
	return 0;
}
]])]
	, [
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_GETADAPTERSADDRESSES, [1], [If we have this function (windows XP and later)])
	], [
		AC_MSG_RESULT(no)
	])
fi
AC_DEFINE(USE_MINI_EVENT, 1, [Use builtin event system])
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
#include <unistd.h>
])
fi

AC_CHECK_FUNCS([strftime localtime_r fcntl setsid sleep usleep random srandom recvmsg sendmsg writev chflags])

AC_REPLACE_FUNCS(inet_pton)
AC_REPLACE_FUNCS(inet_ntop)
AC_REPLACE_FUNCS(snprintf)
AC_REPLACE_FUNCS(strlcpy)
AC_REPLACE_FUNCS(memmove)

hooks="auto"
AC_ARG_WITH([hooks], AC_HELP_STRING([--with-hooks],
[Set the DHCP change hooks to use, default 'auto', can be 'osx', 'networkmanager', 'netconfig', 'windows' or 'none']),, withval="")
if test -n "$withval"; then
	hooks="$withval"
fi

# hook settings
networkmanager_dispatcher_dir="$exec_prefix/lib/NetworkManager/dispatcher.d"
AC_ARG_WITH([networkmanager-dispatch], AC_HELP_STRING([--with-networkmanager-dispatch],
	[Set the networkmanager dhcp dispatcher dir, default tests {$exec_prefix/lib,$sysconfdir,/etc}/NetworkManager/dispatcher.d]),
	, withval="")
with_nm_dispatch="$withval"
AC_SUBST(networkmanager_dispatcher_dir)

netconfig_dispatcher_dir="$sysconfdir/netconfig.d"
AC_ARG_WITH([netconfig-dispatch], AC_HELP_STRING([--with-netconfig-dispatch],
	[Set the netconfig dhcp dispatcher dir, default tests prefix/etc/netconfig.d and /etc/netconfig.d]),
	, withval="")
with_netconfig_dispatch="$withval"
AC_SUBST(netconfig_dispatcher_dir)

AC_MSG_CHECKING([for DHCP hooks])
if test "$hooks" != "auto"; then
	:
else
	if test "$on_mingw" = "yes"; then
		hooks="windows"
	else
		if test -x "`which nmcli 2>&1`" -o -x "`which nm-tool 2>&1`"; then
		hooks="networkmanager"
		else
			if test "`uname`" = "Darwin"; then
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
fi
AC_MSG_RESULT([$hooks])
AC_SUBST(hooks)

if test "$hooks" = "networkmanager"; then
	AC_MSG_CHECKING([for NetworkManager dispatch])
	if test "$with_nm_dispatch" != ""; then
		networkmanager_dispatcher_dir="$with_nm_dispatch"
	else
		# prefer /usr/lib/NetworkManager over /etc/NetworkManager, useful for packages
		for D in ${exec_prefix}/lib $sysconfdir /etc
		do
			if test -d "$D/NetworkManager/dispatcher.d"; then
				networkmanager_dispatcher_dir="$D/NetworkManager/dispatcher.d"
				break
			fi
		done
	fi
	AC_MSG_RESULT([$networkmanager_dispatcher_dir])
fi
if test "$hooks" = "netconfig"; then
	AC_MSG_CHECKING([for netconfig.d])
	if test "$with_netconfig_dispatch" != ""; then
		netconfig_dispatcher_dir="$with_netconfig_dispatch"
	else
		if test -d "$netconfig_dispatcher_dir" ; then
			:
		else if test -d /etc/netconfig.d; then
			netconfig_dispatcher_dir="/etc/netconfig.d"
			fi
		fi
	fi
	AC_MSG_RESULT([$netconfig_dispatcher_dir])
fi
if test "$hooks" = "osx"; then
	AC_DEFINE([HOOKS_OSX], 1, [we are on OSX, use that os specific funcs])
fi
if test "$hooks" = "none"; then
	AC_MSG_WARN([have no DHCP hooks, cannot detect network changes])
fi

gui="auto"
AC_ARG_WITH([gui], AC_HELP_STRING([--with-gui],
[Set the user interface style to use, default 'auto', can be 'cocoa' (on OSX), 'windows' or 'gtk']),, withval="")
if test -n "$withval" -a "$withval" != "yes"; then
	gui="$withval"
fi
AC_MSG_CHECKING([for gui])
if test "$gui" != "auto"; then
	:
else
	if test "`uname`" = "Darwin"; then
		gui="cocoa"
	else
		if test "$on_mingw" = yes; then
			gui="windows"
		else
			gui="gtk"
		fi
	fi
fi
AC_MSG_RESULT([$gui])
AC_SUBST(gui)

if test "$gui" = "gtk"; then
	# GTK
	GTK_CFLAGS=`pkg-config --cflags gtk+-2.0`
	GTK_LIBS=`pkg-config --libs gtk+-2.0`
	if test -z "$GTK_LIBS"; then
		AC_MSG_ERROR([No gtk+-2.0 detected, please install glib-dev, gtk2-dev])
	fi
	AC_SUBST(GTK_CFLAGS)
	AC_SUBST(GTK_LIBS)

	AC_MSG_CHECKING([for libappindicator])
	AC_ARG_ENABLE(appindicator, AS_HELP_STRING([--enable-appindicator[=@<:@no/auto/yes@:>@]],[Build support for application indicators (for Ubuntu Unity)]), [enable_appindicator=$enableval], [enable_appindicator="auto"])
	if test x$enable_appindicator = xauto ; then
		if pkg-config --exists appindicator-0.1; then
			enable_appindicator="yes"
		else
			enable_appindicator="no"
		fi
	fi
	if test x$enable_appindicator = xyes ; then
		# replace since GTK is included in the appindicator flags
		GTK_CFLAGS=`pkg-config --cflags appindicator-0.1`
		GTK_LIBS=`pkg-config --libs appindicator-0.1`
		if test -z "$GTK_LIBS"; then
			AC_MSG_ERROR([appindicator-0.1 is not installed, need libappindicator-dev])
		fi
		AC_DEFINE(HAVE_APP_INDICATOR, 1, [Have AppIndicator (Ubuntu Unity)])
		APP_INDICATOR="yes"
		AC_SUBST(APP_INDICATOR)
		AC_MSG_RESULT([yes])
		BAKLIBS="$LIBS"
		LIBS="$LIBS $GTK_LIBS"
		AC_CHECK_FUNCS([app_indicator_set_icon_full])
		LIBS="$BAKLIBS"
	else
		AC_MSG_RESULT([no])
	fi

	# check for missing -lgthread-2.0 in the GTK_LIBS string.
	case "$GTK_LIBS" in *-lgthread* ) ;;
	*) AC_CHECK_LIB(gthread-2.0, g_thread_init, [GTK_LIBS="$GTK_LIBS -lgthread-2.0"]) esac

	if test "$on_mingw" = "no"; then
		xdg_autostart_dir="$sysconfdir/xdg/autostart"
		AC_ARG_WITH([xdg-autostart], AC_HELP_STRING([--with-xdg-autostart],
			[Set the GNOME autostart dir, default tests prefix/etc/xdg/autostart and /etc/xdg/autostart]),
			, withval="")
		with_xdg_autostart="$withval"
		AC_SUBST(xdg_autostart_dir)
		AC_MSG_CHECKING([for autostart dir])
		if test "$with_xdg_autostart" != ""; then
			xdg_autostart_dir="$with_xdg_autostart"
		else
			if test -d "$xdg_autostart_dir" ; then
				:
			else if test -d /etc/xdg/autostart; then
				xdg_autostart_dir="/etc/xdg/autostart"
				fi
			fi
		fi
		AC_MSG_RESULT([$xdg_autostart_dir])
	fi
fi

login_command="auto"
login_location="auto"
AC_SUBST(login_command)
AC_SUBST(login_location)
AC_ARG_WITH([login-command], AC_HELP_STRING([--with-login-command],
[Set the command to start login, a web browser, default 'auto']),, withval="")
if test -n "$withval" -a "$withval" != "yes"; then
	login_command="$withval"
fi
AC_ARG_WITH([login-location], AC_HELP_STRING([--with-login-location],
[Set the url location to login, default 'auto']),, withval="")
if test -n "$withval" -a "$withval" != "yes"; then
	login_location="$withval"
fi
if test "$login_location" = "auto"; then
	login_location="http://www.nlnetlabs.nl/projects/dnssec-trigger"
fi
AC_MSG_CHECKING([for web browser])
if test "$login_command" = "auto"; then
  if test "$USE_WINSOCK" = 1; then
	login_command="open"
  else
    if test "`uname`" = "Darwin"; then
	login_command="open"
    else
	clist="xdg-open sensible-browser gnome-open x-www-browser firefox konqueror chrome google-chrome"
	login_command=""
	for i in $clist; do
		if test -x "`which $i 2>&1`"; then
			login_command="$i"
			break;
		fi
	done
    fi
  fi
fi
AC_MSG_RESULT([$login_command])
AC_DEFINE_UNQUOTED([LOGIN_COMMAND], ["$login_command"], [web browser to open login url])
AC_DEFINE_UNQUOTED([LOGIN_LOCATION], ["$login_location"], [login url to open at hot spots])

AC_ARG_WITH([check-updates], AC_HELP_STRING([--with-check-updates=yesno],
[Set default value for check-updates config option]),, withval="")
if test -n "$withval"; then
	check_updates="$withval"
else
	# enable on WIN, OSX, not on unixes (use ports, package manager there).
	if test "$USE_WINSOCK" = 1; then
		check_updates="yes"
	else
		if test "`uname`" = "Darwin"; then
			check_updates="yes"
		else
			check_updates="no"
		fi
	fi
fi
AC_DEFINE_UNQUOTED([CHECK_UPDATES], ["$check_updates"], [default value for check-updates config option])
AC_SUBST(check_updates)

AC_ARG_WITH([keydir], AC_HELP_STRING([--with-keydir=path],
[Set the directory where ssl key files are kept, read by daemon and other tools, default prefix/etc]),, withval="")
keydir=`eval echo "$sysconfdir"`
if test -n "$withval"; then
	keydir="$withval"
fi
ACX_ESCAPE_BACKSLASH($keydir, keydir_esc)
AC_DEFINE_UNQUOTED([KEYDIR], ["$keydir_esc"], [directory with ssl key files for dnssec-trigger])
AC_SUBST(keydir)

libexec_store_dir=`eval echo "$libexecdir"`
ACX_ESCAPE_BACKSLASH($libexec_store_dir, libexec_store_dir_esc)
AC_DEFINE_UNQUOTED([LIBEXEC_DIR], ["$libexec_store_dir_esc"], [directory with scripts for dnssec-trigger])

AC_ARG_WITH([uidir], AC_HELP_STRING([--with-uidir=path],
[Set the directory where ui files (icon,xml) are kept, default prefix/share/dnssec-trigger]),, withval="")
uidir=`eval echo "$datadir/dnssec-trigger"`
if test -n "$withval"; then
	uidir="$withval"
fi
ACX_ESCAPE_BACKSLASH($uidir, uidir2)
uidir=`eval echo $uidir2`
ACX_ESCAPE_BACKSLASH($uidir, uidir_esc)
AC_DEFINE_UNQUOTED([UIDIR], ["$uidir_esc"], [directory with UI xml and png for dnssec-trigger])
AC_SUBST(uidir)

AC_ARG_WITH([configfile], AC_HELP_STRING([--with-configfile=path],
[set the configfile to use, default keydir/dnssec-trigger.conf]),, withval="")
configfile="$keydir/dnssec-trigger.conf"
if test -n "$withval"; then
	configfile="$withval"
fi
ACX_ESCAPE_BACKSLASH($configfile, configfile_esc)
AC_DEFINE_UNQUOTED([CONFIGFILE], ["$configfile_esc"], [default config file name for dnssec-trigger])
AC_SUBST(configfile)

AC_ARG_WITH([pidfile], AC_HELP_STRING([--with-pidfile=path],
[set the pidfile to use, default /var/run/dnssec-trigger.pid]),, withval="")
pidfile="/var/run/dnssec-trigger.pid"
if test -n "$withval"; then
	pidfile="$withval"
fi
ACX_ESCAPE_BACKSLASH($pidfile, pidfile_esc)
AC_DEFINE_UNQUOTED([PIDFILE], ["$pidfile_esc"], [default pidfile name for dnssec-trigger])
AC_SUBST(pidfile)

AC_ARG_WITH([python], AC_HELP_STRING([--with-python=path],
[set the path to Python interpreter to use for Python scripts, defaults /usr/bin/python]),, withval="")
PYTHON="/usr/bin/python"
if test -n "$withval"; then
	PYTHON="$withval"
fi
ACX_ESCAPE_BACKSLASH($PYTHON, python_esc)
AC_DEFINE_UNQUOTED([PYTHON], ["$python_esc"], [default Python interpreter path for all Python scripts])
AC_SUBST(PYTHON)

AC_ARG_WITH([unbound-control], AC_HELP_STRING([--with-unbound-control=path],
[set the unbound-control to use, default what configure finds in its path]),, withval="")
AC_MSG_CHECKING([for unbound-control])
if test "$on_mingw" = "yes"; then
	unbound_control_path='"C:\Program Files\Unbound\unbound-control.exe"'
else
	unbound_control_path="`which unbound-control 2>&1`"
fi
if test -n "$withval"; then
	unbound_control_path="$withval"
fi
if test "$on_mingw" = "yes" -o -n "$withval"; then
	AC_MSG_RESULT($unbound_control_path)
else
	if test -x "$unbound_control_path"; then
		AC_MSG_RESULT($unbound_control_path)
	else
		AC_MSG_RESULT([not found: try "unbound-control" in runtime PATH])
		unbound_control_path="unbound-control"
	fi
fi
ACX_ESCAPE_BACKSLASH($unbound_control_path, unbound_control_esc)
unbound_control_esc="`echo $unbound_control_esc | sed -e 's/\\"/\\\\"/g'`"
AC_DEFINE_UNQUOTED([UNBOUND_CONTROL], ["$unbound_control_esc"], [unbound-control to call])
AC_SUBST(unbound_control_path)

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
	AC_CHECK_LIB(ldns, ldns_buffer_new,,[AC_MSG_ERROR([please install ldns-devel])])
	])

# add option to disable the evil rpath
ACX_ARG_RPATH
AC_SUBST(RUNTIME_PATH)

AC_DEFINE_UNQUOTED([MAXSYSLOGMSGLEN], [10240], [Define to the maximum message length to pass to syslog.])
AC_DEFINE_UNQUOTED([DNS_PORT], [53], [DNS port number])

NMDISPATCHERCOMMAND="update"
AC_ARG_WITH([forward-zones-support], AC_HELP_STRING([--with-forward-zones-support],
[Set whether to enable forward zones support. Beware, it is only POSIX OSes feature]),, withval="")
# we don't provide this functionality for NON-POSIX OSes e.g. windows
# for enabling this functionality on NON-POSIX systems some functions must be rewritten with target system's API
if test "$USE_WINSOCK" != 1; then
	if test "$withval" = "yes"; then
		FWD_ZONES_SUPPORT=yes
		AC_SUBST(FWD_ZONES_SUPPORT)
        AC_DEFINE(FWD_ZONES_SUPPORT, 1, [Support forward zones])
		NMDISPATCHERCOMMAND="update_all"
	fi
fi
AC_SUBST(NMDISPATCHERCOMMAND)

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

#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
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
]
AHX_CONFIG_INET_PTON(dnssectrigger)
AHX_CONFIG_INET_NTOP(dnssectrigger)
AHX_CONFIG_MEMMOVE(dnssectrigger)
AHX_CONFIG_STRLCPY(dnssectrigger)
AHX_CONFIG_SNPRINTF(dnssectrigger)
AHX_CONFIG_W32_SLEEP
AHX_CONFIG_W32_USLEEP
AHX_CONFIG_W32_RANDOM
AHX_CONFIG_W32_SRANDOM
AHX_CONFIG_W32_FD_SET_T
)

DATE=`date +%x`
AC_SUBST(DATE)
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT

if test "$hooks" = "none"; then
	echo "WARNING NO DHCP HOOKS DETECTED CANNOT SETUP TRIGGER"
fi
[
echo "configure completed with $hooks hooks and $gui gui, now you can"
echo "	make | make all		: compile the code"
echo "	make install 		: install files"
echo "	make uninstall 		: uninstall files"
]

