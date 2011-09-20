/*
 * panel/panel.c - implementation of dnssec-trigger panel
 *
 * Copyright (c) 2011, NLnet Labs. All rights reserved.
 *
 * This software is open source.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 * 
 * Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 * 
 * Neither the name of the NLNET LABS nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * \file
 * Implementation of dnssec-trigger panel.
 */

#include "config.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <signal.h>
#include <gtk/gtk.h>
#include <glib.h>

#include "riggerd/log.h"
#include "riggerd/cfg.h"
#include "panel/attach.h"

static GtkTextView* result_textview;
static GtkStatusIcon* status_icon;
static GtkWidget* result_window;
static GtkWidget* unsafe_dialog;
static GdkPixbuf* normal_icon;
static GdkPixbuf* alert_icon;
static GtkMenu* statusmenu;
/** if we have asked about disconnect or insecure */
static int unsafe_asked = 0;

static void feed_alert(struct alert_arg* a);

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-trigger-panel [options]\n");
	printf(" -c config      use configfile, default is %s\n", CONFIGFILE);
	printf(" -d		run from current directory (UIDIR=panel/)\n");
	printf(" -h             this help\n");
}

#ifdef USE_WINSOCK
/**
 * Obtain registry string (if it exists).
 * @param key: key string
 * @param name: name of value to fetch.
 * @return malloced string with the result or NULL if it did not
 * exist on an error (logged) was encountered.
 */
static char*
lookup_reg_str(const char* key, const char* name)
{
	HKEY hk = NULL;
	DWORD type = 0;
	BYTE buf[1024];
	DWORD len = (DWORD)sizeof(buf);
	LONG ret;
	char* result = NULL;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk);
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* key does not exist */
	else if(ret != ERROR_SUCCESS) {
		log_err("RegOpenKeyEx failed");
		return NULL;
	}
	ret = RegQueryValueEx(hk, (LPCTSTR)name, 0, &type, buf, &len);
	if(RegCloseKey(hk))
		log_err("RegCloseKey");
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* name does not exist */
	else if(ret != ERROR_SUCCESS) {
		log_err("RegQueryValueEx failed");
		return NULL;
	}
	if(type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ) {
		buf[sizeof(buf)-1] = 0;
		buf[sizeof(buf)-2] = 0; /* for multi_sz */
		result = strdup((char*)buf);
		if(!result) log_err("out of memory");
	}
	return result;
}
#endif /* USE_WINSOCK */

/** sighandler.  Since we must have one
 *  * @param sig: signal number.
 *   * @return signal handler return type (void or int).
 *    */
static RETSIGTYPE record_sigh(int sig)
{
	switch(sig) {
#ifdef SIGHUP
	case SIGHUP:
#endif
	case SIGTERM:
#ifdef SIGQUIT
	case SIGQUIT:
#endif
#ifdef SIGBREAK
	case SIGBREAK:
#endif
	case SIGINT:
		if(verbosity >= 2) printf("killed by signal %d\n", (int)sig);
		gtk_main_quit();
	break;
#ifdef SIGPIPE
	case SIGPIPE:
	break;
#endif
	default:
		if(verbosity >= 2) printf("ignoring signal %d", sig);
	}
}

/** the lock for the feed structure */
static GMutex* feed_lock = NULL;

/** callback that locks feedlock */
static void lock_feed_lock(void)
{
	g_mutex_lock(feed_lock);
}

/** callback that unlocks feedlock */
static void unlock_feed_lock(void)
{
	g_mutex_unlock(feed_lock);
}

/** callback that quits the program */
static void feed_quit(void)
{
	/* we are in the feed thread */
	gdk_threads_enter();
	gtk_main_quit();
	gdk_threads_leave();
}

gpointer feed_thread(gpointer data)
{
	attach_start((struct cfg*)data);
	return NULL;
}

/** spawn the feed thread */
static void
spawn_feed(struct cfg* cfg)
{
	GError* err=NULL;
	GThread* thr;
	attach_create();
	feed_lock = g_mutex_new();
	feed->lock = &lock_feed_lock;
	feed->unlock = &unlock_feed_lock;
	feed->quit = &feed_quit;
	feed->alert = &feed_alert;

	thr = g_thread_create(&feed_thread, cfg, FALSE, &err);
	if(!thr) fatal_exit("cannot create thread: %s", err->message);
}

/* the G_MODULE_EXPORT makes the routine exported on windows for dynamic
 * linking to gtk.  On linux the -export-dynamic flag to the linker does that.
 */
G_MODULE_EXPORT
void on_quit_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	gtk_main_quit();
}

G_MODULE_EXPORT
gboolean
on_result_dialog_delete_event(GtkWidget* ATTR_UNUSED(widget),
	GdkEvent* ATTR_UNUSED(event), gpointer ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(result_window));
	attach_send_insecure(0);
	return TRUE; /* stop other handlers, do not destroy the window */
}

G_MODULE_EXPORT
void 
on_result_ok_button_clicked(GtkButton* ATTR_UNUSED(button),
	gpointer ATTR_UNUSED(user_data)) 
{
	gtk_widget_hide(GTK_WIDGET(result_window));
}

G_MODULE_EXPORT
void on_reprobe_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	attach_send_reprobe();
}

G_MODULE_EXPORT
void on_proberesults_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	char buf[102400];
	GtkTextBuffer *buffer;

	/* fetch results */
	fetch_proberesults(buf, sizeof(buf), "\n");
	buffer = gtk_text_view_get_buffer(result_textview);
	gtk_text_buffer_set_text(buffer, buf, -1);

	/* show them */
	gtk_widget_show(GTK_WIDGET(result_window));
}

G_MODULE_EXPORT
void 
on_statusicon_popup_menu(GtkStatusIcon* ATTR_UNUSED(status_icon),
	guint button, guint activate_time,
	gpointer ATTR_UNUSED(user_data))
{
#ifndef UB_ON_WINDOWS
	gtk_menu_popup(GTK_MENU(statusmenu), NULL, NULL,
		&gtk_status_icon_position_menu, status_icon,
		button, activate_time);
#else
	/* on windows, the statusicon is not good to center on, use the
	   mouse position */
	gtk_menu_popup(GTK_MENU(statusmenu), NULL, NULL,
		NULL, NULL, button, activate_time);
#endif
}

G_MODULE_EXPORT
void 
on_statusicon_activate(GtkStatusIcon* ATTR_UNUSED(status_icon),
	gpointer ATTR_UNUSED(user_data))
{
	/* no window to show and hide by default */
	if(0) {
		/* hide and show the window when the status icon is clicked */
		if(gtk_widget_get_visible(result_window) &&
			gtk_window_has_toplevel_focus(GTK_WINDOW(
				result_window))) {
			gtk_widget_hide(GTK_WIDGET(result_window));
		} else {
			gtk_widget_show(GTK_WIDGET(result_window));
			gtk_window_deiconify(GTK_WINDOW(result_window));
			gtk_window_present(GTK_WINDOW(result_window));
		}
	}
}

G_MODULE_EXPORT
gboolean
on_unsafe_dialog_delete_event(GtkWidget* ATTR_UNUSED(widget),
	GdkEvent* ATTR_UNUSED(event), gpointer ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	unsafe_asked = 1;
	attach_send_insecure(0);
	return TRUE; /* stop other handlers, do not destroy dialog */
}

G_MODULE_EXPORT
void on_disconnect_button_clicked(GtkButton *ATTR_UNUSED(button), gpointer
	ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	unsafe_asked = 1;
	attach_send_insecure(0);
}

G_MODULE_EXPORT
void on_insecure_button_clicked(GtkButton *ATTR_UNUSED(button), gpointer
	ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	unsafe_asked = 1;
	attach_send_insecure(1);
}

void present_unsafe_dialog(void)
{
	gtk_window_set_urgency_hint(GTK_WINDOW(unsafe_dialog), TRUE);
	gtk_widget_show(GTK_WIDGET(unsafe_dialog));
	gtk_window_deiconify(GTK_WINDOW(unsafe_dialog));
	gtk_window_present(GTK_WINDOW(unsafe_dialog));
}

void panel_alert_danger(void)
{
	gtk_status_icon_set_from_pixbuf(status_icon, alert_icon);
}

void panel_alert_safe(void)
{
	gtk_status_icon_set_from_pixbuf(status_icon, normal_icon);
}

/** tell panel to update itself with new state information */
void panel_alert_state(struct alert_arg* a)
{
	/* handle state changes */
	gtk_status_icon_set_tooltip_text(status_icon, state_tooltip(a));
	process_state(a, &unsafe_asked, &panel_alert_danger, &panel_alert_safe,
		&present_unsafe_dialog);
}

#ifdef USE_WINSOCK
/* the parameters for the panel alert state */
static GMutex* call_lock = NULL;
static struct alert_arg cp_arg;

gboolean call_alert(gpointer ATTR_UNUSED(arg))
{
	/* get params */
	struct alert_arg a;
	g_mutex_lock(call_lock);
	a = cp_arg;
	g_mutex_unlock(call_lock);
	panel_alert_state(&a);
	/* only call once, remove call_alert from the glib mainloop */
	return FALSE;
}

/* schedule a call to the panel alert state from the main thread */
void call_panel_alert_state(struct alert_arg* a)
{
	if(!call_lock) {
		call_lock = g_mutex_new();
	}
	/* store parameters */
	g_mutex_lock(call_lock);
	cp_arg = *a;
	g_mutex_unlock(call_lock);
	/* the  call_alert function will run from the main thread, because
	 * GTK+ is not threadsafe on windows */
	g_idle_add(&call_alert, NULL);
}
#endif /* USE_WINSOCK */

/** callback that alerts panel of new status */
static void feed_alert(struct alert_arg* a)
{
	gdk_threads_enter();
#ifndef USE_WINSOCK
	panel_alert_state(a);
#else
	/* call the above function from the main thread, in case the system
 	 * is not threadsafe (windows) */
	call_panel_alert_state(a);
#endif
	gdk_threads_leave();
}

static GdkPixbuf* load_icon(const char* icon, int debug)
{
	char file[1024];
	GError* error = NULL;
	if(debug) snprintf(file, sizeof(file), "panel/%s", icon);
	else snprintf(file, sizeof(file), "%s/%s", UIDIR, icon);
#ifdef HOOKS_OSX
	/* smaller icons on OSX because of its tray icon size issues */
	return gdk_pixbuf_new_from_file_at_size(file, 18, 18, &error);
#else
	return gdk_pixbuf_new_from_file_at_size(file, 64, 64, &error);
#endif
}

static void make_tray_icon(void)
{
	status_icon = gtk_status_icon_new_from_pixbuf(normal_icon);
	g_signal_connect(G_OBJECT(status_icon), "activate",
		G_CALLBACK(on_statusicon_activate), NULL);
	g_signal_connect(G_OBJECT(status_icon), "popup-menu",
		G_CALLBACK(on_statusicon_popup_menu), NULL);
	gtk_status_icon_set_tooltip_text(status_icon, "dnssec-trigger");
	gtk_status_icon_set_visible(status_icon, TRUE);
}

/* build UI from xml */
static GtkBuilder* load_ui_xml(int debug)
{
	const char* file;
	GtkBuilder* builder = gtk_builder_new();
	/* read xml with gui */
	if(debug) file = "panel/pui.xml";
	else	file = UIDIR"/pui.xml";
	gtk_builder_add_from_file(builder, file, NULL);
	return builder;
}

/** initialize the gui */
static void
init_gui(int debug)
{
	GtkBuilder* builder = load_ui_xml(debug);

	/* grab important widgets into global variables */
	result_window = GTK_WIDGET(gtk_builder_get_object(builder,
		"result_dialog"));
	if(!result_window) {
		printf("could not load the UI (-d to run from build dir)\n");
		exit(1);
	}
	result_textview = GTK_TEXT_VIEW(gtk_builder_get_object(builder,
		"result_textview"));
	unsafe_dialog = GTK_WIDGET(gtk_builder_get_object(builder,
		"unsafe_dialog"));
	statusmenu = GTK_MENU(gtk_builder_get_object(builder, "statusmenu"));
	/* we need to incref otherwise we may lose the reference */
	g_object_ref(G_OBJECT(statusmenu));
	gtk_widget_hide(GTK_WIDGET(result_window));
	g_object_ref(G_OBJECT(result_window));
	g_object_ref(G_OBJECT(unsafe_dialog));

	/* no more need for the builder */
	gtk_builder_connect_signals(builder, NULL);          
	g_object_unref(G_OBJECT(builder));

	normal_icon = load_icon("status-icon.png", debug);
	alert_icon = load_icon("status-icon-alert.png", debug);
	/* create the status icon in the system tray */
	make_tray_icon();
	/* loaded the icons, also good for our windows */
	gtk_window_set_icon(GTK_WINDOW(result_window), normal_icon);
	gtk_window_set_icon(GTK_WINDOW(unsafe_dialog), alert_icon);
}

/** remove GUI stuff on exit */
static void
stop_gui(void)
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	gtk_widget_hide(GTK_WIDGET(result_window));
	gtk_widget_hide(GTK_WIDGET(statusmenu));
	gtk_status_icon_set_visible(status_icon, FALSE);
}

/** do main work */
static void
do_main_work(const char* cfgfile, int debug)
{
	struct cfg* cfg = cfg_create(cfgfile);
	if(!cfg) fatal_exit("cannot read config %s", cfgfile);

        /* start signal handlers */
        if( signal(SIGTERM, record_sigh) == SIG_ERR ||
#ifdef SIGQUIT
                signal(SIGQUIT, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGBREAK
                signal(SIGBREAK, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGHUP
                signal(SIGHUP, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGPIPE
                signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
#endif
                signal(SIGINT, record_sigh) == SIG_ERR
	)
                printf("install sighandler failed: %s\n", strerror(errno));
        /* start */
	init_gui(debug); /* initializes the GUI objects */
	spawn_feed(cfg); /* starts connecting to the server in other thread */

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	stop_gui();
	attach_stop(); /* stop the other thread */
#ifdef USE_WINSOCK
	if(call_lock) g_mutex_free(call_lock);
#endif
	if(feed_lock) g_mutex_free(feed_lock);
}


/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/**
 * main program. Set options given commandline arguments.
 * @param argc: number of commandline arguments.
 * @param argv: array of commandline arguments.
 * @return: exit status of the program.
 */
int main(int argc, char *argv[])
{
        int c;
	const char* cfgfile = CONFIGFILE;
	int debug = 0;
#ifdef USE_WINSOCK
	int r;
	WSADATA wsa_data;
	if((r = WSAStartup(MAKEWORD(2,2), &wsa_data)) != 0)
		fatal_exit("WSAStartup failed: %s", wsa_strerror(r));
	/* setup THEME */
	/* if the theme uses an engine dll, set GTK_PATH to the directory
	 * that contains 2.x.0/engines/libblabla.dll */
#endif
	log_ident_set("dnssec-trigger-panel");
	log_init(NULL, 0, NULL);
#ifdef USE_WINSOCK
	cfgfile = lookup_reg_str("Software\\DnssecTrigger", "ConfigFile");
	if(!cfgfile) cfgfile = CONFIGFILE;
#endif
        while( (c=getopt(argc, argv, "c:dh")) != -1) {
                switch(c) {
                default:
		case 'd':
			debug = 1;
			break;
		case 'c':
			cfgfile = optarg;
			break;
                case 'h':
                        usage();
                        return 1;
                }
        }
        argc -= optind;
        argv += optind;
#ifdef USE_WINSOCK
	if(debug)
		putenv("GTK2_RC_FILES=./winrc/gtkrc");
	else {
		char* inst;
		char* gtkrc = lookup_reg_str("Software\\DnssecTrigger", "Gtkrc");
		if(gtkrc) {
			char buf[1024];
			snprintf(buf, sizeof(buf), "GTK2_RC_FILES=%s", gtkrc);
			putenv(buf);
			free(gtkrc);
		} else putenv("GTK2_RC_FILES="UIDIR"\\gtkrc");
		/* chdir to the uidir, in programfiles\dnssectrigger, so that
		 * the current dir has dlls and lots of rc and modules */
		inst = lookup_reg_str("Software\\DnssecTrigger",
			"InstallLocation");
		if(inst) {
			if(chdir(inst) == -1)
				log_err("cannot chdir(%s) %s",
					inst, strerror(errno));
			free(inst);
		} else {
			if(chdir(UIDIR) == -1)
				log_err("cannot chdir(%s) %s",
					UIDIR, strerror(errno));
		}
		putenv("GDK_PIXBUF_MODULEDIR=.");
		putenv("GDK_PIXBUF_MODULE_FILE=loaders.cache");
		putenv("PANGO_RC_FILE=pangorc");
	}
#endif

       	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(&argc, &argv);

 	if(argc != 0) {
                usage();
                return 1;
	}

        ERR_load_crypto_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	(void)SSL_library_init();

	/* show user interface */
	do_main_work(cfgfile, debug);
#ifdef USE_WINSOCK
	WSACleanup();
#endif
	return 0;
}
