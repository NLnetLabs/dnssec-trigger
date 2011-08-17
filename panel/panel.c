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

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-trigger-panel [options]\n");
	printf(" -c config      use configfile, default is %s\n", CONFIGFILE);
	printf(" -d		run from current directory (UIDIR=panel/)\n");
	printf(" -h             this help\n");
}

/** sighandler.  Since we must have one
 *  * @param sig: signal number.
 *   * @return signal handler return type (void or int).
 *    */
static RETSIGTYPE record_sigh(int sig)
{
	switch(sig) {
	case SIGHUP:
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
	feed = (struct feed*)calloc(1, sizeof(*feed));
	if(!feed) fatal_exit("out of memory");
	feed->lock = g_mutex_new();
	thr = g_thread_create(&feed_thread, cfg, FALSE, &err);
	if(!thr) fatal_exit("cannot create thread: %s", err->message);
}

void on_quit_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	gtk_main_quit();
}

gboolean
on_result_dialog_delete_event(GtkWidget* ATTR_UNUSED(widget),
	GdkEvent* ATTR_UNUSED(event), gpointer ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(result_window));
	attach_send_insecure(0);
	return TRUE; /* stop other handlers, do not destroy the window */
}

void 
on_result_ok_button_clicked(GtkButton* ATTR_UNUSED(button),
	gpointer ATTR_UNUSED(user_data)) 
{
	gtk_widget_hide(GTK_WIDGET(result_window));
}

void on_reprobe_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	attach_send_reprobe();
}

void on_proberesults_activate(GtkMenuItem* ATTR_UNUSED(menuitem),
	gpointer ATTR_UNUSED(user_data))
{
	GtkTextBuffer *buffer;
	struct strlist* p;
	GtkTextIter end;

	/* fetch results */
	buffer = gtk_text_view_get_buffer(result_textview);
	gtk_text_buffer_set_text(buffer, "results from probe:\n", -1);
	g_mutex_lock(feed->lock);
	if(!feed->connected) {
		gtk_text_buffer_get_end_iter(buffer, &end);
		gtk_text_buffer_insert(buffer, &end, "error: ", -1);
		gtk_text_buffer_get_end_iter(buffer, &end);
		gtk_text_buffer_insert(buffer, &end, feed->connect_reason, -1);
		gtk_text_buffer_get_end_iter(buffer, &end);
		gtk_text_buffer_insert(buffer, &end, "\n", -1);
	}
	/* indent for strings is adjusted to be able to judge line length */
	for(p=feed->results; p; p=p->next) {
		if(!p->next) {
			/* last line */
			gtk_text_buffer_get_end_iter(buffer, &end);
			gtk_text_buffer_insert(buffer, &end, "\n", -1);
			gtk_text_buffer_get_end_iter(buffer, &end);
			if(strstr(p->str, "cache"))
				gtk_text_buffer_insert(buffer, &end, 
		"DNSSEC results fetched from (DHCP) cache(s)\n", -1);
			else if(strstr(p->str, "auth"))
				gtk_text_buffer_insert(buffer, &end, 
		"DNSSEC results fetched direct from authorities\n", -1);
			else if(strstr(p->str, "disconnected"))
				gtk_text_buffer_insert(buffer, &end, 
		"The network seems to be disconnected. A local cache of DNS\n"
		"results is used, but no queries are made.\n", -1);
			else if(strstr(p->str, "dark") && !strstr(p->str,
				"insecure"))
				gtk_text_buffer_insert(buffer, &end, 
		"A local cache of DNS results is used but no queries\n"
		"are made, because DNSSEC is intercepted on this network.\n"
		"(DNS is stopped)\n", -1);
			else gtk_text_buffer_insert(buffer, &end, 
		"DNS queries are sent to INSECURE servers.\n"
		"Please, be careful out there.\n", -1);
		} else {
			gtk_text_buffer_get_end_iter(buffer, &end);
			gtk_text_buffer_insert(buffer, &end, p->str, -1);
			gtk_text_buffer_get_end_iter(buffer, &end);
			gtk_text_buffer_insert(buffer, &end, "\n", -1);
		}
	}
	g_mutex_unlock(feed->lock);

	/* show them */
	gtk_widget_show(GTK_WIDGET(result_window));
}

void 
on_statusicon_popup_menu(GtkStatusIcon* ATTR_UNUSED(status_icon),
	guint button, guint activate_time,
	gpointer ATTR_UNUSED(user_data))
{
	gtk_menu_popup(GTK_MENU(statusmenu), NULL, NULL,
		&gtk_status_icon_position_menu, status_icon,
		button, activate_time);
}

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

gboolean
on_unsafe_dialog_delete_event(GtkWidget* ATTR_UNUSED(widget),
	GdkEvent* ATTR_UNUSED(event), gpointer ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	unsafe_asked = 1;
	attach_send_insecure(0);
	return TRUE; /* stop other handlers, do not destroy dialog */
}

void on_disconnect_button_clicked(GtkButton *ATTR_UNUSED(button), gpointer
	ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(unsafe_dialog));
	unsafe_asked = 1;
	attach_send_insecure(0);
}

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

void panel_alert_state(int last_insecure, int now_insecure, int dark,
        int cache, int ATTR_UNUSED(auth), int disconn)
{
	const char* tt;
	/* handle state changes */
	if(now_insecure)
		tt = "DNS DANGER";
	else if(dark)
		tt = "DNS stopped";
	else if(cache)
		tt = "DNSSEC via cache";
	else if(disconn)
		tt = "network disconnected";
	else	tt = "DNSSEC via authorities";
	gtk_status_icon_set_tooltip_text(status_icon, tt);
	if(!dark)
		unsafe_asked = 0;
	if(!last_insecure && now_insecure) {
		panel_alert_danger();
	} else if(last_insecure && !now_insecure) {
		panel_alert_safe();
	}
	if(!now_insecure && dark && !unsafe_asked) {
		present_unsafe_dialog();
	}

}

static GdkPixbuf* load_icon(const char* icon, int debug)
{
	char file[1024];
	GError* error = NULL;
	if(debug) snprintf(file, sizeof(file), "panel/%s", icon);
	else snprintf(file, sizeof(file), "%s/%s", UIDIR, icon);
	return gdk_pixbuf_new_from_file_at_size(file, 64, 64, &error);
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
	attach_stop(); /* stop the other thread */
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
#endif
	g_thread_init(NULL);
	gdk_threads_init();
	gtk_init(&argc, &argv);
	log_ident_set("dnssec-trigger-panel");
	log_init(NULL, 0, NULL);
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
