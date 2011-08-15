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
static GdkPixbuf* normal_icon;
static GdkPixbuf* alert_icon;
static GtkMenu* statusmenu;

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-trigger-panel [options]\n");
	printf(" -c config      use configfile, default is %s\n", CONFIGFILE);
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

void 
on_window_destroy(GtkObject* ATTR_UNUSED(object),
	gpointer ATTR_UNUSED(user_data))
{
	gtk_widget_hide(GTK_WIDGET(result_window));
}

void 
on_result_ok_button_clicked(GtkButton* ATTR_UNUSED(button),
	gpointer ATTR_UNUSED(user_data)) 
{
	gtk_widget_hide(GTK_WIDGET(result_window));
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
	for(p=feed->results; p; p=p->next) {
		if(!p->next) {
			/* last line */
			gtk_text_buffer_get_end_iter(buffer, &end);
			gtk_text_buffer_insert(buffer, &end, "\n", -1);
			gtk_text_buffer_get_end_iter(buffer, &end);
			if(strstr(p->str, "cache"))
				gtk_text_buffer_insert(buffer, &end, 
					"DNSSEC results fetched from (DHCP) "
					"cache(s)\n", -1);
			else if(strstr(p->str, "auth"))
				gtk_text_buffer_insert(buffer, &end, 
					"DNSSEC results fetched direct from "
					"authorities\n", -1);
			else if(strstr(p->str, "dark") && !strstr(p->str,
				"insecure"))
				gtk_text_buffer_insert(buffer, &end, 
		"A local cache of DNS results is used but no queries\n"
		"are made, because DNSSEC is intercepted on this network.\n"
		"(DNS is stopped)\n", -1);
			else gtk_text_buffer_insert(buffer, &end, 
				"DNS queries are sent to INSECURE servers.\n"
				"Please, be careful there.\n", -1);
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

void panel_alert_danger(void)
{
	gtk_status_icon_set_from_pixbuf(status_icon, alert_icon);
}

void panel_alert_safe(void)
{
	gtk_status_icon_set_from_pixbuf(status_icon, normal_icon);
}

void panel_alert_state(int last_insecure, int now_insecure, int dark,
        int cache, int ATTR_UNUSED(auth))
{
	const char* tt;
	/* handle state changes */
	if(now_insecure)
		tt = "DNS DANGER";
	else if(dark)
		tt = "DNS stopped";
	else if(cache)
		tt = "DNSSEC via cache";
	else	tt = "DNSSEC via authorities";
	gtk_status_icon_set_tooltip(status_icon, tt);
	if(last_insecure != now_insecure) {
		if(now_insecure)
			panel_alert_danger();
		else
			panel_alert_safe();
	}
}

static void make_tray_icon(void)
{
	GError* error = NULL;
	normal_icon = gdk_pixbuf_new_from_file_at_size(
		"panel/status-icon.png", 64, 64, &error);
	alert_icon = gdk_pixbuf_new_from_file_at_size(
		"panel/status-icon-alert.png", 64, 64, &error);
	status_icon = gtk_status_icon_new_from_pixbuf(normal_icon);
	g_signal_connect(G_OBJECT(status_icon), "activate",
		G_CALLBACK(on_statusicon_activate), NULL);
	g_signal_connect(G_OBJECT(status_icon), "popup-menu",
		G_CALLBACK(on_statusicon_popup_menu), NULL);
	gtk_status_icon_set_tooltip(status_icon, "dnssec-trigger");
	gtk_status_icon_set_visible(status_icon, TRUE);
}

/** do main work */
static void
do_main_work(const char* cfgfile)
{
	GtkBuilder* builder;
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
	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "panel/pui.xml", NULL);

	result_window = GTK_WIDGET(gtk_builder_get_object(builder,
		"result_dialog"));
	result_textview = GTK_TEXT_VIEW(gtk_builder_get_object(builder,
		"result_textview"));
	statusmenu = GTK_MENU(gtk_builder_get_object(builder, "statusmenu"));
	g_object_ref(G_OBJECT(statusmenu));
	gtk_widget_hide(GTK_WIDGET(result_window));
	g_object_ref(G_OBJECT(result_window));

	gtk_builder_connect_signals(builder, NULL);          
	g_object_unref(G_OBJECT(builder));
	make_tray_icon();
	/* make tray icon loaded the icons, also good for our windows */
	gtk_window_set_icon(GTK_WINDOW(result_window), normal_icon);
	spawn_feed(cfg);

	gdk_threads_enter();
	gtk_main();
	gdk_threads_leave();
	attach_stop();
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
        while( (c=getopt(argc, argv, "c:h")) != -1) {
                switch(c) {
                default:
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
	do_main_work(cfgfile);
#ifdef USE_WINSOCK
	WSACleanup();
#endif
	return 0;
}
