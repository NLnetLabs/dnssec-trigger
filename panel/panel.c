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

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-trigger-panel [options]\n");
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
		printf("killed by signal %d\n", (int)sig);
		exit(0);
	break;
#ifdef SIGPIPE
	case SIGPIPE:
	break;
#endif
	default:
		printf("ignoring signal %d", sig);
	}
}

void 
on_window_destroy(GtkObject* object, gpointer user_data)
{
	gtk_main_quit();
}

/** do main work */
static void
do_main_work(void)
{
	GtkBuilder* builder;
	GtkWidget* window;

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
                printf("install sighandler: %s\n", strerror(errno));
        /* start */
	printf("panel\n");

	builder = gtk_builder_new();
	gtk_builder_add_from_file(builder, "panel/pui.xml", NULL);

	window = GTK_WIDGET(gtk_builder_get_object(builder, "resultdialog"));
	gtk_builder_connect_signals(builder, NULL);          
	g_object_unref(G_OBJECT(builder));

	gtk_widget_show(window);       
	gtk_main();
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
        while( (c=getopt(argc, argv, "h")) != -1) {
                switch(c) {
                default:
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

	/* show user interface */
	gtk_init (&argc, &argv);
	do_main_work();
	return 0;
}
