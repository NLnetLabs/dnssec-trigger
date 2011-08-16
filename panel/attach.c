/*
 * attach.h - dnssec-trigger acttachment from panel to daemon.
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
 *
 * This file contains the code that attaches the panel to the daemon.
 */
#include "config.h"
#include <gtk/gtk.h>
#include "panel/attach.h"
#include "riggerd/cfg.h"
#include "riggerd/log.h"
#include "riggerd/net_help.h"

/* the global feed structure */
struct feed* feed = NULL;

static void attach_main(void);

/* stop read */
static void
stop_ssl(SSL* ssl, int fd)
{
	if(ssl) SSL_shutdown(ssl);
	SSL_free(ssl);
#ifndef USE_WINSOCK
	close(fd);
#else
	closesocket(fd);
#endif
}

void attach_stop(void)
{
	g_mutex_lock(feed->lock);
	if(feed->ssl_read) {
		stop_ssl(feed->ssl_read, SSL_get_fd(feed->ssl_read));
		feed->ssl_read = NULL;
	}
	if(feed->ssl_write) {
		stop_ssl(feed->ssl_write, SSL_get_fd(feed->ssl_write));
		feed->ssl_write = NULL;
	}
	g_mutex_unlock(feed->lock);
}

/* keep trying to open the read channel, blocking */
static SSL* try_contact_server()
{
	const char* svr = "127.0.0.1";
	SSL* ssl = NULL;
	while(!ssl) {
		int fd = -1;
		while(fd == -1) {
			fd = contact_server(svr, feed->cfg->control_port, 0,
				feed->connect_reason,
				sizeof(feed->connect_reason));
			if(fd == -1) {
				g_mutex_unlock(feed->lock);
				sleep(1);
				g_mutex_lock(feed->lock);
			}
		}
		ssl = setup_ssl_client(feed->ctx, fd, feed->connect_reason,
				sizeof(feed->connect_reason));
		if(!ssl) {
			stop_ssl(ssl, fd);
			g_mutex_unlock(feed->lock);
			sleep(1);
			g_mutex_lock(feed->lock);
		}
	}
	return ssl;
}

/* write the first command over SSL, blocking */
static void write_firstcmd(SSL* ssl, char* cmd)
{
	char pre[10];
	if(!ssl) return;
	snprintf(pre, sizeof(pre), "DNSTRIG%d ", CONTROL_VERSION);
	if(SSL_write(ssl, pre, (int)strlen(pre)) <= 0)
		fatal_exit("could not SSL_write");
	if(SSL_write(ssl, cmd, (int)strlen(cmd)) <= 0)
		fatal_exit("could not SSL_write");
}

void attach_start(struct cfg* cfg)
{
	g_mutex_lock(feed->lock);
	snprintf(feed->connect_reason, sizeof(feed->connect_reason),
		"connecting to probe daemon");
	feed->cfg = cfg;
	feed->ctx = cfg_setup_ctx_client(cfg, feed->connect_reason,
		sizeof(feed->connect_reason));
	if(!feed->ctx) {
		fatal_exit("cannot setup ssl context: %s",
			feed->connect_reason);
	}
	feed->ssl_read = try_contact_server();
	feed->ssl_write = try_contact_server();
	printf("contacted server\n");
	write_firstcmd(feed->ssl_write, "cmdtray\n");
	write_firstcmd(feed->ssl_read, "results\n");
	printf("contacted server, first cmds written\n");
	feed->connected = 1;
	g_mutex_unlock(feed->lock);
	/* mainloop */
	attach_main();
}

static int check_for_event(void)
{
	int fd;
	fd_set r;
	g_mutex_lock(feed->lock);
	fd = SSL_get_fd(feed->ssl_read);
	g_mutex_unlock(feed->lock);
	/* select on it */
	while(1) {
		FD_ZERO(&r);
		FD_SET(fd, &r);
		if(select(fd+1, &r, NULL, NULL, NULL) < 0) {
			if(errno == EAGAIN || errno == EINTR)
				continue;
			else break;
		}
		return 1;
	}
	return 0;
}

static int
read_an_ssl_line(SSL* ssl, char* line, size_t len)
{
	size_t i = 0;
	while(SSL_read(ssl, line+i, 1) > 0) {
		if(line[i] == '\n') {
			line[i]=0;
			return 1;
		}
		if(++i >= len) {
			log_err("line too long");
			return 0;
		}
	}
	/* error */
	log_err("failed SSL_read");
	return 0;
}

/** append to strlist */
static void strlist_append(struct strlist** first, struct strlist** last,
	char* str)
{
	struct strlist* e = (struct strlist*)malloc(sizeof(*e));
	if(!e) fatal_exit("out of memory");
	e->next = NULL;
	e->str = strdup(str);
	if(!e->str) fatal_exit("out of memory");
	if(*last)
		(*last)->next = e;
	else	*first = e;
	*last = e;
}

/** free strlist */
static void
strlist_delete(struct strlist* e)
{
	struct strlist* p = e, *np;
	while(p) {
		np = p->next;
		free(p->str);
		free(p);
		p = np;
	}
}

static void read_from_feed(void)
{
	struct strlist* first=NULL, *last=NULL;
	char line[1024];
	printf("read from feed\n");
	while(read_an_ssl_line(feed->ssl_read, line, sizeof(line))) {
		/* stop at empty line */
		printf("feed: %s\n", line);
		if(line[0] == 0) {
			strlist_delete(feed->results);
			feed->results = first;
			feed->results_last = last;
			return;
		}
		strlist_append(&first, &last, line);
	}
	feed->connected = 0;
	stop_ssl(feed->ssl_read, SSL_get_fd(feed->ssl_read));
	feed->ssl_read = NULL; /* for quit in meantime */
	feed->ssl_read = try_contact_server();
	write_firstcmd(feed->ssl_read, "results\n");
	feed->connected = 1;
}

static void process_results(void)
{
	int now_insecure = 0, feed_insecure = 0;
	int now_dark = 0, now_auth = 0, now_cache = 0, now_disconn = 0;

	/* fetch data */
	g_mutex_lock(feed->lock);
	if(!feed->connected) return;
	if(!feed->results_last) return;
	now_insecure = (strstr(feed->results_last->str, "insecure")!=NULL);
	now_dark = (strstr(feed->results_last->str, "dark")!=NULL);
	now_cache = (strstr(feed->results_last->str, "cache")!=NULL);
	now_auth = (strstr(feed->results_last->str, "auth")!=NULL);
	now_disconn = (strstr(feed->results_last->str, "disconnected")!=NULL);
	feed_insecure = feed->insecure_mode;
	g_mutex_unlock(feed->lock);

	gdk_threads_enter();
	panel_alert_state(feed_insecure, now_insecure, now_dark, now_cache,
		now_auth, now_disconn);
	gdk_threads_leave();
}

static void attach_main(void)
{
	/* check for event */
	while(check_for_event()) {
		g_mutex_lock(feed->lock);
		if(!feed->ssl_read) {
			g_mutex_unlock(feed->lock);
			break;
		}
		read_from_feed();
		g_mutex_unlock(feed->lock);
		process_results();
	}

}
