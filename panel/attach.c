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
#ifdef HOOKS_OSX
#include "osxattach.h"
#include "cfg.h"
#include "log.h"
#include "net_help.h"
#else
#include "panel/attach.h"
#include "riggerd/cfg.h"
#include "riggerd/log.h"
#include "riggerd/net_help.h"
#endif

/* the global feed structure */
struct feed* feed = NULL;

static void attach_main(void);

void attach_create(void)
{
	feed = (struct feed*)calloc(1, sizeof(*feed));
	if(!feed) fatal_exit("out of memory");
}

void attach_delete(void)
{
	free(feed);
	feed = NULL;
}

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
	feed->lock();
	if(feed->ssl_read) {
		stop_ssl(feed->ssl_read, SSL_get_fd(feed->ssl_read));
		feed->ssl_read = NULL;
	}
	if(feed->ssl_write) {
		stop_ssl(feed->ssl_write, SSL_get_fd(feed->ssl_write));
		feed->ssl_write = NULL;
	}
	feed->unlock();
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
			if(fd == -1 || fd == -2) {
				feed->unlock();
				sleep(1);
				feed->lock();
			}
		}
		ssl = setup_ssl_client(feed->ctx, fd, feed->connect_reason,
				sizeof(feed->connect_reason));
		if(!ssl) {
			stop_ssl(ssl, fd);
			feed->unlock();
			sleep(1);
			feed->lock();
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
	feed->lock();
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
	if(verbosity>2) printf("contacted server\n");
	write_firstcmd(feed->ssl_write, "cmdtray\n");
	write_firstcmd(feed->ssl_read, "results\n");
	if(verbosity>2) printf("contacted server, first cmds written\n");
	feed->connected = 1;
	feed->unlock();
	/* mainloop */
	attach_main();
}

static int check_for_event(void)
{
	int fd;
	fd_set r;
	feed->lock();
	fd = SSL_get_fd(feed->ssl_read);
	feed->unlock();
	/* select on it */
	while(1) {
		FD_ZERO(&r);
		FD_SET(FD_SET_T fd, &r);
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
	if(ERR_get_error() != 0)
		log_err("failed SSL_read");
	return 0;
}

static void read_from_feed(void)
{
	struct strlist* first=NULL, *last=NULL;
	char line[1024];
	if(verbosity > 2) printf("read from feed\n");
	while(read_an_ssl_line(feed->ssl_read, line, sizeof(line))) {
		/* stop at empty line */
		if(verbosity > 2) printf("feed: %s\n", line);
		if(strcmp(line, "stop") == 0) {
			strlist_delete(first);
			feed->quit();
			return;
		}
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
	struct alert_arg a;
	memset(&a, 0, sizeof(a));

	/* fetch data */
	feed->lock();
	if(!feed->connected) return;
	if(!feed->results_last) return;
	a.now_insecure = (strstr(feed->results_last->str, "insecure")!=NULL);
	a.now_dark = (strstr(feed->results_last->str, "nodnssec")!=NULL);
	a.now_cache = (strstr(feed->results_last->str, "cache")!=NULL);
	a.now_auth = (strstr(feed->results_last->str, "auth")!=NULL);
	a.now_tcp = (strstr(feed->results_last->str, "tcp")!=NULL);
	a.now_disconn = (strstr(feed->results_last->str, "disconnected")!=NULL);
	a.last_insecure = feed->insecure_mode;
	feed->insecure_mode = a.now_insecure;
	feed->unlock();

	feed->alert(&a);
}

static void attach_main(void)
{
	/* check for event */
	while(check_for_event()) {
		feed->lock();
		if(!feed->ssl_read) {
			feed->unlock();
			break;
		}
		read_from_feed();
		feed->unlock();
		process_results();
	}

}

static void send_ssl_cmd(const char* cmd)
{
	feed->lock();
	if(feed->ssl_write) {
		if(SSL_write(feed->ssl_write, cmd, (int)strlen(cmd)) <= 0) {
			log_err("could not SSL_write");
			/* reconnect and try again */
			stop_ssl(feed->ssl_write, SSL_get_fd(feed->ssl_write));
			feed->ssl_write = NULL; /* for quit in meantime */
			feed->ssl_write = try_contact_server();
			write_firstcmd(feed->ssl_write, "cmdtray\n");
			(void)SSL_write(feed->ssl_write, cmd, (int)strlen(cmd));
		}
	}
	feed->unlock();
}

void attach_send_insecure(int val)
{
	if(val) send_ssl_cmd("insecure yes\n");
	else	send_ssl_cmd("insecure no\n");
}

void attach_send_reprobe(void)
{
	send_ssl_cmd("reprobe\n");
}

void attach_send_hotspot_signon(void)
{
	send_ssl_cmd("hotspot_signon\n");
}

const char* state_tooltip(struct alert_arg* a)
{
	if(a->now_forced_insecure)
		return "DNS DANGER (hotspot signon)";
	else if(a->now_insecure)
		return "DNS DANGER";
	else if(a->now_dark)
		return "DNS stopped";
	else if(a->now_cache)
		return "DNSSEC via cache";
	else if(a->now_tcp)
		return "DNSSEC via tcp open resolver";
	else if(a->now_disconn)
		return "network disconnected";
	return "DNSSEC via authorities";
}

void process_state(struct alert_arg* a, int* unsafe_asked,
        void (*danger)(void), void(*safe)(void), void(*dialog)(void))
{
	if(!a->now_dark)
		*unsafe_asked = 0;
	if(!a->last_insecure && a->now_insecure) {
		danger();
	} else if(a->last_insecure && !a->now_insecure) {
		safe();
	}
	if(!a->now_insecure && a->now_dark && !*unsafe_asked
		&& !a->now_forced_insecure) {
		dialog();
	}
}

void fetch_proberesults(char* buf, size_t len, const char* lf)
{
	char* pos = buf;
	size_t left = len, n;
	struct strlist* p;

	buf[0] = 0; /* safe start */
	buf[len-1] = 0; /* no buffer overflow */
	n=snprintf(pos, left, "results from probe ");
	pos += n; left -= n;

	feed->lock();
	p = feed->results;
	if(p && strncmp(p->str, "at ", 3) == 0) {
		n=snprintf(pos, left, "%s", p->str);
		pos += n; left -= n;
		p=p->next;
	}
	n=snprintf(pos, left, "%s%s", lf, lf);
	pos += n; left -= n;
	if(!feed->connected) {
		n=snprintf(pos, left, "error: %s%s", feed->connect_reason, lf);
		pos += n; left -= n;
		n=snprintf(pos, left, 
		"cannot connect to the dnssec-trigger service, DNSSEC%s"
		"status cannot be read.%s", lf, lf);
		pos += n; left -= n;
		p = NULL;
	}
	/* indent for strings is adjusted to be able to judge line length */
	for(; p; p=p->next) {
		if(!p->next) {
			/* last line */
			n=snprintf(pos, left, "%s", lf);
			pos += n; left -= n;
			if(strstr(p->str, "cache"))
				n=snprintf(pos, left, 
		"DNSSEC results fetched from (DHCP) cache(s)%s", lf);
			else if(strstr(p->str, "auth"))
				n=snprintf(pos, left, 
		"DNSSEC results fetched direct from authorities%s", lf);
			else if(strstr(p->str, "tcp"))
				n=snprintf(pos, left, 
		"DNSSEC results fetched from open resolvers over TCP%s", lf);
			else if(strstr(p->str, "disconnected"))
				n=snprintf(pos, left, 
		"The network seems to be disconnected. A local cache of DNS%s"
		"results is used, but no queries are made.%s", lf, lf);
			else if(strstr(p->str, "forced_insecure"))
				n=snprintf(pos, left, 
		"DNS queries are sent to INSECURE servers, because of%s"
		"Hotspot Signon. Select Reprobe (from menu) after signon.%s"
		"Please, be careful out there.%s", lf, lf, lf);
			else if(strstr(p->str, "nodnssec") && !strstr(p->str,
				"insecure"))
				n=snprintf(pos, left, 
		"A local cache of DNS results is used but no queries%s"
		"are made, because DNSSEC is intercepted on this network.%s"
		"(DNS is stopped)%s", lf, lf, lf);
			else 	n=snprintf(pos, left, 
		"DNS queries are sent to INSECURE servers.%s"
		"Please, be careful out there.%s", lf, lf);
			pos += n; left -= n;
		} else {
			n=snprintf(pos, left, "%s%s", p->str, lf);
			pos += n; left -= n;
		}
	}
	feed->unlock();
}
