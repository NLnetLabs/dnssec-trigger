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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
	if(!feed->ssl_read) {
		feed->unlock();
		return 0;
	}
	if(SSL_pending(feed->ssl_read) != 0) {
		feed->unlock();
		return 1;
	}
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

/**
 * Read data from feed and return indication what to do
 * 0: stop. lock is unlocked for exit.
 * 1: nothing. caller unlocks lock.
 * 2: new probe results. caller unlocks lock.
 * 3: new softwareupdate. caller unlocks lock.
 */
static int read_from_feed(void)
{
	struct strlist* first=NULL, *last=NULL;
	char line[1024];
	if(verbosity > 2) printf("read from feed\n");
	while(read_an_ssl_line(feed->ssl_read, line, sizeof(line))) {
		/* stop at empty line */
		if(verbosity > 2) printf("feed: %s\n", line);
		if(!first && strcmp(line, "") == 0) {
			/* skip empty lines at start */
			continue;
		}
		if(!first && strcmp(line, "stop") == 0) {
			strlist_delete(first);
			feed->unlock();
			feed->quit();
			return 0;
		}
		if(line[0] == 0) {
			if(!first)
				return 1; /* robust */
			if(strncmp(first->str, "at ", 3) == 0) {
				if(verbosity >2) printf("got results\n");
				strlist_delete(feed->results);
				feed->results = first;
				feed->results_last = last;
				return 2;
			} else if(strncmp(first->str, "update ", 7) == 0) {
				if(verbosity >2) printf("got update\n");
				strlist_delete(feed->update);
				feed->update = first;
				feed->update_last = last;
				return 3;
			}
			if(verbosity >2) printf("got unknown\n");
			strlist_delete(first);
			return 1; /* robust */
		}
		strlist_append(&first, &last, line);
	}
	feed->connected = 0;
	stop_ssl(feed->ssl_read, SSL_get_fd(feed->ssl_read));
	feed->ssl_read = NULL; /* for quit in meantime */
	feed->ssl_read = try_contact_server();
	write_firstcmd(feed->ssl_read, "results\n");
	feed->connected = 1;
	return 1;
}

static void process_update(void)
{
	char* s;

	/* fetch data */
	feed->lock();
	if(!feed->connected) {
		feed->unlock();
		return;
	}
	if(!feed->update_last) {
		feed->unlock();
		return;
	}
	s = strdup(feed->update_last->str);
	feed->unlock();

	if(s) {
		if(feed->update_alert) feed->update_alert(s);
		else free(s);
	}
}

static void process_results(void)
{
	char* s;
	struct alert_arg a;
	memset(&a, 0, sizeof(a));

	/* fetch data */
	feed->lock();
	if(!feed->connected) {
		feed->unlock();
		return;
	}
	if(!feed->results_last) {
		feed->unlock();
		return;
	}
	s = feed->results_last->str;
	a.now_insecure = (strstr(s, "insecure_mode")!=NULL);
	a.now_http_insecure = (strstr(s, "http_insecure")!=NULL);
	a.now_forced_insecure = (strstr(s, "forced_insecure")!=NULL);
	a.now_dark = (strstr(s, "nodnssec")!=NULL);
	a.now_cache = (strstr(s, "cache")!=NULL);
	a.now_auth = (strstr(s, "auth")!=NULL);
	a.now_tcp = (strstr(s, "tcp")!=NULL);
	a.now_ssl = (strstr(s, "ssl")!=NULL);
	a.now_disconn = (strstr(s, "disconnected")!=NULL);
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
		switch(read_from_feed()) {
			case 0: /* already unlocked the lock */
				return;
			default:
			case 1: feed->unlock();
				break;
			case 2: feed->unlock();
				process_results();
				break;
			case 3: feed->unlock();
				process_update();
				break;
		}
	}
}

static void send_ssl_cmd(const char* cmd)
{
	if(verbosity > 2) printf("sslcmd: %s\n", cmd);
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
	if(verbosity > 2) printf("insecure command %s\n", val?"yes":"no");
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

void attach_send_skip_http(void)
{
	send_ssl_cmd("skip_http\n");
}

void attach_send_update_cancel(void)
{
	send_ssl_cmd("update_cancel\n");
}

void attach_send_update_ok(void)
{
	send_ssl_cmd("update_ok\n");
}

const char* state_tooltip(struct alert_arg* a)
{
	if(a->now_forced_insecure)
		return "DNS DANGER (forced hotspot signon)";
	else if(a->now_http_insecure && a->now_insecure)
		return "DNS DANGER (hotspot signon)";
	else if(a->now_insecure)
		return "DNS DANGER";
	else if(a->now_dark)
		return "DNS stopped";
	else if(a->now_cache)
		return "DNSSEC via cache";
	else if(a->now_tcp)
		return "DNSSEC via tcp relay resolver";
	else if(a->now_ssl)
		return "DNSSEC via ssl relay resolver";
	else if(a->now_disconn)
		return "network disconnected";
	return "DNSSEC via authorities";
}

void process_state(struct alert_arg* a, int* unsafe_asked, int* noweb_asked,
        void (*danger)(void), void(*safe)(void), void(*dialog)(void),
	void (*noweb)(void))
{
	/* if we are no longe unsafe, set asked to false to ask again
	 * next time */
	if(!a->now_dark) {
		*unsafe_asked = 0;
		*noweb_asked = 0;
	}
	if(!a->now_http_insecure)
		*noweb_asked = 0;
	if(!a->now_insecure)
		*unsafe_asked = 0;

	/* see what must be done */
	if(!a->last_insecure && a->now_insecure) {
		danger();
	} else if(a->last_insecure && !a->now_insecure) {
		safe();
	}
	if(!a->now_insecure && a->now_dark && !*unsafe_asked
		&& !a->now_forced_insecure && !a->now_http_insecure) {
		dialog();
	}
	if(!a->now_insecure && a->now_dark && a->now_http_insecure &&
		!a->now_forced_insecure && !*noweb_asked) {
		noweb();
	}
}

void fetch_proberesults(char* buf, size_t len, const char* lf)
{
	char* pos = buf;
	size_t left = len, n;
	struct strlist* p;

	buf[0] = 0; /* safe start */
	buf[len-1] = 0; /* no buffer overflow */
	snprintf(pos, left, "%s%sresults from probe ", PACKAGE_STRING, lf);
	n = strlen(pos);
	pos += n; left -= n;

	feed->lock();
	p = feed->results;
	if(p && strncmp(p->str, "at ", 3) == 0) {
		snprintf(pos, left, "%s", p->str);
		n = strlen(pos);
		pos += n; left -= n;
		p=p->next;
	}
	snprintf(pos, left, "%s%s", lf, lf);
	n = strlen(pos);
	pos += n; left -= n;
	if(!feed->connected) {
		snprintf(pos, left, "error: %s%s", feed->connect_reason, lf);
		n = strlen(pos);
		pos += n; left -= n;
		snprintf(pos, left, 
		"cannot connect to the dnssec-trigger service, DNSSEC%s"
		"status cannot be read.%s", lf, lf);
		n = strlen(pos);
		pos += n; left -= n;
		p = NULL;
	}
	/* indent for strings is adjusted to be able to judge line length */
	for(; p; p=p->next) {
		if(!p->next) {
			/* last line */
			snprintf(pos, left, "%s", lf);
			n = strlen(pos);
			pos += n; left -= n;
			if(strstr(p->str, "cache"))
				snprintf(pos, left, 
		"DNSSEC results fetched from (DHCP) cache(s)%s", lf);
			else if(strstr(p->str, "auth"))
				snprintf(pos, left, 
		"DNSSEC results fetched direct from authorities%s", lf);
			else if(strstr(p->str, "tcp"))
				snprintf(pos, left, 
		"DNSSEC results fetched from relay resolvers over TCP%s", lf);
			else if(strstr(p->str, "ssl"))
				snprintf(pos, left, 
		"DNSSEC results fetched from relay resolvers over SSL%s", lf);
			else if(strstr(p->str, "disconnected"))
				snprintf(pos, left, 
		"The network seems to be disconnected. A local cache of DNS%s"
		"results is used, but no queries are made.%s", lf, lf);
			else if(strstr(p->str, "forced_insecure"))
				snprintf(pos, left, 
		"DNS queries are being sent to INSECURE servers%s"
		"because Hotspot Sign-on mode was selected. Select%s"
		"Reprobe (from menu) after sign-on. A red exclamation%s"
		"mark in the icon warns you when DNSSEC is disabled.%s",
				lf, lf, lf, lf);
			else if(strstr(p->str, "http_insecure") &&
				strstr(p->str, "insecure_mode")==NULL)
				snprintf(pos, left, 
		"DNS queries are stopped until user confirmation.%s"
		"There is no web access, asking if user wants to do%s"
		"hotspot signon in insecure mode.%s", lf, lf, lf);
			else if(strstr(p->str, "http_insecure") &&
				strstr(p->str, "insecure_mode"))
				snprintf(pos, left, 
		"DNS queries are sent to INSECURE servers. There is%s"
		"no web access, perhaps you must do hotspot signon.%s"
		"Please, be careful out there.%s", lf, lf, lf);
			else if(strstr(p->str, "nodnssec") && !strstr(p->str,
				"insecure"))
				snprintf(pos, left, 
		"A local cache of DNS results is used but no queries%s"
		"are made, because DNSSEC is intercepted on this network.%s"
		"(DNS is stopped)%s", lf, lf, lf);
			else 	snprintf(pos, left, 
		"DNS queries are sent to INSECURE servers.%s"
		"Please, be careful out there.%s", lf, lf);
			n = strlen(pos);
			pos += n; left -= n;
		} else {
			snprintf(pos, left, "%s%s", p->str, lf);
			n = strlen(pos);
			pos += n; left -= n;
		}
	}
	feed->unlock();
}

void run_login(void)
{
	struct cfg* cfg = feed->cfg;
#ifndef USE_WINSOCK
	pid_t p;
#endif
	if(!cfg->login_command || !cfg->login_command[0])
		return; /* disabled */
#ifndef USE_WINSOCK
	p = fork();
	if(p == -1) {
		log_err("could not fork: %s", strerror(errno));
		return;
	}
	if(p) return; /* parent returns */
	if(execlp(cfg->login_command, cfg->login_command, cfg->login_location,
		NULL) == -1) {
		log_err("could not exec: %s", strerror(errno));
	}
	/* not reachable */
	exit(1);
#endif /* USE_WINSOCK */
}
