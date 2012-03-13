/*
 * http.c - dnssec-trigger HTTP client code to GET a simple URL
 *
 * Copyright (c) 2012, NLnet Labs. All rights reserved.
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
 * This file contains an implementation of HTTP fetch for a simple URL file.
 */
#include "config.h"
#include <ldns/ldns.h>
#include "riggerd/http.h"
#include "riggerd/netevent.h"
#include "riggerd/log.h"
#include "riggerd/svr.h"
#include "riggerd/probe.h"
#include "riggerd/cfg.h"
#include "riggerd/net_help.h"
#ifdef USE_WINSOCK
#include "winsock_event.h"
#endif

/** start http get with a random dest address from the set */
void http_probe_start_http_get(struct http_probe* hp);

/** parse url into hostname and filename */
static int parse_url(char* url, char** h, char** f)
{
	char* front, *sl;
	if(strncmp(url, "http://", 7) != 0) {
		return 0;
	}
	front = url+7;
	sl = strchr(front, '/');
	if(!sl) {
		/* http://www.example.com */
		(*h) = strdup(front);
		(*f) = strdup("");
	} else {
		*sl = 0;
		(*h) = strdup(front);
		(*f) = strdup(sl+1);
		*sl = '/';
	}
	if(!(*h) || !(*f)) {
		log_err("parse_url: malloc failure");
		return 0;
	}
	return 1;
}

/** setup httpprobe for a new url */
static int
http_probe_setup_url(struct http_general* hg, struct http_probe* hp, size_t i)
{
	hp->do_addr = 1;
	hp->url_idx = i;
	hp->url = strdup(hg->urls[i]);
	if(!hp->url) {
		log_err("out of memory");
		return 0;
	}
	if(!parse_url(hp->url, &hp->hostname, &hp->filename)) {
		return 0;
	}
	verbose(VERB_ALGO, "setup url %s %s", hp->hostname, hp->filename);
	return 1;
}

/** create probe for address */
static void
probe_create_addr(const char* ip, const char* domain, int rrtype)
{
	struct probe_ip* p;
	p = (struct probe_ip*)calloc(1, sizeof(*p));
	if(!p) {
		log_err("out of memory");
		return;
	}
	p->port = DNS_PORT;
	p->to_http = 1;
	p->http_ip6 = (rrtype == LDNS_RR_TYPE_AAAA);
	p->name = strdup(ip);
	if(!p->name) {
		free(p);
		log_err("out of memory");
		return;
	}
	/* no need for EDNS-probe, DNSSEC-types; we check for magic cookie in
	 * HTTP response data */
	p->host_c = outq_create(p->name, rrtype, domain, 1, p, 0, 0,
		p->port, 0, 0);
	if(!p->host_c) {
		free(p->name);
		free(p);
		log_err("out of memory");
		return;
	}

	/* put it in the svr list */
	p->next = global_svr->probes;
	global_svr->probes = p;
	global_svr->num_probes++;
}

/** create address lookup queries for http probe */
static void
http_probe_make_addr_queries(struct http_general* hg, struct http_probe* hp)
{
	/* lookup hostname at the recursive resolvers */
	struct probe_ip* p;
	hp->num_addr_qs = 0;
	hp->num_failed_addr_qs = 0;

	/* created probes are prepended, thus this can continue easily */
	for(p = hg->svr->probes; p; p=p->next) {
		if(!probe_is_cache(p))
			continue;
		probe_create_addr(p->name, hp->hostname,
			hp->ip6?LDNS_RR_TYPE_AAAA:LDNS_RR_TYPE_A);
		hp->num_addr_qs++;
		if(hp->num_addr_qs >= HTTP_MAX_ADDR_QUERIES)
			break;
	}
}

/** see if hp ip6 fits with probe ip6 */
static int
right_ip6(struct http_probe* hp, struct probe_ip* p)
{
	return (hp->ip6 && p->http_ip6) || (!hp->ip6 && !p->http_ip6);
}

/* delete addr lookups from probe list in svr */
void http_probe_remove_addr_lookups(struct http_probe* hp)
{
	struct svr* svr = global_svr;
	struct probe_ip* p = svr->probes, **pp = &svr->probes;
	/* find and delete addr lookups */
	while(p) {
		/* need to delete this? */
		if(p->to_http && right_ip6(hp, p) && p->host_c) {
			/* snip off */
			(*pp) = p->next;
			if(p->works)
				svr->num_probes_done --;
			svr->num_probes --;
			probe_delete(p);
			p = (*pp);
			continue;
		}
		/* go to next item */
		pp = &p->next;
		p = p->next;
	}
}

/* delete http lookups from probe list in svr */
void http_probe_remove_http_lookups(struct http_probe* hp)
{
	struct svr* svr = global_svr;
	struct probe_ip* p = svr->probes, **pp = &svr->probes;
	verbose(VERB_ALGO, "remove http lookups");
	/* find and delete http lookups */
	while(p) {
		/* need to delete this? */
		if(p->to_http && right_ip6(hp, p) && p->http) {
			/* snip off */
			(*pp) = p->next;
			if(p->works)
				svr->num_probes_done --;
			svr->num_probes --;
			probe_delete(p);
			p = (*pp);
			continue;
		}
		/* go to next item */
		pp = &p->next;
		p = p->next;
	}
}

/** the http_probe is done (fail with reason, or its is NULL) */
static void http_probe_done(struct http_general* hg,
	struct http_probe* hp, char* reason)
{
	hp->finished = 1;
	verbose(VERB_OPS, "http probe%s %s done: %s", hp->ip6?"6":"4", hp->url,
		reason?reason:"success");
	if(reason == NULL) {
		/* success! stop the other probe part */
		if(hp->ip6 && hg->v4) {
			if(hg->v4->do_addr)
				http_probe_remove_addr_lookups(hg->v4);
			else	http_probe_remove_http_lookups(hg->v4);
		} else if(!hp->ip6 && hg->v6) {
			if(hg->v6->do_addr)
				http_probe_remove_addr_lookups(hg->v6);
			else	http_probe_remove_http_lookups(hg->v6);
		}
		hp->works = 1;
		http_general_done(reason);
	} else {
		hp->works = 0;
		/* if other done too, now its total fail for http */
		if(hp->ip6) {
			if(!hg->v4 || hg->v4->finished) {
				http_general_done(reason);
			}
		} else {
			if(!hg->v6 || hg->v6->finished) {
				http_general_done(reason);
			}
		}
	}
}

/** start resolving the hostname of the next url in the list */
static void http_probe_go_next_url(struct http_general* hg,
	struct http_probe* hp)
{
	free(hp->url);
	hp->url = NULL;
	free(hp->hostname);
	hp->hostname = NULL;
	free(hp->filename);
	hp->filename = NULL;
	ldns_rr_list_deep_free(hp->addr);
	hp->addr = NULL;

	log_assert(hp->url_idx < hg->url_num);
	if(!http_probe_setup_url(hg, hp, ++hp->url_idx)) {
		http_probe_done(hg, hp, "out of memory or parse error");
		return;
	}
	http_probe_make_addr_queries(hg, hp);
}

/** http probe is done with an address, check next addr */
static void http_probe_done_addr(struct http_general* hg,
	struct http_probe* hp, char* reason, int connects)
{
	/* if we connected to some sort of server, then we do not need to
	 * attempt a different server - we are hotspotted or successed */
	if(connects) {
		http_probe_done(hg, hp, reason);
		return;
	}

	if(!reason) { /* should also 'connects', but for robustness */
		http_probe_done(hg, hp, reason);
		return;
	}

	/* So: we did not connect and there is an error reason */
	log_assert(!connects && reason);

	/* try the next address */
	if(hp->addr && ldns_rr_list_rr_count(hp->addr) != 0) {
		http_probe_start_http_get(hp);
		return;
	}
	/* no more addresses? try the next url */
	if(hp->url_idx+1 < global_svr->http->url_num) {
		http_probe_go_next_url(hg, hp);
		return;
	}
	/* fail */
	http_probe_done(hg, hp, reason);
}

static int
http_probe_create_get(struct http_probe* hp, ldns_rr* addr, char** reason)
{
	struct probe_ip* p;
	p = (struct probe_ip*)calloc(1, sizeof(*p));
	if(!p) {
		*reason = "out of memory";
		return 0;
	}
	p->port = 80;
	p->to_http = 1;
	p->http_ip6 = hp->ip6;
	if(!addr || !ldns_rr_rdf(addr, 0)) {
		*reason = "addr without rdata";
		free(p);
		return 0;
	}
	p->name = ldns_rdf2str(ldns_rr_rdf(addr, 0));
	if(!p->name) {
		free(p);
		*reason = "out of memory";
		return 0;
	}

	/* create http_get structure */
	p->http = http_get_create(hp->url, global_svr->base, p);
	if(!p->http) {
		*reason = "out of memory";
		free(p->name); 
		free(p);
		return 0;
	}
	if(!http_get_fetch(p->http, p->name, reason)) {
		http_get_delete(p->http);
		free(p->name); 
		free(p);
		return 0;
	}
	p->http_desc = strdup(hp->hostname);
	if(!p->http_desc) {
		*reason = "malloc failure";
		http_get_delete(p->http);
		free(p->name); 
		free(p);
		return 0;
	}

	/* put it in the svr list */
	p->next = global_svr->probes;
	global_svr->probes = p;
	global_svr->num_probes++;
	return 1;
}

/** start http get with a random dest address from the set */
void http_probe_start_http_get(struct http_probe* hp)
{
	char* reason = "out of memory";
	/* pick random address */
	size_t count = ldns_rr_list_rr_count(hp->addr);
	size_t i = ldns_get_random()%count;
	ldns_rr* rr = ldns_rr_list_rr(hp->addr, i);

	/* remove from rr_list */
	if(i < count) {
		(void)ldns_rr_list_set_rr(hp->addr,
			ldns_rr_list_rr(hp->addr, count-1), i);
		ldns_rr_list_set_rr_count(hp->addr, count-1);
	}

	/* create probe */
	if(!http_probe_create_get(hp, rr, &reason)) {
		log_err("http_probe_create_get: %s", reason);
		ldns_rr_free(rr);
		http_probe_done_addr(global_svr->http, hp, reason, 0);
		return;
	}
	ldns_rr_free(rr);
}

/** delete http probe structure */
static void http_probe_delete(struct http_probe* hp)
{
	if(!hp) return;
	ldns_rr_list_deep_free(hp->addr);
	free(hp->url);
	free(hp->hostname);
	free(hp->filename);
	free(hp);
}

/** create and start new http probe for v4 or v6 */
static struct http_probe*
http_probe_start(struct http_general* hg, int ip6)
{
	struct http_probe* hp = (struct http_probe*)calloc(1, sizeof(*hp));
	if(!hp) return NULL;
	hp->ip6 = ip6;
	if(!http_probe_setup_url(hg, hp, 0)) {
		http_probe_delete(hp);
		return NULL;
	}
	http_probe_make_addr_queries(hg, hp);
	return hp;
}

/* see if str in array */
static int already_used(struct http_general* hg, char* s)
{
	size_t i;
	for(i=0; i<hg->url_num; i++)
		if(hg->urls[i] == s)
			return 1;
	return 0;
}

/* pick url from list not picking twice */
static char* pick_url(struct http_general* hg, size_t x, char** code)
{
	size_t now = 0;
	struct strlist2* p;
	for(p=hg->svr->cfg->http_urls; p; p=p->next) {
		if(already_used(hg, p->str1))
			continue;
		if(now++ == x) {
			*code = p->str2;
			return p->str1;
		}
	}
	return NULL;
}

/* fill the url array randomly */
static void fill_urls(struct http_general* hg)
{
	size_t i;
	for(i=0; i<hg->url_num; i++) {
		/* random number from remaining number of choices */
		if((int)hg->url_num == hg->svr->cfg->num_http_urls &&
			i == hg->url_num)
			hg->urls[i] = pick_url(hg, 0, &hg->codes[i]);
		else hg->urls[i] = pick_url(hg,
			ldns_get_random()%(hg->svr->cfg->num_http_urls - i),
			&hg->codes[i]);
	}
	for(i=0; i<hg->url_num; i++)
		verbose(VERB_ALGO, "hg url[%d]=%s", (int)i, hg->urls[i]);
}

struct http_general* http_general_start(struct svr* svr)
{
	struct http_general* hg = (struct http_general*)calloc(1, sizeof(*hg));
	if(!hg) return NULL;
	hg->svr = svr;
	if(svr->cfg->num_http_urls >= HTTP_NUM_URLS_MAX_PROBE)
		hg->url_num = HTTP_NUM_URLS_MAX_PROBE;
	else	hg->url_num = (size_t)svr->cfg->num_http_urls;
	hg->urls = (char**)calloc(hg->url_num, sizeof(char*));
	hg->codes = (char**)calloc(hg->url_num, sizeof(char*));
	if(!hg->urls || !hg->codes) {
		free(hg->urls);
		free(hg->codes);
		free(hg);
		return NULL;
	}
	/* randomly pick that number of urls from the config */
	fill_urls(hg);
	/* start v4 and v6 */
	hg->v4 = http_probe_start(hg, 0);
	if(!hg->v4) {
		log_err("out of memory");
		http_general_delete(hg);
		return NULL;
	}
	hg->v6 = http_probe_start(hg, 1);
	if(!hg->v6) {
		log_err("out of memory");
		http_general_delete(hg);
		return NULL;
	}
	return hg;
}

void http_general_delete(struct http_general* hg)
{
	if(!hg) return;
	free(hg->urls);
	free(hg->codes);
	http_probe_delete(hg->v4);
	http_probe_delete(hg->v6);
	free(hg);
}

void http_general_done(const char* reason)
{
	struct svr* svr = global_svr;
	verbose(VERB_OPS, "http_general done %s", reason?reason:"success");
	if(!reason) {
		svr->http->saw_http_work = 1;
	}

	if(svr->num_probes_done < svr->num_probes) {
		/* if we are probing the cache, and now http works,
		 * and some cache was already seen to work.
		 * (and we are not probing TCP, SSL, Authority),
		 * (and we are not in forced_insecure mode).
		 * Then we can already use the working cache server now. */
		if(!reason && !svr->probe_dnstcp && !svr->probe_direct &&
			svr->saw_first_working && !svr->forced_insecure) {
			probe_setup_cache(svr, NULL);
		}
		return; /* wait for other probes at the cache stage */
	}
	probe_cache_done();
}

void http_host_outq_done(struct probe_ip* p, const char* reason)
{
	struct http_probe* hp;
	if(!reason) {
		verbose(VERB_OPS, "addr lookup %s at %s successful",
			p->host_c->qname, p->name);
		p->works = 1;
	} else {
		verbose(VERB_OPS, "addr lookup %s at %s failed: %s",
			p->host_c->qname, p->name, reason);
		p->reason = strdup(reason);
		p->works = 0;
	}
	p->finished = 1;
	global_svr->num_probes_done++;

	if(p->http_ip6) 
		hp = global_svr->http->v6;
	else	hp = global_svr->http->v4;

	if(reason) {
		hp->num_failed_addr_qs++;
		/* see if other address lookups have also failed */
		if(hp->num_failed_addr_qs >= hp->num_addr_qs) {
			/* if so, go to next url */
			/* attempt to go to the next url or fail if no next url */
			if(hp->url_idx+1 < global_svr->http->url_num) {
				http_probe_remove_addr_lookups(hp);
				http_probe_go_next_url(global_svr->http, hp);
			} else {
				http_probe_done(global_svr->http, hp,
					"cannot resolve domain name");
			}
		}
	} else {
		hp->got_addrs = 1;
		hp->do_addr = 0;
		/* it worked, remove other address lookups for this hostname */
		http_probe_remove_addr_lookups(hp);
		/* if it worked, then start http part of the probe sequence */
		http_probe_start_http_get(hp);
	}
}

void http_host_outq_result(struct probe_ip* p, ldns_pkt* pkt)
{
	/* not picked by name because of CNAMEs */
	ldns_rr_list* addr = ldns_pkt_rr_list_by_type(pkt, p->http_ip6?
		LDNS_RR_TYPE_AAAA:LDNS_RR_TYPE_A, LDNS_SECTION_ANSWER);
	ldns_pkt_free(pkt);
	/* see if RR data, is empty, outq_done with error */
	if(!addr || ldns_rr_list_rr_count(addr) == 0) {
		ldns_rr_list_deep_free(addr);
		http_host_outq_done(p, "nodata answer");
		return;
	}
	/* store the address results */
	if(p->http_ip6)
		global_svr->http->v6->addr = addr;
	else 	global_svr->http->v4->addr = addr;
	http_host_outq_done(p, NULL);
}

/** check if the data is correct, ignore whitespace */
static int
hg_check_data(ldns_buffer* data, char* result)
{
	char* s = (char*)ldns_buffer_begin(data);
	while(isspace(*s))
		s++;
	if(strncmp(s, result, strlen(result)) != 0)
		return 0;
	s += 2;
	while(isspace(*s))
		s++;
	if(*s != 0)
		return 0;
	return 1;
}

/** http get is done (failure or success) */
static void
http_get_done(struct http_get* hg, char* reason, int connects)
{
	struct probe_ip* p = hg->probe;
	struct http_probe* hp = (p->http_ip6)?
		global_svr->http->v6:global_svr->http->v4;
	p->finished = 1;
	global_svr->num_probes_done++;
	/* printout data we got (but pages can be big)
	if(!reason) verbose(VERB_ALGO, "got %d data: '%s'", 
		(int)ldns_buffer_position(hg->data),
		ldns_buffer_begin(hg->data)); */
	if(!reason || connects)
		hp->connects = 1;
	if(!reason) {
		/* check the data */
		if(!hg_check_data(hg->data,
			global_svr->http->codes[hp->url_idx]))
			reason = "wrong page content";
		else 	verbose(VERB_ALGO, "correct page content from %s",
				p->name);
	}

	verbose(VERB_OPS, "http_get_done: %s from %s: %s (%s)", hg->url, hg->dest,
		reason?reason:"success",
		!reason||connects?"connects":"noconnects");
	if(!reason) {
		p->works = 1;
	} else {
		p->works = 0;
		p->reason = strdup(reason);
		if(!p->reason) log_err("malloc failure");
	}
	http_get_delete(hg);
	p->http = NULL;

	http_probe_done_addr(global_svr->http, hp, reason, hp->connects);
}

/** handle timeout for the http_get operation */
void
http_get_timeout_handler(void* arg)
{
	struct http_get* hg = (struct http_get*)arg;
	verbose(VERB_ALGO, "http_get timeout");
	http_get_done(hg, "timeout", 0);
}

struct http_get* http_get_create(const char* url, struct comm_base* base,
	struct probe_ip* probe)
{
	struct http_get* hg = (struct http_get*)calloc(1, sizeof(*hg));
	if(!hg) {
		log_err("http_get_create: out of memory");
		return NULL;
	}
	hg->probe = probe;
	hg->state = http_state_none;
	hg->url = strdup(url);
	if(!hg->url) {
		log_err("http_get_create: out of memory");
		free(hg);
		return NULL;
	}
	hg->buf = ldns_buffer_new(MAX_HTTP_LENGTH);
	if(!hg->buf) {
		log_err("http_get_create: out of memory");
		http_get_delete(hg);
		return NULL;
	}
	hg->data = ldns_buffer_new(MAX_HTTP_LENGTH);
	if(!hg->data) {
		log_err("http_get_create: out of memory");
		http_get_delete(hg);
		return NULL;
	}
	hg->timer = comm_timer_create(base, http_get_timeout_handler, hg);
	if(!hg->timer) {
		log_err("http_get_create: out of memory");
		http_get_delete(hg);
		return NULL;
	}
	hg->base = base;
	return hg;
}

/** Put HTTP GET 1.1 into the buffer, ready to send to host */
static int
prep_get_cmd(struct http_get* hg)
{
	ldns_buffer_clear(hg->buf);
	if(ldns_buffer_printf(hg->buf, "GET /%s HTTP/1.1\r\n", hg->filename)
		== -1)
		return 0;
	if(ldns_buffer_printf(hg->buf, "Host: %s\r\n", hg->hostname) == -1)
		return 0;
	if(ldns_buffer_printf(hg->buf, "User-Agent: dnssec-trigger/%s\r\n",
		PACKAGE_VERSION) == -1)
		return 0;
	/* not really needed: Connection: close */
	if(ldns_buffer_printf(hg->buf, "\r\n") == -1)
		return 0;
	ldns_buffer_flip(hg->buf);
	verbose(VERB_ALGO, "created http get text: %s", ldns_buffer_begin(hg->buf));
	return 1;
}

/** connect to destination IP (nonblocking), return fd (or -1). */
static int
http_get_connect(struct sockaddr_storage* addr, socklen_t addrlen, char** err)
{
	int fd;
#ifdef INET6
	if(addr_is_ip6(addr, addrlen))
		fd = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	else
#endif
		fd = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(fd == -1) {
#ifndef USE_WINSOCK
		log_err("http_get: socket: %s", strerror(errno));
		*err = strerror(errno);
#else
		*err = wsa_strerror(WSAGetLastError());
		log_err("http_get: socket: %s",
			wsa_strerror(WSAGetLastError()));
#endif
		return -1;
	}
	fd_set_nonblock(fd);
	if(connect(fd, (struct sockaddr*)addr, addrlen) == -1) {
#ifndef USE_WINSOCK
#ifdef EINPROGRESS
		if(errno != EINPROGRESS) {
#else
		if(1) {
#endif
			*err = strerror(errno);
			log_err("http_get: connect: %s", *err);
			close(fd);
#else /* USE_WINSOCK */
		if(WSAGetLastError() != WSAEINPROGRESS &&
			WSAGetLastError() != WSAEWOULDBLOCK) {
			*err = wsa_strerror(WSAGetLastError());
			log_err("http_get: connect: %s", *err);
			closesocket(fd);
#endif
			return -1;
		}

	}
	return fd;
}

/** write buffer to socket, returns true if done, false if notdone or error */
static int hg_write_buf(struct http_get* hg, ldns_buffer* buf)
{
	ssize_t r;
	char* str = NULL;
	int fd = hg->cp->fd;
	if(hg->cp->tcp_check_nb_connect) {
		/* check for pending error from nonblocking connect */
		/* from Stevens, unix network programming, vol1, 3rd ed, p450*/
		int error = 0;
		socklen_t len = (socklen_t)sizeof(error);
		if(getsockopt(fd, SOL_SOCKET, SO_ERROR, (void*)&error,\
			&len) < 0) {
#ifndef USE_WINSOCK
			error = errno; /* on solaris errno is error */
#else /* USE_WINSOCK */
			error = WSAGetLastError();
#endif
		}
#ifndef USE_WINSOCK
#if defined(EINPROGRESS) && defined(EWOULDBLOCK)
		if(error == EINPROGRESS || error == EWOULDBLOCK)
			return 0; /* try again later */
		else
#endif
		if(error != 0) {
			str = strerror(error);
#else /* USE_WINSOCK */
		if(error == WSAEINPROGRESS)
			return 0;
		else if(error == WSAEWOULDBLOCK) {
			winsock_tcp_wouldblock(comm_point_internal(hg->cp),
				EV_WRITE);
			return 0;
		} else if(error != 0) {
			str = wsa_strerror(error);
#endif /* USE_WINSOCK */
			log_err("http connect: %s", str);
			http_get_done(hg, str, 0);
			return 0;
		}
		/* no connect error */
		hg->cp->tcp_check_nb_connect = 0;
	}

	/* write data */
	r = send(fd, (void*)ldns_buffer_current(buf),
		ldns_buffer_remaining(buf), 0);
	if(r == -1) {
#ifndef USE_WINSOCK
		if(errno == EINTR || errno == EAGAIN)
			return 0;
		str = strerror(errno);
#else
		if(WSAGetLastError() == WSAEINPROGRESS)
			return 0;
		if(WSAGetLastError() == WSAEWOULDBLOCK) {
			winsock_tcp_wouldblock(comm_point_internal(hg->cp),
				EV_WRITE);
			return 0;
		}
		str = wsa_strerror(WSAGetLastError());
#endif
		log_err("http write: %s", str);
		http_get_done(hg, str, 0);
		return 0;
	}
	ldns_buffer_skip(buf, r);
	return (ldns_buffer_remaining(buf) == 0);
}

/** read buffer from socket, returns false on failures (or simply not done).
 * returns true if something extra was read in. caller checks if done. 
 * zero terminates after a read (right after buf position) */
static int hg_read_buf(struct http_get* hg, ldns_buffer* buf)
{
	ssize_t r;
	int fd = hg->cp->fd;
	/* save up one space at end for a trailing zero byte */
	r = recv(fd, (void*)ldns_buffer_current(buf),
		ldns_buffer_remaining(buf)-1, 0);
	/* zero terminate for sure */
	ldns_buffer_write_u8_at(buf, ldns_buffer_limit(buf)-1, 0);
	/* check for errors */
	if(r == -1) {
		char* str = NULL;
#ifndef USE_WINSOCK
		if(errno == EINTR || errno == EAGAIN)
			return 0;
		str = strerror(errno);
#else
		if(WSAGetLastError() == WSAEINPROGRESS)
			return 0;
		if(WSAGetLastError() == WSAEWOULDBLOCK) {
			winsock_tcp_wouldblock(comm_point_internal(hg->cp),
				EV_READ);
			return 0;
		}
		/* WSAECONNRESET could happen */
		str = wsa_strerror(WSAGetLastError());
#endif
		log_err("http read: %s", str);
		http_get_done(hg, str, 0);
		return 0;
	}
	ldns_buffer_skip(buf, r);
	return 1;
}

/** parse lines from the buffer, from begin to len, modify to remove line-end
 * and call parse func.  Returns false on parse failure. */
static int
hg_parse_lines(struct http_get* hg, ldns_buffer* src, size_t len,
	int (*func)(struct http_get*, char*, void*), void* arg)
{
	size_t pos = 0;
	log_assert(len <= ldns_buffer_position(src));
	/* the check for pos in limit is for robustness */
	while(pos < len && pos <= ldns_buffer_limit(src)) {
		/* see if there is a (whole) line here) */
		/* safe because the source buffer is zero terminated for sure*/
		char* eol = strstr((char*)ldns_buffer_at(src, pos), "\r\n");
		if(!eol) {
			http_get_done(hg, "header line without eol", 1);
			return 0;
		}
		if(pos >= ldns_buffer_limit(src)) {
			/* impossible, but check for robustness */
			http_get_done(hg, "header line too long", 1);
			return 0;
		}
		if(eol > (char*)ldns_buffer_at(src, len)) {
			break;
		}
		/* eol == len is allowed, for \r\n at end of headers */
		/* zero terminate the line (removes the eol from string) */
		*eol = 0;
		/* callback function */
		if(!(*func)(hg, (char*)ldns_buffer_at(src, pos), arg))
			return 0;
		/* next line */
		pos += (eol - (char*)ldns_buffer_at(src, pos));
		pos += 2; /* skip -r-n (now 00-n) */
	}
	return 1;
}

/** move trailing end of buffer to the front */
static void
hg_buf_move(ldns_buffer* buf, size_t headlen)
{
	if(ldns_buffer_position(buf) > headlen) {
		size_t traillen = ldns_buffer_position(buf)-headlen;
		memmove(ldns_buffer_begin(buf),
			ldns_buffer_at(buf, headlen), traillen);
		ldns_buffer_set_position(buf, traillen);
	} else {
		ldns_buffer_clear(buf);
	}
	/* zero terminate buffer */
	ldns_buffer_current(buf)[0] = 0;
}

/** handle write of http request */
static int hg_handle_request(struct http_get* hg)
{
	/* write request */
	if(!hg_write_buf(hg, hg->buf))
		return 0;
	/* done, start reading reply headers */
	ldns_buffer_clear(hg->buf);
	comm_point_listen_for_rw(hg->cp, 1, 0);
	hg->state = http_state_reply_header;
	return 1;
}

/** parse reply header line */
static int
reply_header_parse(struct http_get* hg, char* line, void* arg)
{
	size_t* datalen = (size_t*)arg;
	verbose(VERB_ALGO, "http reply header: %s", line);
	if(strncasecmp(line, "HTTP/1.1 ", 9) == 0) {
		/* check returncode; we understand the following from
		 * rcodes:
		 * 2xx : success, look at content (perhaps changed by hotspot)
		 * 3xx : redirect of some form - probably the hotspot.
		 * other: failure
		 */
		if(line[9] == '3') {
			/* redirect type codes, this means it fails 
			 * completely*/
			char err[512];
			snprintf(err, sizeof(err), "http redirect %s", line+9);
			/* we connected to the server, this looks like a
			 * hotspot that redirects */
			http_get_done(hg, err, 1);
			return 0;
		} else if(line[9] != '2') {
			char err[512];
			snprintf(err, sizeof(err), "http error %s", line+9);
			/* we 'connected' but it seems the page is not
			 * there anymore.  Try another url and pretend we
			 * could not connect to get it to try another url. */
			/* because we pass noconnect, it will also try other
			 * ip addresses for the server.  perhaps another server
			 * does not give 404? */
			http_get_done(hg, err, 0);
			return 0;
		}
	} else if(strncasecmp(line, "Content-Length: ", 16) == 0) {
		*datalen = (size_t)atoi(line+16);
	} else if(strncasecmp(line, "Transfer-Encoding: chunked", 19+7) == 0) {
		*datalen = 0;
	}
	return 1;
}

/** handle read of reply headers (the topmost headers) */
static int hg_handle_reply_header(struct http_get* hg)
{
	size_t headlen = 0;
	size_t datalen = 0;
	char* endstr;
	if(!hg_read_buf(hg, hg->buf))
		return 0;
	/* check if done */
	endstr = strstr((char*)ldns_buffer_begin(hg->buf), "\r\n\r\n");
	if(!endstr) {
		if(ldns_buffer_remaining(hg->buf)-1 == 0) {
			http_get_done(hg, "http headers too large", 1);
			return 0;
		}
		return 0;
	}
	headlen = (size_t)(endstr-(char*)ldns_buffer_begin(hg->buf));
	verbose(VERB_ALGO, "http done, parse reply header");
	/* done reading, parse it */
	log_assert(strncmp(ldns_buffer_at(hg->buf, headlen), "\r\n\r\n", 4)==0);
	/* there is a header part, and a start of a trailing part. */
	/* extract lines, parse with the given function */
	if(!hg_parse_lines(hg, hg->buf, headlen, reply_header_parse, &datalen))
		return 0;
	/* figured out what form the reply takes (one data and its length,
	 * or chunked, or error */
	/* move trailing part to front of data buffer (skip /r/n/r/n) */
	hg_buf_move(hg->buf, headlen+4);
	/* if one data seg: see if data can fit into the buffer, or fail */
	if(datalen != 0) {
		if(datalen > HTTP_MAX_DATA) {
			http_get_done(hg, "http reply data too large", 1);
			return 0;
		}
		if(!ldns_buffer_reserve(hg->buf,
			datalen - ldns_buffer_position(hg->buf))) {
			http_get_done(hg, "out of memory", 1);
			return 0;
		}
		hg->state = http_state_reply_data;
		hg->datalen = datalen;
		verbose(VERB_ALGO, "http 1.0 data len %d", (int)datalen);
	} else {
		hg->state = http_state_chunk_header;
	}
	return 1;
}

/** add data to output buffer */
static int
hg_add_data(struct http_get* hg, ldns_buffer* add, size_t len)
{
	if(ldns_buffer_position(hg->data) + len > HTTP_MAX_DATA) {
		http_get_done(hg, "http data too large", 1);
		return 0;
	}
	if(!ldns_buffer_reserve(hg->data, len+1)) {
		http_get_done(hg, "out of memory", 1);
		return 0;
	}
	ldns_buffer_write(hg->data, ldns_buffer_begin(add), len);
	/* zero terminate */
	ldns_buffer_write_u8_at(hg->data, ldns_buffer_position(hg->data), 0);
	return 1;
}

/** handle read of reply data (as one block of data) */
static int hg_handle_reply_data(struct http_get* hg)
{
	/* this state could start with initial data that is complete
	 * already, otherwise, read more */
	if(ldns_buffer_position(hg->buf) < hg->datalen) {
		if(!hg_read_buf(hg, hg->buf))
			return 0;
		if(ldns_buffer_position(hg->buf) < hg->datalen)
			return 0;
	}
	log_assert(ldns_buffer_position(hg->buf) >= hg->datalen);
	if(!hg_add_data(hg, hg->buf, hg->datalen))
		return 0;
	/* done with success with data */
	verbose(VERB_ALGO, "http read completed");
	http_get_done(hg, NULL, 1);
	return 0;
}

/** parse reply header line */
static int
chunk_header_parse(struct http_get* hg, char* line, void* arg)
{
	size_t* chunklen = (size_t*)arg;
	char* e = NULL;
	size_t v;
	verbose(VERB_ALGO, "http chunk header: '%s'", line);
	v = (size_t)strtol(line, &e, 16);
	if(e == line) {
		http_get_done(hg, "could not parse chunk header", 1);
		return 0;
	}
	*chunklen = v;
	return 1;
}

/** handle read of chunked reply headers (the size of the chunk) */
static int hg_handle_chunk_header(struct http_get* hg)
{
	/* this state could start with initial data that is complete
	 * already, otherwise, read more */
	size_t headlen = 0;
	size_t chunklen = 0;
	char* endstr;
	if(!strstr((char*)ldns_buffer_begin(hg->buf), "\r\n")) {
		if(!hg_read_buf(hg, hg->buf))
			return 0;
	}
	endstr = strstr((char*)ldns_buffer_begin(hg->buf), "\r\n");
	if(!endstr) {
		if(ldns_buffer_remaining(hg->buf)-1 == 0) {
			http_get_done(hg, "http chunk headers too large", 1);
			return 0;
		}
		return 0;
	}
	headlen = (size_t)(endstr-(char*)ldns_buffer_begin(hg->buf));
	/* done reading, parse it */
	log_assert(strncmp(ldns_buffer_at(hg->buf, headlen), "\r\n", 2)==0);
	/* extract lines, parse with the given function */
	if(!hg_parse_lines(hg, hg->buf, headlen, chunk_header_parse, &chunklen))
		return 0;
	if(chunklen == 0) {
		/* chunked read completed */
		/* TODO there can be chunked trailer headers here .. */
		verbose(VERB_ALGO, "http chunked read completed");
		http_get_done(hg, NULL, 1);
		return 0;
	}
	/* move trailing part to front of data buffer (skip /r/n) */
	hg_buf_move(hg->buf, headlen+2);
	/* see if data can possibly fit */
	if(chunklen > HTTP_MAX_DATA) {
		http_get_done(hg, "http reply chunk data too large", 1);
		return 0;
	}
	if(!ldns_buffer_reserve(hg->buf,
		chunklen - ldns_buffer_position(hg->buf))) {
		http_get_done(hg, "out of memory", 1);
		return 0;
	}
	hg->state = http_state_chunk_data;
	verbose(VERB_ALGO, "http chunk len %d", (int)chunklen);
	hg->datalen = chunklen;
	return 1;
}

/** handle read of chunked reply data (of one chunk) */
static int hg_handle_chunk_data(struct http_get* hg)
{
	/* this state could start with initial data that is complete
	 * already, otherwise, read more */
	/* read datalen+2 - body + /r/n */
	if(ldns_buffer_position(hg->buf) < hg->datalen+2) {
		if(!hg_read_buf(hg, hg->buf))
			return 0;
		if(ldns_buffer_position(hg->buf) < hg->datalen+2)
			return 0;
	}
	/* done reading put it together */
	log_assert(ldns_buffer_position(hg->buf) >= hg->datalen);
	verbose(VERB_ALGO, "datalen %d", (int)hg->datalen);
	verbose(VERB_ALGO, "position %d", (int)ldns_buffer_position(hg->buf));
	if(strncmp((char*)ldns_buffer_at(hg->buf, hg->datalen), "\r\n", 2)!=0) {
		http_get_done(hg, "chunk data not terminated with eol", 1);
		return 0;
	}
	/* remove trailing newline */
	ldns_buffer_write_u8_at(hg->buf, hg->datalen, 0);
	if(!hg_add_data(hg, hg->buf, hg->datalen))
		return 0;

	/* move up data (plus emptyline) */
	hg_buf_move(hg->buf, hg->datalen+2);
	hg->state = http_state_chunk_header;
	return 1;
}

/** handle http get state (return true to continue processing) */
static int hg_handle_state(struct http_get* hg)
{
	verbose(VERB_ALGO, "hg_handle_state %d", (int)hg->state);
	switch(hg->state) {
		case http_state_none:
			/* not possible */
			http_get_done(hg, "got event while not connected", 0);
			return 0;
		case http_state_request:
			return hg_handle_request(hg);
		case http_state_reply_header:
			return hg_handle_reply_header(hg);
		case http_state_reply_data:
			return hg_handle_reply_data(hg);
		case http_state_chunk_header:
			return hg_handle_chunk_header(hg);
		case http_state_chunk_data:
			return hg_handle_chunk_data(hg);
		default:
			break;
	}
	http_get_done(hg, "unknown state", 0);
	return 0;
}

/** handle events (read or write) on the http file descriptor */
int
http_get_callback(struct comm_point* ATTR_UNUSED(cp), void* arg, int err,
	struct comm_reply* ATTR_UNUSED(reply))
{
	struct http_get* hg = (struct http_get*)arg;
	if(err != NETEVENT_NOERROR) {
		/* timeout handled with timer, other errors not possible */
		log_err("internal error: http_get_callback got %d", err);
		return 0;
	}
	/* is this read or write, and if so, what part of the protocol */
	verbose(VERB_ALGO, "http_get: got event for %s from %s", hg->url, hg->dest);

	while(hg_handle_state(hg)) {
		;
	}
	/* the return value is not used by comm_point_raw */
	return 0;
}

int http_get_fetch(struct http_get* hg, const char* dest, char** err)
{
	int fd;
	struct timeval tv;
	struct sockaddr_storage addr;
	socklen_t addrlen = 0;

	/* parse the URL */
	verbose(VERB_ALGO, "http_get fetch %s from %s", hg->url, dest);
	if(!parse_url(hg->url, &hg->hostname, &hg->filename)) {
		*err = "cannot parse url";
		return 0;
	}
	verbose(VERB_ALGO, "parsed into %s and %s", hg->hostname, hg->filename);

	/* parse dest IP address */
	if(!(hg->dest = strdup(dest))) {
		*err = "out of memory";
		return 0;
	}
	if(!ipstrtoaddr(dest, HTTP_PORT, &addr, &addrlen)) {
		log_err("error in syntax of IP address %s", dest);
		*err = "cannot parse IP address";
		return 0;
	}

	/* start TCP connection to destination, prepare send headers */
	if(!prep_get_cmd(hg)) {
		*err = "out of memory";
		return 0;
	}
	/* clear and zero terminate data buffer */
	ldns_buffer_clear(hg->data);
	ldns_buffer_write_u8_at(hg->data, ldns_buffer_position(hg->data), 0);

	/* set timeout */
	tv.tv_sec = HTTP_TIMEOUT/1000;
	tv.tv_usec = HTTP_TIMEOUT%1000;
	comm_timer_set(hg->timer, &tv);

	/* create fd and connect nonblockingly */
	if( (fd=http_get_connect(&addr, addrlen, err)) == -1) {
		return 0;
	}

	/* commpoint, raw,   get nb_connect check on write */
	/* we created the fd before to pass it here, so that the event_add
	 * on windows sees the full (TCP, SOCK_STREAM) file descriptor and
	 * activates the necessary workarounds for TCP sticky events */
	hg->cp = comm_point_create_raw(hg->base, fd, 1, http_get_callback, hg);
	if(!hg->cp) {
		*err = "out of memory";
		return 0;
	}
	hg->cp->do_not_close = 0;
	hg->cp->tcp_check_nb_connect = 1;
	hg->state = http_state_request;

	*err = NULL;
	return 1;
}

void http_get_delete(struct http_get* hg)
{
	if(!hg) return;
	free(hg->url);
	free(hg->hostname);
	free(hg->filename);
	free(hg->dest);
	ldns_buffer_free(hg->buf);
	ldns_buffer_free(hg->data);
	comm_point_delete(hg->cp);
	comm_timer_delete(hg->timer);
	free(hg);
}
