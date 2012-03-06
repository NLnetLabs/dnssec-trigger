/*
 * probe.h - dnssec-trigger DNSSEC probes
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
 * This file contains the probe definition.
 */

#ifndef PROBE_H
#define PROBE_H
struct comm_point;
struct comm_reply;
struct http_get;
struct http_fetch;
struct outq;
struct svr;

/**
 * probe structure that contains the probe details for one IP address.
 */
struct probe_ip {
	struct probe_ip* next;
	/* the IP address probed */
	char* name;
	/* to authority? */
	int to_auth;
	/* for dnstcp? */
	int dnstcp;
	/* for ssl? */
	struct ssllist* ssldns;
	/* is this a http probe */
	int to_http;
	/* is http on ipv6 (or v4)? */
	int http_ip6;
	/* destination port */
	int port;

	/* the ssl context (if any) for this destination address */
	void* sslctx;

	/* DS query, or NULL if done */
	struct outq* ds_c;
	/* DNSKEY query, or NULL if done */
	struct outq* dnskey_c;
	/* nodata query probes NSEC3, or NULL if done or not used */
	struct outq* nsec3_c;

	/* A,AAAA query to resolve http hostname, or NULL if done or not used*/
	struct outq* host_c;
	/* http query in progress */
	struct http_get* http;
	/* desc of http (available even when done and http is NULL) */
	char* http_desc;

	/* if probe has finished */
	int finished;
	/* result for this IP, true if DNSSEC OK */
	int works;
	/* string with explanation of failure */
	char* reason;
	/* if a packet has been received by a query (i.e. network is up) */
	int got_packet;
};

/** outstanding query */
struct outq {
	struct sockaddr_storage addr;
	socklen_t addrlen;
	uint16_t qid;
	uint16_t qtype;
	int recurse; /* if true: recursive probe */
	const char* qname; /* reference to a static string */
	int timeout; /* in msec */
	int on_tcp; /* if we are using TCP */
	int on_ssl; /* if we are using SSL */
	int port; /* port number (mostly 53) */
	int edns; /* if edns yes */
	struct comm_point* c;
	struct comm_timer* timer;
	struct probe_ip* probe; /* reference only to owner */
};

#define QUERY_START_TIMEOUT 100 /* msec */
#define QUERY_END_TIMEOUT 1000 /* msec */
#define QUERY_TCP_TIMEOUT 3000 /* msec */

/** start the probe process for a new set of IPs.
 * in a string, with whitespace in between
 * the string may be altered. */
void probe_start(char* ips);

/** delete and stop probe */
void probe_delete(struct probe_ip* p);

/** probe list delete */
void probe_list_delete(struct probe_ip* list);

/** handle probe results */
int outq_handle_udp(struct comm_point* c, void* my_arg, int error,
        struct comm_reply *reply_info);
int outq_handle_tcp(struct comm_point* c, void* my_arg, int error,
        struct comm_reply *reply_info);

/** outstanding query UDP timeout handler */
void outq_timeout(void* arg);

void probe_cache_done(void);
void probe_all_done(void);
void probe_unsafe_test(void);
void probe_tcp_test(void);
void probe_http_test(void);
void probe_ssl_test(void);
void probe_setup_cache(struct svr* svr, struct probe_ip* p);
void probe_setup_hotspot_signon(struct svr* svr);
void probe_setup_dnstcp(struct svr* svr);

/** true if probe is a cache IP, a DNS server from the DHCP hook */
int probe_is_cache(struct probe_ip* p);

/** Create new outgoing query */
struct outq* outq_create(const char* ip, int tp, const char* domain,
	int recurse, struct probe_ip* p, int tcp, int onssl, int port,
	int edns);

#endif /* PROBE_H */
