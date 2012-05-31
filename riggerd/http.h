/*
 * http.h - dnssec-trigger HTTP client code to GET a simple URL
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

#ifndef HTTP_H
#define HTTP_H
struct comm_base;
struct comm_point;
#include <ldns/buffer.h>
#include <ldns/packet.h>
struct svr;
struct http_probe;
struct probe_ip;
struct comm_reply;

/**
 * overall HTTP probe structure
 */
struct http_general {
	struct svr* svr;

	/* array of urls to attempt to transfer from */
	char** urls;
	/* array of checkcodes to check - the content of those urls */
	char** codes;
	/* number of urls in array */
	size_t url_num;

	/* the ipv4 http probe */
	struct http_probe* v4;
	/* the ipv6 http probe */
	struct http_probe* v6;

	/* http works */
	int saw_http_work;
};

/**
 * HTTP probe.  The url split up and results.
 */
struct http_probe {
	/* the current url (const reference) */
	char* url;
	/* hostname */
	char* hostname;
	/* filename (not prefixed with a / ) */
	char* filename;
	/* url index in urls array */
	size_t url_idx;

	/* are we fetching the address record or doing http_get? */
	int do_addr;
	/* is this ipv6? */
	int ip6;
	
	/* num addr queries */
	int num_addr_qs;
	/* num addr queries that failed */
	int num_failed_addr_qs;
	/* list of addresses (RR records) */
	ldns_rr_list* addr;
	/* port number */
	int port;

	/* result: did we get addresses? */
	int got_addrs;
	/* result: does it connect? */
	int connects;
	/* result: does it work (correct page) */
	int works;
	/* is the probe finished? */
	int finished;
};

/** the number of urls to try to probe; in case one fails. */
#define HTTP_NUM_URLS_MAX_PROBE 3

/** max number of address queries for one name (all to different caches,
 * once for A then for AAAA, so double that number in sockets is needed). */
#define HTTP_MAX_ADDR_QUERIES 5

/**
 * create and randomise http general structure
 * @param svr: with config and create and register probes here.
 * @return: new http lookup administration
 */
struct http_general* http_general_start(struct svr* svr);

/**
 * delete the http_general structure.
 * @param hg: http lookup administration
 */
void http_general_delete(struct http_general* hg);

/**
 * The http lookup is completely done, either success (NULL) or fail reason
 */
void http_general_done(const char* reason);

/** a host addr lookup is done (with an error or NULL) */
void http_host_outq_done(struct probe_ip* p, const char* reason);
/** a host addr lookup is done, here is the packet (QR, rcode NOERROR).
 * The pkt is freeed by this routine. */
void http_host_outq_result(struct probe_ip* p, ldns_pkt* pkt);

/**
 * Structure that represents an open TCP activity for a HTTP (no -s) GET.
 */
struct http_get {
	/* The url of the target */
	char* url;
	/* hostname : name of host part of the URL */
	char* hostname;
	/* filename : name of file part of URL (*not* prefixed with a / ) */
	char* filename;

	/* state of the HTTP transaction */
	enum http_get_state {
		/* we are not sending or reading any things */
		http_state_none,
		/* we are sending the request (initial headers) */
		http_state_request,
		/* we are reading the reply headers */
		http_state_reply_header,
		/* we are reading the reply (HTTP/1.0) */
		http_state_reply_data,
		/* we are reading chunked reply headers (HTTP/1.1) */
		http_state_chunk_header,
		/* we are reading chunked reply data (HTTP/1.1) */
		http_state_chunk_data,
	} state;
	/* data length (of replydata or chunkdata) */
	size_t datalen;

	/* max data we want (0 is no max) */
	size_t data_limit;

	/* the buffer with contents sent/received */
	ldns_buffer* buf;
	/* the buffer with the result data */
	ldns_buffer* data;

	/* my comm_base */
	struct comm_base* base;
	/* my comm_point (a comm_raw) */
	struct comm_point* cp;
	/* the timer */
	struct comm_timer* timer;

	/* destination IP as a string */
	char* dest;
	/* port number */
	int port;
	/* the probe that this is part of */
	struct probe_ip* probe;
};

/* define max length that the buffer is created for */
#define MAX_HTTP_LENGTH 16384
/* the timeout for the HTTP part of the httpprobe operation, in msec */
#define HTTP_TIMEOUT 3000
/* HTTP port */
#define HTTP_PORT 80

/**
 * Create a new HTTP GET for the given url (http://example.com/bla.txt) 
 * It does a plain (noSSL) http GET.
 * @param url: The url to fetch.
 * @param base: comm_base to register connect-ed TCP socket's comm_point.
 * @param probe: probe this is part of.
 * @return new get or NULL on failure (malloc failure).
 */
struct http_get* http_get_create(const char* url, struct comm_base* base,
	struct probe_ip* probe);

/**
 * Delete a HTTP GET fetch.
 * @param hg: http_get structure to delete.
 */
void http_get_delete(struct http_get* hg);

/**
 * Perform the fetch that was initialised.
 * Parses, connects, and so on.
 * @param hg: http_get structure.
 * @param dest: destination IP address.
 * @param port: port number (HTTP_PORT is the default 80).
 * @param err: the detailed error on failure (set to constant string).
 * @return false if failed.
 */
int http_get_fetch(struct http_get* hg, const char* dest, int port, char** err);

/** handle socket events on http_get */
int http_get_callback(struct comm_point* cp, void* arg, int err,
	struct comm_reply* reply);
/** handle timeout for the http_get operation */
void http_get_timeout_handler(void* arg);

/** pick random RR from rr list, removes it from the list. list not empty*/
ldns_rr* http_pick_random_addr(ldns_rr_list* list);

#endif /* HTTP_H */
