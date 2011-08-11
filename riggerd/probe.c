/*
 * probe.c - dnssec-trigger DNSSEC probes implementation
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
 * This file contains the probe implementation.
 */
#include "config.h"
#include "probe.h"
#include "svr.h"
#include "log.h"
#include "netevent.h"
#include "net_help.h"
#include <ldns/packet.h>

/* create probes for the ip addresses in the string */
static void probe_spawn(char* ip);
/* delete and stop outq */
static void outq_delete(struct outq* outq);
/* set timeout on outq and create UDP query and send it */
static int outq_settimeout_and_send(struct outq* outq);
/* send outq over tcp */
static void outq_send_tcp(struct outq* outq);
/* add timeval without overflow */
static void timeval_add(struct timeval* d, const struct timeval* add);
/* a query is done, check probe to see if failed, succeed or wait */
static void probe_partial_done(struct probe_ip* p, const char* in,
	const char* reason);
/* a probe is done (fail or success) see global progress */
static void probe_done(struct probe_ip* p);

/** add timers and the values do not overflow or become negative */
static void
timeval_add(struct timeval* d, const struct timeval* add)
{
#ifndef S_SPLINT_S
	d->tv_sec += add->tv_sec;
	d->tv_usec += add->tv_usec;
	if(d->tv_usec > 1000000) {
		d->tv_usec -= 1000000;
		d->tv_sec++;
	}
#endif
}

void probe_start(char* ips)
{
	char* next;
	/* spawn a probe for every IP address in the list */
	while(*ips == ' ')
		ips++;
	while( *ips && (next=strchr(ips, ' ')) != NULL) {
		*next++ = 0;
		probe_spawn(ips);
		ips = next;
	}
	/* TODO: if no resulting probes, check result now */
}

void probe_delete(struct probe_ip* p)
{
	if(!p) return;
	free(p->name);
	free(p->reason);
	outq_delete(p->ds_c);
	outq_delete(p->dnskey_c);
	free(p);
}

static const char*
get_random_dest(void)
{
	const char* choices[] = { "se.", "uk.", "nl.", "de." };
	return choices[ ldns_get_random() %4 ];
}

/** outq is done, NULL reason for success */
static void
outq_done(struct outq* outq, const char* reason)
{
	struct probe_ip* p = outq->probe;
	const char* in = NULL;
	if(p->ds_c == outq) {
		p->ds_c = NULL;
		in = "DS";
	} else {
		p->dnskey_c = NULL;
		in = "DNSKEY";
	}
	outq_delete(outq);
	probe_partial_done(p, in, reason);
}

/** test if type is present in returned packet */
static int
check_type_in_answer(ldns_pkt* p, int t)
{
	ldns_rr_list *l = ldns_pkt_rr_list_by_type(p, t, LDNS_SECTION_ANSWER);
	if(!l) {
		return 0;
	}
	ldns_rr_list_deep_free(l);
	return 1;
}

static void
outq_check_packet(struct outq* outq, uint8_t* wire, size_t len)
{
	char reason[512];
	ldns_pkt *p = NULL;
	ldns_status s;
	if(!LDNS_QR_WIRE(wire)) {
		outq_done(outq, "reply without QR flag");
		return;
	}
	if(LDNS_TC_WIRE(wire)) {
		/* start TCP query and wait for it */
		verbose(VERB_ALGO, "%s: TC flag, switching to TCP",
			outq->probe->name);
		outq_send_tcp(outq);
		return;
	}
	if( (s=ldns_wire2pkt(&p, wire, len)) != LDNS_STATUS_OK) {
		snprintf(reason, sizeof(reason), "cannot disassemble reply: %s",
			ldns_get_errorstr_by_id(s));
		outq_done(outq, reason);
		return;
	}
	if(!p) {
		outq_done(outq, "out of memory");
		return;
	}

	/* does DNS work? */
	if(ldns_pkt_get_rcode(p) != LDNS_RCODE_NOERROR) {
		char* r = ldns_pkt_rcode2str(ldns_pkt_get_rcode(p));
		snprintf(reason, sizeof(reason), "no answer, %s\n",
			r?r:"(out of memory)");
		outq_done(outq, reason);
		LDNS_FREE(r);
		ldns_pkt_free(p);
		return;
	}

	/* test EDNS0 presence, of OPT record */
	/* LDNS forgets during pkt parse, but we test the ARCOUNT;
 	 * 0 additionals means no EDNS(on the wire), and after parsing the
 	 * same additional RRs as before means no EDNS OPT */
	if(LDNS_ARCOUNT(wire) == 0 ||
		ldns_pkt_arcount(p) == LDNS_ARCOUNT(wire)) {
		outq_done(outq, "no EDNS");
		ldns_pkt_free(p);
		return;
	}

	/* test if the type, RRSIG present */
	if(!check_type_in_answer(p, outq->qtype)) {
		char* r = ldns_rr_type2str(outq->qtype);
		snprintf(reason, sizeof(reason),
			"no %s in reply", r?r:"DNSSEC-RRTYPE");
		outq_done(outq, reason);
		LDNS_FREE(r);
		ldns_pkt_free(p);
		return;
	}
	if(!check_type_in_answer(p, LDNS_RR_TYPE_RRSIG)) {
		outq_done(outq, "no RRSIGs in reply");
		ldns_pkt_free(p);
		return;
	}

	outq_done(outq, NULL);
	ldns_pkt_free(p);
}

int outq_handle_udp(struct comm_point* c, void* my_arg, int error,
	struct comm_reply *reply_info)
{
	struct outq* outq = (struct outq*)my_arg;
	uint8_t* wire = ldns_buffer_begin(c->buffer);
	size_t len = ldns_buffer_limit(c->buffer);
	if(error != NETEVENT_NOERROR) {
		verbose(VERB_ALGO, "udp receive error");
		return 0;
	}
	if(sockaddr_cmp(&outq->addr, outq->addrlen, &reply_info->addr,
		reply_info->addrlen) != 0) {
		/* from wrong source, keep listening for the real one */
		log_addr(VERB_ALGO, "reply from wrong source",
			&reply_info->addr, reply_info->addrlen);
		return 0;
	}
	/* quick sanity check */
	if(len < LDNS_HEADER_SIZE || LDNS_ID_WIRE(wire) != outq->qid) {
		/* wait for the real reply */
		verbose(VERB_ALGO, "ignored bad reply (tooshort or wrong qid)");
		return 0;
	}
	outq_check_packet(outq, wire, len);
	return 0;
}

static int
create_probe_query(struct outq* outq, ldns_buffer* buffer)
{
	ldns_pkt* pkt = NULL;
	ldns_status status = ldns_pkt_query_new_frm_str(&pkt, outq->qname,
		outq->qtype, LDNS_RR_CLASS_IN,
		(uint16_t)(outq->recurse?LDNS_RD|LDNS_CD:0));
	if(status != LDNS_STATUS_OK) {
		log_err("could not pkt_query_new %s",
			ldns_get_errorstr_by_id(status));
		return 0;
	}
	ldns_pkt_set_edns_do(pkt, 1);
	ldns_pkt_set_edns_udp_size(pkt, 4096);
	outq->qid = (uint16_t)ldns_get_random();
	ldns_pkt_set_id(pkt, outq->qid);
	ldns_buffer_clear(buffer);
	status = ldns_pkt2buffer_wire(buffer, pkt);
	if(status != LDNS_STATUS_OK) {
		log_err("could not host2wire packet %s",
			ldns_get_errorstr_by_id(status));
		ldns_pkt_free(pkt);
		return 0;
	}
	ldns_pkt_free(pkt);
	return 1;
}

static struct outq*
outq_create(const char* ip, int tp, const char* domain, int recurse,
	struct probe_ip* p)
{
	int fd;
	struct outq* outq = (struct outq*)calloc(1, sizeof(*outq));
	/* open UDP socket */
	if(!outq) {
		log_err("out of memory");
		return NULL;
	}
	outq->qname = domain;
	outq->probe = p;
	outq->qtype = tp;
	outq->recurse = recurse;

	if(!ipstrtoaddr(ip, DNS_PORT, &outq->addr, &outq->addrlen)) {
		log_err("could not parse ip %s", ip);
		free(outq);
		return NULL;
	}
	fd = socket(strchr(ip, ':')?PF_INET6:PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if(fd == -1) {
		log_err("socket %s udp: %s", strchr(ip, ':')?"ip6":"ip4",
			strerror(errno));
		free(outq);
		return NULL;
	}
	outq->c = comm_point_create_udp(global_svr->base, fd,
		global_svr->udp_buffer, &outq_handle_udp, outq);
	if(!outq->c) {
#ifndef USE_WINSOCK
		close(fd);
#else
		closesocket(fd);
#endif
		free(outq);
		return NULL;
	}
	/* set timeout on commpoint */
	outq->timeout = QUERY_START_TIMEOUT; /* msec */
	outq->timer = comm_timer_create(global_svr->base, &outq_timeout, outq);
	if(!outq->timer) {
		log_err("cannot create timer");
		outq_delete(outq);
		return NULL;
	}
	if(!outq_settimeout_and_send(outq)) {
		outq_delete(outq);
		return NULL;
	}
	return outq;
}

static void outq_delete(struct outq* outq)
{
	if(!outq) return;
	comm_timer_delete(outq->timer);
	comm_point_delete(outq->c);
	free(outq);
}

static void outq_settimer(struct outq* outq)
{
	struct timeval tv, now;
	/* add timeofday */
	tv.tv_sec = outq->timeout/1000;
	tv.tv_usec = (outq->timeout%1000)*1000;
	gettimeofday(&now, NULL);
	timeval_add(&tv, &now);
	comm_timer_set(outq->timer, &tv);
}

static int outq_settimeout_and_send(struct outq* outq)
{
	ldns_buffer* udpbuf = global_svr->udp_buffer;
	outq_settimer(outq);

	/* create and send a message over the fd */
	if(!create_probe_query(outq, udpbuf)) {
		log_err("cannot create probe query");
		return 0;
	}
	/* send it */
	if(!comm_point_send_udp_msg(outq->c, udpbuf,
		(struct sockaddr*)&outq->addr, outq->addrlen)) {
		log_err("could not UDP send to ip %s", outq->probe->name);
		return 0;
	}
	return 1;
}

void outq_timeout(void* arg)
{
	struct outq* outq = (struct outq*)arg;
	verbose(VERB_ALGO, "%s: UDP timeout after %d msec",
		outq->probe->name, outq->timeout);
	if(outq->timeout > QUERY_END_TIMEOUT) {
		/* too many timeouts */
		outq_done(outq, "timeout");
		return;
	}
	/* resend */
	outq->timeout *= 2;
	if(!outq_settimeout_and_send(outq)) {
		outq_done(outq, "could not resend after timeout");
		return;
	}
}

/** use next free buffer to service a tcp query */ 
static int 
outq_tcp_take_into_use(struct outq* outq) 
{ 
	int s;
	/* open socket */
#ifdef INET6
	if(strchr(outq->probe->name, ':'))
		s = socket(PF_INET6, SOCK_STREAM, IPPROTO_TCP);
	else
#endif
		s = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(s == -1) {
#ifndef USE_WINSOCK
		log_err("outgoing tcp: socket: %s", strerror(errno));
#else
		log_err("outgoing tcp: socket: %s",
			wsa_strerror(WSAGetLastError()));
#endif
		log_addr(VERB_QUERY, "failed address",
			&outq->addr, outq->addrlen);
		return 0;
	}

	fd_set_nonblock(s);
	if(connect(s, (struct sockaddr*)&outq->addr, outq->addrlen) == -1) {
#ifndef USE_WINSOCK
#ifdef EINPROGRESS
		if(errno != EINPROGRESS) {
#else
		if(1) {
#endif
			log_err("outgoing tcp: connect: %s", strerror(errno));
			close(s);
#else /* USE_WINSOCK */
		if(WSAGetLastError() != WSAEINPROGRESS &&
			WSAGetLastError() != WSAEWOULDBLOCK) {
			closesocket(s);
#endif
			log_addr(VERB_OPS, "failed address",
				&outq->addr, outq->addrlen);
			return 0;
		}
	}
	outq->c->repinfo.addrlen = outq->addrlen;
	memcpy(&outq->c->repinfo.addr, &outq->addr, outq->addrlen);
	outq->c->tcp_is_reading = 0;
	outq->c->tcp_byte_count = 0;
	comm_point_start_listening(outq->c, s, -1);
	return 1;
}

static void outq_send_tcp(struct outq* outq)
{
	/* send outq over tcp, stop UDP in progress (if any) */
	if(outq->c) comm_point_delete(outq->c);
	outq->timeout = QUERY_TCP_TIMEOUT;
	outq->on_tcp = 1;
	outq->qid = (uint16_t)ldns_get_random();
	outq->c = comm_point_create_tcp_out(global_svr->base, 65553,
		outq_handle_tcp, outq);
	if(!create_probe_query(outq, outq->c->buffer)) {
		outq_done(outq, "cannot create TCP probe query");
		return;
	}
	if(!outq_tcp_take_into_use(outq)) {
		outq_done(outq, "cannot send TCP probe query");
		return;
	}
	outq_settimer(outq);
}

int outq_handle_tcp(struct comm_point* c, void* my_arg, int error,
	struct comm_reply* ATTR_UNUSED(reply_info))
{
	struct outq* outq = (struct outq*)my_arg;
	uint8_t* wire = ldns_buffer_begin(c->buffer);
	size_t len = ldns_buffer_limit(c->buffer);
	if(error != NETEVENT_NOERROR) {
		if(error == NETEVENT_CLOSED)
			outq_done(outq, "TCP connection failure");
		else	outq_done(outq, "TCP receive error");
		return 0;
	}
	/* quick sanity check */
	if(len < LDNS_HEADER_SIZE) {
		outq_done(outq, "TCP reply with short header");
		return 0;
	}
	if(LDNS_ID_WIRE(wire) != outq->qid) {
		outq_done(outq, "TCP reply with wrong ID");
		return 0;
	}
	outq_check_packet(outq, wire, len);
	return 0;
}

static void probe_spawn(char* ip)
{
	const char* dest;
	struct probe_ip* p = (struct probe_ip*)calloc(1, sizeof(*p));
	/* create a probe for this IP */
	if(!p) {
		log_err("out of memory");
		return;
	}
	/* create probe structure and register it */
	p->name = strdup(ip);
	if(!p->name) {
		free(p);
		log_err("out of memory");
		return;
	}

	/* send the queries */
	dest = get_random_dest();
	verbose(VERB_ALGO, "spawn probe for %s (for %s)", p->name, dest);

	/* send the probe queries and wait for reply */
	p->dnskey_c = outq_create(p->name, LDNS_RR_TYPE_DNSKEY, ".", 1, p);
	p->ds_c = outq_create(p->name, LDNS_RR_TYPE_DS, dest, 1, p);
	if(!p->ds_c || !p->dnskey_c) {
		log_err("could not send queries for probe");
		probe_delete(p);
		return;
	}

	/* put it in the svr list */
	p->next = global_svr->probes;
	global_svr->probes = p;
}

/** see if probe totally done or we have to wait more */
static void
probe_partial_done(struct probe_ip* p, const char* in, const char* reason)
{
	if(!reason && (p->ds_c || p->dnskey_c)) {
		/* this one success but wait for the other one */
		verbose(VERB_ALGO, "probe %s: %s completed successfully",
			p->name, in);
		return;
	}
	if(reason) {
		verbose(VERB_ALGO, "probe %s: %s failed: %s",
			p->name, in, reason);
		/* stop other probe (if any), it failed */
		outq_delete(p->ds_c);
		p->ds_c = NULL;
		outq_delete(p->dnskey_c);
		p->dnskey_c = NULL;
		/* note failure */
		p->reason = strdup(reason);
		p->works = 0;
	} else {
		verbose(VERB_ALGO, "probe %s: %s completed successfully",
			p->name, in);
		p->works = 1;
	}

	p->finished = 1;
	probe_done(p);
}

/* once a probe completes, do this:
 * if this probe succeeds and it is the first to do so, set unbound_fwd.
 * if all probes are done and have successes, set unbound_fwd.
 * if all probes failed DNSSEC, spawn a probe for DNS-direct.
 * if all probes failed and dns-direct failed, we fail.
 * if all probes failed and dns-direct works, set unbound_fwd.
 *
 * p is the probe that is done now.
 */
static void
probe_done(struct probe_ip* p)
{
	if(p->works) {
	}
}
