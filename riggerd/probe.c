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
#include "ubhook.h"
#include "reshook.h"
#include <ldns/ldns.h>

/* create probes for the ip addresses in the string */
static void probe_spawn(const char* ip, int recurse);
/* delete and stop outq */
static void outq_delete(struct outq* outq);
/* set timeout on outq and create UDP query and send it */
static int outq_settimeout_and_send(struct outq* outq);
/* send outq over tcp */
static void outq_send_tcp(struct outq* outq);
/* a query is done, check probe to see if failed, succeed or wait */
static void probe_partial_done(struct probe_ip* p, const char* in,
	const char* reason);
/* a probe is done (fail or success) see global progress */
static void probe_done(struct probe_ip* p);

void probe_start(char* ips)
{
	char* next;
	struct svr* svr = global_svr;
	if(svr->probes) {
		/* clear existing probe list */
		probe_list_delete(svr->probes);
		svr->probes = NULL;
		if(svr->num_probes_done < svr->num_probes) {
			verbose(VERB_QUERY, "probes cancelled due to fast "
				"net change"); 
		}
		svr->num_probes_done = 0;
		svr->num_probes = 0;
	}

	/* spawn a probe for every IP address in the list */
	svr->saw_first_working = 0;
	svr->saw_direct_work = 0;
	svr->probe_direct = 0;
	while(*ips == ' ')
		ips++;
	while(ips && *ips) {
		if((next = strchr(ips, ' ')) != NULL) {
			*next++ = 0;
			while(*next == ' ')
				next++;
		}
		probe_spawn(ips, 1);
		ips = next;
	}
	svr->num_probes_to_cache = svr->num_probes;
	/* (if no resulting probes), check result now */
	if(!svr->probes)
		probe_cache_done();
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

void probe_list_delete(struct probe_ip* list)
{
	struct probe_ip* p=list, *np;
	while(p) {
		np = p->next;
		probe_delete(p);
		p = np;
	}
}

/** get random signed TLD */
static const char*
get_random_dest(void)
{
	const char* choices[] = { "se.", "uk.", "nl.", "de." };
	return choices[ ldns_get_random() %4 ];
}

/** get random authority server */
static const char*
get_random_auth_ip4(void)
{
	/* list of root servers */
	const char* choices[] = {
		"198.41.0.4", /* a */
		"192.228.79.201", /* b */
		"192.33.4.12", /* c */
		"128.8.10.90", /* d */
		"192.203.230.10", /* e */
		"192.5.5.241", /* f */
		"192.112.36.4", /* g */
		"128.63.2.53", /* h */
		"192.36.148.17", /* i */
		"192.58.128.30", /* j */
		"193.0.14.129", /* k */
		"199.7.83.42", /* l */
		"202.12.27.33" /* m */
	};
	return choices[ ldns_get_random() % 13 ];
}

/** get random authority server */
static const char*
get_random_auth_ip6(void)
{
	/* list of root servers */
	const char* choices[] = {
		"2001:503:ba3e::2:30", /* a */
		"2001:500:2d::d", /* d */
		"2001:500:2f::f", /* f */
		"2001:500:1::803f:235", /* h */
		"2001:7fe::53", /* i */
		"2001:503:c27::2:30", /* j */
		"2001:7fd::1", /* k */
		"2001:500:3::42", /* l */
		"2001:dc3::35" /* m */
	};
	return choices[ ldns_get_random() % 9 ];
}

/** outq is done, NULL reason for success */
static void
outq_done(struct outq* outq, const char* reason)
{
	struct probe_ip* p = outq->probe;
	const char* in = NULL;
	if(p->ds_c == outq) {
		outq_delete(p->ds_c);
		p->ds_c = NULL;
		in = "DS";
	} else {
		outq_delete(p->dnskey_c);
		p->dnskey_c = NULL;
		in = "DNSKEY";
	}
	probe_partial_done(p, in, reason);
}

/** test if type is present in authority section of returned packet */
static int
check_type_in_authority(ldns_pkt* p, int t)
{
	ldns_rr_list *l = ldns_pkt_rr_list_by_type(p, t,
		LDNS_SECTION_AUTHORITY);
	if(!l) {
		return 0;
	}
	ldns_rr_list_deep_free(l);
	return 1;
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

/** test if the right denial (from parent) is in the returned packet */
static int
check_denial_in_answer(ldns_pkt* p, const char* dname)
{
	size_t i;
	ldns_rdf* d = ldns_dname_new_frm_str(dname);
	ldns_rr_list *l = ldns_pkt_rr_list_by_type(p, LDNS_RR_TYPE_SOA,
		LDNS_SECTION_AUTHORITY);
	if(!d) {
		ldns_rr_list_deep_free(l);
		return 0; /* robustness, the name should parse */
	}
	if(!l) {
		ldns_rdf_deep_free(d);
		return 0;
	}
	for(i=0; i<ldns_rr_list_rr_count(l); i++) {
		/* note that subdomain test is false if names are equal,
		 * the SOA must be from a parent server */
		if(ldns_dname_is_subdomain(d, ldns_rr_owner(ldns_rr_list_rr(
			l, i)))) {
			ldns_rr_list_deep_free(l);
			ldns_rdf_deep_free(d);
			return 1;
		}
	}
	ldns_rr_list_deep_free(l);
	ldns_rdf_deep_free(d);
	return 0;
}

static void
outq_check_packet(struct outq* outq, uint8_t* wire, size_t len)
{
	char reason[512];
	int rrsig_in_auth = 0;
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
		snprintf(reason, sizeof(reason), "no answer, %s",
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
	if(!check_type_in_answer(p, (int)outq->qtype)) {
		if(outq->qtype == LDNS_RR_TYPE_DS) {
			/* if type DS, and it is not present, it is OK if
			 * we get a proper denial from the parent with NSEC */
			if(!check_denial_in_answer(p, outq->qname)) {
				outq_done(outq, "no DS and no proper "
					"denial in reply");
				ldns_pkt_free(p);
				return;
			}
			if(!check_type_in_authority(p, LDNS_RR_TYPE_NSEC)) {
				outq_done(outq, "no NSEC in denial reply");
				ldns_pkt_free(p);
				return;
			}
			rrsig_in_auth = 1;
		} else {
			/* failed to find type */
			char* r = ldns_rr_type2str(outq->qtype);
			snprintf(reason, sizeof(reason),
				"no %s in reply", r?r:"DNSSEC-RRTYPE");
			outq_done(outq, reason);
			LDNS_FREE(r);
			ldns_pkt_free(p);
			return;
		}
	}
	if(rrsig_in_auth) {
		if(!check_type_in_authority(p, LDNS_RR_TYPE_RRSIG)) {
			outq_done(outq, "no RRSIGs in reply");
			ldns_pkt_free(p);
			return;
		}
	} else {
		if(!check_type_in_answer(p, LDNS_RR_TYPE_RRSIG)) {
			outq_done(outq, "no RRSIGs in reply");
			ldns_pkt_free(p);
			return;
		}
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
	if(len < LDNS_HEADER_SIZE || LDNS_ID_WIRE(wire) != outq->qid
		|| !LDNS_QR_WIRE(wire)) {
		verbose(VERB_ALGO, "%4.4x wire, qid %4.4x, qr %s",
			LDNS_ID_WIRE(wire), outq->qid,
			LDNS_QR_WIRE(wire)?"yes":"no");
		/* wait for the real reply */
		verbose(VERB_ALGO, "ignored bad reply (tooshort, wrong qid or noQR)");
		return 0;
	}
	comm_timer_disable(outq->timer);
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
	ldns_pkt_set_id(pkt, outq->qid);
	ldns_buffer_clear(buffer);
	status = ldns_pkt2buffer_wire(buffer, pkt);
	if(status != LDNS_STATUS_OK) {
		log_err("could not host2wire packet %s",
			ldns_get_errorstr_by_id(status));
		ldns_pkt_free(pkt);
		return 0;
	}
	ldns_buffer_flip(buffer);
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
	outq->qtype = (uint16_t)tp;
	outq->qid = (uint16_t)ldns_get_random();
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
	struct timeval tv;
	tv.tv_sec = outq->timeout/1000;
	tv.tv_usec = (outq->timeout%1000)*1000;
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
	verbose(VERB_ALGO, "%s %s: UDP timeout after %d msec",
		outq->probe->name,
		outq->qtype==LDNS_RR_TYPE_DNSKEY?"DNSKEY":"DS", outq->timeout);
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
	comm_timer_disable(outq->timer);
	outq_check_packet(outq, wire, len);
	return 0;
}

static int addr_is_localhost(const char* ip)
{
	struct sockaddr_storage addr;
	socklen_t len;
	struct sockaddr_storage lo;
	socklen_t lolen;
	/* unified print format for ipv4 addresses */
	if(strcmp(ip, "127.0.0.1") == 0)
		return 1;
	/* only for IPv6 do we need more tests */
	if(!strchr(ip, ':'))
		return 0;
	/* detect ::ffff:127.0.0.1 */
	if(strstr(ip, "127.0.0.1"))
		return 1;
	/* detect ::1 but there are many ways to denote that IPv6 */
	if(!ipstrtoaddr(ip, DNS_PORT, &addr, &len)) {
		return 0; /* it is not localhost, but unparseable */
	}
	if(!ipstrtoaddr("::1", DNS_PORT, &lo, &lolen)) {
		return 0; /* internal error or no IPv6 */
	}
	return (sockaddr_cmp_addr(&lo, lolen, &addr, len) == 0);
}

static void probe_spawn(const char* ip, int recurse)
{
	const char* dest;
	struct probe_ip* p = (struct probe_ip*)calloc(1, sizeof(*p));
	/* create a probe for this IP */
	if(!p) {
		log_err("out of memory");
		return;
	}
	/* make sure the IP address is not 127.0.0.1 or ::1, that would
	 * create a forward-loop for the resolver */
	if(addr_is_localhost(ip)) {
		free(p);
		verbose(VERB_ALGO, "skip localhost address %s", ip);
		return;
	}

	/* create probe structure and register it */
	p->to_auth = !recurse;
	p->name = strdup(ip);
	if(!p->name) {
		free(p);
		log_err("out of memory");
		return;
	}

	/* send the queries */
	dest = get_random_dest();
	verbose(VERB_ALGO, "probe %s %s (tld %s)",
		p->name, (recurse?"rec":"norec"), dest);

	/* send the probe queries and wait for reply */
	p->dnskey_c = outq_create(p->name, LDNS_RR_TYPE_DNSKEY, ".",
		recurse, p);
	p->ds_c = outq_create(p->name, LDNS_RR_TYPE_DS, dest, recurse, p);
	if(!p->ds_c || !p->dnskey_c) {
		log_err("could not send queries for probe");
		probe_delete(p);
		return;
	}

	/* put it in the svr list */
	p->next = global_svr->probes;
	global_svr->probes = p;
	global_svr->num_probes++;
}

/** start probes for direct DNS authority server connection */
static void probe_spawn_direct(void)
{
	int nump = global_svr->num_probes;
	/* try both IP4 and IP6, one that works is enough */
	verbose(VERB_ALGO, "probe authority servers");
	probe_spawn(get_random_auth_ip4(), 0);
	probe_spawn(get_random_auth_ip6(), 0);
	if(global_svr->num_probes == nump) {
		/* failed to create the probes */
		/* not a loop since svr->probe_direct is true */
		probe_cache_done();
	}
}

void probe_unsafe_test(void)
{
	verbose(VERB_OPS, "test unsafe probe combination started");
	probe_start("127.0.0.3");
	global_svr->probe_direct = 1;
	probe_spawn("127.0.0.4", 0);
}

/* stop unfininished probes and remove them */
static void stop_unfinished_probes(void)
{
	struct probe_ip* p, *prev = NULL, *np;
	for(p = global_svr->probes; p; p = np) {
		np = p->next;
		if(!p->finished) {
			if(prev) prev->next = p->next;
			else	global_svr->probes = p->next;
			verbose(VERB_ALGO, "stop %s: not needed", p->name);
			probe_delete(p);
		} else {
			prev = p;
		}
	}
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
		verbose(VERB_ALGO, "probe %s: failed: %s in %s",
			p->name, reason, in);
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
	global_svr->num_probes_done++;
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
	struct svr* svr = global_svr;
	if(p->works) {
		if(!svr->probe_direct && !svr->saw_first_working) {
			svr->saw_first_working = 1;
			if(!svr->forced_insecure) {
				probe_setup_cache(svr, p);
			}
		} else if(svr->probe_direct && !svr->saw_direct_work) {
			svr->saw_direct_work = 1;
			/* no need for wait for more done */
			stop_unfinished_probes();
			probe_cache_done();
			return;
		}
	}
	if(svr->num_probes_done < svr->num_probes) {
		/* continue to wait for the rest */
		return;
	}
	probe_cache_done();
}

/** setup to use cache */
void probe_setup_cache(struct svr* svr, struct probe_ip* p)
{
	svr->res_state = res_cache;
	if(svr->insecure_state) hook_resolv_flush(svr->cfg);
	svr->insecure_state = 0;
	/* send the working servers to unbound */
	if(p)
		hook_unbound_cache(svr->cfg, p->name);
	else	hook_unbound_cache_list(svr->cfg, svr->probes);
	/* set resolv.conf to 127.0.0.1 */
	hook_resolv_localhost(svr->cfg);
}

/** setup for auth (direct to authorities) */
void probe_setup_auth(struct svr* svr)
{
	svr->res_state = res_auth;
	if(svr->insecure_state) hook_resolv_flush(svr->cfg);
	svr->insecure_state = 0;
	hook_unbound_auth(svr->cfg);
	/* set resolv.conf to 127.0.0.1 */
	hook_resolv_localhost(svr->cfg);
}

/** setup to be disconnected */
void probe_setup_disconnected(struct svr* svr)
{
	svr->insecure_state = 0;
	svr->res_state = res_disconn;
	/* set unbound to go dark */
	hook_unbound_dark(svr->cfg);
	/* set resolver.conf to 127.0.0.1 (get rid of old
	 * settings that may be in there) */
	hook_resolv_localhost(svr->cfg);
}

/** setup for dark (no dnssec) */
void probe_setup_dark(struct svr* svr)
{
	/* DNSSEC failure, and there is some unsafe IPs */
	if(svr->res_state != res_dark)
		svr->insecure_state = 0; /* ask again */
	svr->res_state = res_dark;
	/* set unbound to dark */
	hook_unbound_dark(svr->cfg);
	/* see what the user wants */
	if(svr->insecure_state) {
		/* set resolv.conf to DHCP IP list */
		hook_resolv_iplist(svr->cfg, svr->probes);
	} else { /* set resolv.conf to 127.0.0.1 now,
		* the user may select insecure later */
		hook_resolv_localhost(svr->cfg);
	}
}

/** setup forced insecure (for hotspot signon) */
void probe_setup_hotspot_signon(struct svr* svr)
{
	svr->res_state = res_dark;
	svr->forced_insecure = 1;
	svr->insecure_state = 1;
	/* effectuate it */
	hook_unbound_dark(svr->cfg);
	hook_resolv_iplist(svr->cfg, svr->probes);
}

void
probe_cache_done(void)
{
	struct svr* svr = global_svr;
	if(!svr->probe_direct && !svr->saw_first_working) {
		/* no working server, probe the direct DNS */
		/* we wait until the other probes fail to not put
		 * traffic to the authority servers when a cache works */
		svr->probe_direct = 1;
		/* set flag first avoids loop in case spawn fails */
		probe_spawn_direct();
		return;
	}
	probe_all_done();
}

void
probe_all_done(void)
{
	struct svr* svr = global_svr;
	if(verbosity >= VERB_DETAIL) {
		struct probe_ip* p;
		for(p=svr->probes; p; p=p->next)
			verbose(VERB_DETAIL, "%s %s: %s %s", 
				p->to_auth?"authority":"cache", p->name,
				p->works?"OK":"error", p->reason?p->reason:"");
	}
	if(svr->forced_insecure) {
		verbose(VERB_OPS, "probe done: but still forced insecure");
		/* call it again, in case DHCP changes while hotspot-signon */
		probe_setup_hotspot_signon(svr);
	} else if(svr->probe_direct && svr->saw_direct_work) {
		/* set unbound to process directly */
		verbose(VERB_OPS, "probe done: DNSSEC to auth direct");
		probe_setup_auth(svr);
	} else if(svr->probe_direct && !svr->saw_direct_work) {
		/* if there are no cache IPs, then there is nothing else
		 * we can do, we are in offline mode, most likely. No DHCP,
		 * no network connectivity */
		if(svr->num_probes_to_cache == 0) {
			verbose(VERB_OPS, "probe done: disconnected");
			probe_setup_disconnected(svr);
		} else {
			verbose(VERB_OPS, "probe done: DNSSEC fails");
			probe_setup_dark(svr);
		}
	} else {
		verbose(VERB_OPS, "probe done: DNSSEC to cache");
		probe_setup_cache(svr, NULL);
	}
	svr->probetime = time(0);
	svr_send_results(svr);
}
