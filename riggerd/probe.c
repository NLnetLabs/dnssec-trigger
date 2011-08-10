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

static void probe_spawn(char* ip);

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
}

static void probe_delete(struct probe_ip* p)
{
	if(!p) return;
	free(p->name);
	free(p->reason);
	comm_point_delete(p->ds_c);
	comm_point_delete(p->dnskey_c);
	free(p);
}

static const char*
get_random_dest(void)
{
	const char* choices[] = { "se.", "uk.", "nl.", "de." };
	return choices[ ldns_get_random() %4 ];
}

int probe_handle_ds(struct comm_point* c, void* my_arg, int error,
	struct comm_reply *reply_info)
{
}

int probe_handle_dnskey(struct comm_point* c, void* my_arg, int error,
	struct comm_reply *reply_info)
{
}

static struct comm_point*
send_query_to(const char* ip, int tp, const char* domain,
	comm_point_callback_t* cb, void* arg, int recurse)
{
	ldns_pkt* pkt = NULL;
	ldns_status status;
	struct comm_point* c;
	int fd;
	struct sockaddr_storage addr;
	socklen_t addrlen;
	ldns_buffer* udpbuf = global_svr->udp_buffer;
	/* TODO : open UDP socket */
	fd = -1;
	c = comm_point_create_udp(global_svr->base, fd, udpbuf, cb, arg);
	if(!c) {
#ifndef USE_WINSOCK
		close(fd);
#else
		closesocket(fd);
#endif
		return NULL;
	}
	/* TODO: set timeout on commpoint */
	/* create and send a message over the fd */
	status = ldns_pkt_query_new_frm_str(&pkt, domain, tp, LDNS_RR_CLASS_IN,
		recurse?LDNS_RD|LDNS_CD:0);
	if(status != LDNS_STATUS_OK) {
		log_err("could not create packet %s",
			ldns_get_errorstr_by_id(status));
		comm_point_delete(c);
		return NULL;
	}
	ldns_pkt_set_edns_do(pkt, 1);
	ldns_pkt_set_edns_udp_size(pkt, 4096);
	ldns_buffer_clear(udpbuf);
	status = ldns_pkt2buffer_wire(udpbuf, pkt);
	if(status != LDNS_STATUS_OK) {
		log_err("could not host2wire packet %s",
			ldns_get_errorstr_by_id(status));
		ldns_pkt_free(pkt);
		comm_point_delete(c);
		return NULL;
	}
	ldns_pkt_free(pkt);
	/* send it */
	if(!ipstrtoaddr(ip, DNS_PORT, &addr, &addrlen)) {
		log_err("could not parse ip %s", ip);
		comm_point_delete(c);
		return NULL;
	}
	if(!comm_point_send_udp_msg(c, udpbuf, (struct sockaddr*)&addr, addrlen)) {
		log_err("could not UDP send to ip %s", ip);
		comm_point_delete(c);
		return NULL;
	}
	return c;
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

	/* get random UDP ports and send the message and wait for reply */
	p->ds_c = send_query_to(p->name, LDNS_RR_TYPE_DS, dest,
		&probe_handle_ds, p, 1);
	p->dnskey_c = send_query_to(p->name, LDNS_RR_TYPE_DNSKEY, dest,
		&probe_handle_dnskey, p, 1);
	if(!p->ds_c || !p->dnskey_c) {
		log_err("could not send queries for probe");
		probe_delete(p);
		return;
	}

	/* TODO */
	/* put it in the svr list */
}

/* once a probe completes, do this:
 * if this probe succeeds and it is the first to do so, set unbound_fwd.
 * if all probes are done and have successes, set unbound_fwd.
 * if all probes failed DNSSEC, spawn a probe for DNS-direct.
 * if all probes failed and dns-direct failed, we fail.
 * if all probes failed and dns-direct works, set unbound_fwd.
 */
