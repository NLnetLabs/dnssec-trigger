/*
 * update.c - dnssec-trigger update
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
 * This file contains the implementation to check and download the update
 */
#include "config.h"
#include "update.h"
#include "probe.h"
#include "http.h"
#include "netevent.h"
#include "log.h"
#include "svr.h"
#include <ldns/ldns.h>

struct selfupdate* selfupdate_create(struct svr* svr, struct cfg* cfg)
{
	struct selfupdate* se = (struct selfupdate*)calloc(1, sizeof(*se));
	if(!se) {
		log_err("out of memory");
		return NULL;
	}
	se->svr = svr;
	se->cfg = cfg;
	svr->update_desired = 1;
	se->timer = comm_timer_create(svr->base, selfupdate_timeout, se);
	if(!se->timer) {
		log_err("out of memory");
		free(se);
		return NULL;
	}
	return se;
}

/** zero and init */
static void selfupdate_init(struct selfupdate* se)
{
	se->update_available = 0;
	se->user_replied = 0;
	se->user_okay = 0;
	se->file_available = 0;

	outq_delete(se->txt_query);
	se->txt_query = NULL;
	free(se->version_available);
	se->version_available = NULL;
	free(se->hash);
	se->hash = NULL;

	outq_delete(se->addr_4);
	se->addr_4 = NULL;
	outq_delete(se->addr_6);
	se->addr_6 = NULL;
	http_get_delete(se->download_http4);
	se->download_http4 = NULL;
	http_get_delete(se->download_http6);
	se->download_http6 = NULL;
	free(se->download_file);
	se->download_file = NULL;
}

void selfupdate_delete(struct selfupdate* se)
{
	if(!se)
		return;
	selfupdate_init(se);
	comm_timer_delete(se->timer);
	free(se);
}

/* when timer done, set update-desired again */
void selfupdate_timeout(void* arg)
{
	struct selfupdate* se = (struct selfupdate*)arg;
	/* this instructs the server to call the selfupdate_start when
	 * dnssec becomes available */
	se->svr->update_desired = 1;
	/* if DNSSEC available now, do so now */
	svr_check_update(se->svr);
}

/** set retry timer after a failure */
static void
selfupdate_start_retry_timer(struct selfupdate* se)
{
	struct timeval tv;
	tv.tv_sec = SELFUPDATE_RETRY;
	tv.tv_usec = 0;
	comm_timer_set(se->timer, &tv);
}

/** set 24h timer after success but no update needed */
static void
selfupdate_start_next_timer(struct selfupdate* se)
{
	struct timeval tv;
	tv.tv_sec = SELFUPDATE_NEXT_CHECK;
	tv.tv_usec = 0;
	comm_timer_set(se->timer, &tv);
}

void selfupdate_start(struct selfupdate* se)
{
	char* domain = NULL;
	char* server = "127.0.0.1";
	/* DEBUG */
	server = "213.154.224.23";
	/* do not start us again, if it fails we turn desired back on. */
	if(!se->svr->update_desired) {
		/* robust check for double start */
		return;
	}
	se->svr->update_desired = 0;
	verbose(VERB_ALGO, "start check for software update");

	/* zero some state */
	selfupdate_init(se);

	/* start lookup of the domain name with version string and hash */
#ifdef USE_WINSOCK
	domain = "win.version.dnssec-trigger.nlnetlabs.nl";
#elif defined(HOOKS_OSX)
	domain = "osx.version.dnssec-trigger.nlnetlabs.nl";
#else
	domain = "src.version.dnssec-trigger.nlnetlabs.nl";
#endif
	log_info("fetch domain %s TXT", domain);

	/* setup TXT query, DO to get AD flag, no CD flag we want to check it */
	se->txt_query = outq_create(server, LDNS_RR_TYPE_TXT, domain,
		1, NULL, 0, 0, DNS_PORT, 1, 0);
	if(!se->txt_query) {
		log_err("out of memory, cannot make version txt query");
		selfupdate_start_retry_timer(se);
		return;
	}
}

/** parse the TXT record into version and hash */
static int selfupdate_parse_rr(struct selfupdate* se, ldns_rr* txt)
{
	char* hashstr;

	/* free old strings (if necessary) */
	free(se->version_available);
	se->version_available = NULL;
	free(se->hash);
	se->hash = NULL;
	se->hashlen = 0;

	if(ldns_rr_get_type(txt) != LDNS_RR_TYPE_TXT) {
		log_err("selfupdate txt record wrong RR type");
		return 0;
	}
	if(ldns_rr_rd_count(txt) < 2) {
		log_err("selfupdate txt record has wrong rd count");
		return 0;
	}

	se->version_available = ldns_rdf2str(ldns_rr_rdf(txt, 0));
	if(!se->version_available) {
		log_err("out of memory");
		return 0;
	}
	hashstr = ldns_rdf2str(ldns_rr_rdf(txt, 1));
	if(!hashstr) {
		log_err("out of memory");
		return 0;
	}

	/* parse the hash string */
	se->hashlen = strlen(hashstr)/2;
	if(se->hashlen == 0 || se->hashlen > 8192) {
		log_err("selfupdate parse rr bad hash length");
		free(hashstr);
		return 0;
	}
	se->hash = (uint8_t*)calloc(1, se->hashlen);
	if(ldns_hexstring_to_data(se->hash, hashstr) != (int)se->hashlen) {
		log_err("selfupdate failed to parse hash");
		free(hashstr);
		return 0;
	}
	verbose(VERB_OPS, "version check %s with hash %s",
		se->version_available, hashstr);
	free(hashstr);

	return 1;
}

/** start HTTP fetch of newer version */
static int
selfupdate_start_http_fetch(struct selfupdate* se)
{
	char* server = "127.0.0.1";
	char* domain = "www.nlnetlabs.nl";
	/* get ip4 and ip6 simultaneously, with addr lookup and http_get */
	se->addr_4 = outq_create(server, LDNS_RR_TYPE_A, domain, 1, NULL,
		0, 0, DNS_PORT, 1, 0);
	se->addr_6 = outq_create(server, LDNS_RR_TYPE_AAAA, domain, 1, NULL,
		0, 0, DNS_PORT, 1, 0);
	if(!se->addr_4 && !se->addr_6) {
		log_info("failed to create address lookups for download");
		return 0;
	}
	/* one of the address lookups works, so keep going */
	return 1;
}

/** see if version x is newer than y */
int
version_is_newer(const char* x, const char* y)
{
	const char* xat = x, *yat = y;
	/* version in NLnetLabs format:
	 * 1.2.3  (or 1.2.3.4)
	 * 1.2 is newer than 1.0
	 * 1.2.3 is newer than 1.2
	 * 1.2.3rc1   (for release candidates, 1.2.3 is better)
	 * 1.2.3_20120101 (for snapshots, with date, full 1.2.3 is better) */
	/* returns true if cannot determine and it is different */

	if(x[0] == 0)
		return 0; /* the empty version is no fun */

	/* for the part before the rc or _, compare the numbers every dot */
	while(xat[0] && yat[0]) {
		char* xend, *yend;
		long xnr = strtol(xat, &xend, 10);
		long ynr = strtol(yat, &yend, 10);

		/* difference at this point */
		if(xnr != ynr) {
			return (xnr > ynr);
		}
		xat = xend;
		yat = yend;
		if(xat[0] != '.') break;
		if(yat[0] != '.') break;
		xat++;
		yat++;
	}
	/* one is longer than the other? */
	if(xat[0] == 0 && yat[0] == 0)
		return 0; /* equal */
	if(xat[0] == '.')
		return 1; /* x=1.2.3 y=1.2 and x is newer */
	if(yat[0] == '.')
		return 0; /* x=1.2 y=1.2.3, and thus not newer */
	if(xat[0] == 0 && yat[0] != 0)
		return 1; /* x=1.2 y=1.2[rcorsnap] and thus x is newer */
	if(xat[0] != 0 && yat[0] == 0)
		return 0; /* x=1.2[rcorsnap] y=1.2 and thus x is not newer */
	
	if(strncmp(xat, "rc", 2)==0 && strncmp(yat, "rc", 2)==0) {
		/* compare rc versions */
		char* xend, *yend;
		long xrc = strtol(xat+2, &xend, 10);
		long yrc = strtol(yat+2, &yend, 10);
		/* check that it ends correctly, otherwise it is unknown */
		if(xend[0]==0 && yend[0]==0)
			return (xrc > yrc);
	} else if(xat[0]=='_' && yat[0]=='_') {
		/* compare snapshots 20110304, 20120506 and so on */
		char* xend, *yend;
		long xsnap = strtol(xat+1, &xend, 10);
		long ysnap = strtol(yat+1, &yend, 10);
		/* check that it ends correctly, otherwise it is unknown */
		if(xend[0]==0 && yend[0]==0)
			return (xsnap > ysnap);
	}

	/* not a clue how to compare, such as rc with snapshot, if its
	 * different you want to update */
	if(strcmp(xat, yat) != 0)
		return 1;
	return 0;
}

/* 
 * The TXT query is done.
 */
static void selfupdate_outq_done_txt(struct selfupdate* se, struct outq* outq,
	ldns_pkt* pkt, const char* reason)
{
	ldns_rr_list* txt;
	verbose(VERB_ALGO, "selfupdate %s done: %s", outq->qname,
		reason?reason:"success");
	if(reason || !pkt) {
		/* it failed */
		ldns_pkt_free(pkt); /* in case there is a packet */
		selfupdate_start_retry_timer(se);
		return;
	}
	/* check AD flag */
	if(!ldns_pkt_ad(pkt)) {
		log_err("selfupdate TXT without AD flag encountered, skip");
		ldns_pkt_free(pkt);
		selfupdate_start_retry_timer(se);
		return;
	}

	/* get TXT record */
	txt = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_TXT,
		LDNS_SECTION_ANSWER);
	if(!txt || ldns_rr_list_rr_count(txt) == 0) {
		log_err("selfupdate answer has AD flag, but no TXT");
		ldns_rr_list_deep_free(txt);
		ldns_pkt_free(pkt);
		selfupdate_start_retry_timer(se);
		return;
	}

	/* parse version and hash from it */
	if(!selfupdate_parse_rr(se, ldns_rr_list_rr(txt, 0))) {
		log_err("cannot parse selfupdate TXT rr, skip");
		ldns_rr_list_deep_free(txt);
		ldns_pkt_free(pkt);
		selfupdate_start_retry_timer(se);
		return;
	}

	/* update the time */
	se->last_check = time(NULL);

	ldns_rr_list_deep_free(txt);
	ldns_pkt_free(pkt);

	/* see what we need to do now */
	if(version_is_newer(se->version_available, PACKAGE_VERSION)) {
		/* start http fetch */
		verbose(VERB_OPS, "version %s available, starting download",
			se->version_available);
		if(!selfupdate_start_http_fetch(se)) {
			log_err("selfupdate cannot start http fetch");
			selfupdate_start_retry_timer(se);
			return;
		}
	} else {
		selfupdate_start_next_timer(se);
	}
}

/* 
 * The addr (A, AAAA) query is done.
 */
static void selfupdate_outq_done_addr(struct selfupdate* se, struct outq* outq,
	ldns_pkt* pkt, const char* reason)
{
	ldns_rr_list* addr;
	verbose(VERB_ALGO, "selfupdate addr%s %s done: %s", 
		outq->qtype==LDNS_RR_TYPE_A?"4":"6",
		outq->qname, reason?reason:"success");
	if(reason || !pkt) {
	failed:
		/* it failed */
		ldns_pkt_free(pkt); /* in case there is a packet */
		/* see if the other query is active */
		if(outq==se->addr_4 && se->addr_6) {
			outq_delete(outq);
			se->addr_4 = NULL;
		} else if(outq==se->addr_6 && se->addr_4) {
			outq_delete(outq);
			se->addr_6 = NULL;
		} else {
			selfupdate_start_retry_timer(se);
		}
		return;
	}
	/* check AD flag */
	if(!ldns_pkt_ad(pkt)) {
		log_err("selfupdate addr without AD flag encountered, skip");
		goto failed;
	}

	/* get addresses */
	addr = ldns_pkt_rr_list_by_type(pkt, outq->qtype, LDNS_SECTION_ANSWER);
	if(!addr || ldns_rr_list_rr_count(addr) == 0) {
		log_err("selfupdate answer has AD flag, but no TXT");
		ldns_rr_list_deep_free(addr);
		goto failed;
	}
	ldns_rr_list_deep_free(addr);
	ldns_pkt_free(pkt);
	/* TODO */
}


void selfupdate_outq_done(struct selfupdate* se, struct outq* outq,
	ldns_pkt* pkt, const char* reason)
{
	if(se->txt_query == outq)
		selfupdate_outq_done_txt(se, outq, pkt, reason);
	else if(se->addr_4 == outq || se->addr_6 == outq)
		selfupdate_outq_done_addr(se, outq, pkt, reason);
	else {
		log_err("internal error: selfupdate unknown outq? leaked");
		/* and ignore this to continue ... */
	}
}

void selfupdate_userokay(struct selfupdate* se, int okay)
{
	/* is the user OK ? */
	/* if not, note so we do not ask him again for 24h or next start */
	se->user_replied = 1;
	se->user_okay = okay;

	/* TODO if OK run installer (fork,exec because it updates this one) */
}

