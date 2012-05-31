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
#include "cfg.h"
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

/** delete the temporary file */
static void
selfupdate_delete_file(struct selfupdate* se)
{
	if(se->download_file) {
		(void)unlink(se->download_file);
		free(se->download_file);
		se->download_file = NULL;
	}
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
	ldns_rr_list_deep_free(se->addr_list_4);
	se->addr_list_4 = NULL;
	ldns_rr_list_deep_free(se->addr_list_6);
	se->addr_list_6 = NULL;
	http_get_delete(se->download_http4);
	se->download_http4 = NULL;
	http_get_delete(se->download_http6);
	se->download_http6 = NULL;

	selfupdate_delete_file(se);
	free(se->filename);
	se->filename = NULL;
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
	if(se->test_flag)
		domain = "win.test."DNSSECTRIGGER_DOMAIN;
	else	domain = "win.version."DNSSECTRIGGER_DOMAIN;
#elif defined(HOOKS_OSX)
	if(se->test_flag)
		domain = "osx.test."DNSSECTRIGGER_DOMAIN;
	else	domain = "osx.version."DNSSECTRIGGER_DOMAIN;
#else
	if(se->test_flag)
		domain = "src.test."DNSSECTRIGGER_DOMAIN;
	else	domain = "src.version."DNSSECTRIGGER_DOMAIN;
#endif
	verbose(VERB_ALGO, "fetch domain %s TXT", domain);

	/* setup TXT query, DO to get AD flag, no CD flag we want to check it */
	se->txt_query = outq_create(server, LDNS_RR_TYPE_TXT, domain,
		1, NULL, 0, 0, DNS_PORT, 1, 0);
	if(!se->txt_query) {
		log_err("out of memory, cannot make version txt query");
		selfupdate_start_retry_timer(se);
		return;
	}
}

/** remove "bla" to bla without quotes */
static void remove_quotes(char* str)
{
	size_t len;
	if(!str || str[0] != '"')
		return;
	len = strlen(str);
	if(len <= 1)
		return;
	/* remove endquote */
	if(str[len-1] == '"')
		str[len-1] = 0;
	/* remove startquote, end also EOS marker */
	memmove(str, str+1, len);
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
	remove_quotes(se->version_available);
	remove_quotes(hashstr);

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
	char* domain = DNSSECTRIGGER_DOWNLOAD_HOST;
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
		return 0; /* the empty version is no fun, do not prefer it */

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
	/* both xat and yat are not at eos */
	
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
	outq_delete(se->txt_query);
	se->txt_query = NULL;
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
		verbose(VERB_ALGO, "version %s available (it is not newer)",
			se->version_available);
		selfupdate_start_next_timer(se);
	}
}

/*
 * Initiate file download from http
 */
static int selfupdate_start_file_download(struct selfupdate* se,
	ldns_rr_list* addr)
{
	char url[256];
	char file[256];
	char* reason = NULL;
	struct http_get** handle;
	char* ipstr;
	ldns_rr* rr;
	file[0]=0;
	url[0]=0;

	/* pick the next address (randomly) */
	rr = http_pick_random_addr(addr);
	if(!rr || !ldns_rr_rdf(rr, 0)) {
		log_err("addr without rdata");
		ldns_rr_free(rr);
		return 0;
	}
	ipstr = ldns_rdf2str(ldns_rr_rdf(rr, 0));
	if(!ipstr) {
		log_err("out of memory");
		ldns_rr_free(rr);
		return 0;
	}

	/* create the URL */
#ifdef HOOKS_OSX
	snprintf(file, sizeof(file), "dnssectrigger-%s.dmg",
		se->version_available);
#elif defined(USE_WINSOCK)
	snprintf(file, sizeof(file), "dnssec_trigger_setup_%s.exe",
		se->version_available);
#else /* UNIX */
	snprintf(file, sizeof(file), "dnssec-trigger-%s.tar.gz",
		se->version_available);
#endif
	snprintf(url, sizeof(url), "http://%s%s%s%s",
		DNSSECTRIGGER_DOWNLOAD_HOST,
		DNSSECTRIGGER_DOWNLOAD_URLPRE,
		se->test_flag?"test/":"",
		file);
	if(!(se->filename=strdup(file))) {
		log_err("out of memory");
		ldns_rr_free(rr);
		free(ipstr);
		return 0;
	}

	/* start http_get */
	verbose(VERB_ALGO, "fetch %s from %s", url, ipstr);
	if(ldns_rr_get_type(rr) == LDNS_RR_TYPE_A)
		handle = &se->download_http4;
	else	handle = &se->download_http6;
	ldns_rr_free(rr);
	http_get_delete(*handle);
	*handle = http_get_create(url, se->svr->base, NULL);
	if(!*handle) {
		log_err("out of memory");
		http_get_delete(*handle);
		*handle = NULL;
		free(ipstr);
		return 0;
	}
	if(!http_get_fetch(*handle, ipstr, HTTP_PORT, &reason)) {
		log_err("update fetch failed: %s", reason?reason:"fail");
		http_get_delete(*handle);
		*handle = NULL;
		free(ipstr);
		return 0;
	}
	free(ipstr);
	return 1;
}

/** attempt next address in the selfupdate addr list */
static int
selfupdate_next_addr(struct selfupdate* se, ldns_rr_list* list)
{
	while(list && ldns_rr_list_rr_count(list)) {
		if(selfupdate_start_file_download(se, list)) {
			return 1;
		}
	}
	return 0;
}

/** check hash on data segment */
static int
software_hash_ok(struct selfupdate* se, struct http_get* hg)
{
	unsigned char download_hash[LDNS_SHA256_DIGEST_LENGTH];
	if(se->hashlen != LDNS_SHA256_DIGEST_LENGTH) {
		log_err("bad hash length from TXT record %d", (int)se->hashlen);
		return 0;
	}
	(void)ldns_sha256((unsigned char*)ldns_buffer_begin(hg->data),
		(unsigned int)ldns_buffer_limit(hg->data), download_hash);
	if(memcmp(download_hash, se->hash, se->hashlen) != 0) {
		log_err("hash mismatch:");
		log_hex("download", download_hash, sizeof(download_hash));
		log_hex("txtindns", se->hash, se->hashlen);
		return 0;
	}
	verbose(VERB_ALGO, "downloaded file sha256 is OK");
	return 1;
}

/** write to temporary file */
static int
selfupdate_write_file(struct selfupdate* se, struct http_get* hg)
{
	char buf[1024];
	FILE *out;
	/* get directory to store the file into */
#ifdef HOOKS_OSX
	char* dirname = UIDIR;
	char* slash="/";
#elif defined(USE_WINSOCK)
	char* dirname = w_lookup_reg_str("Software\\Unbound", "InstallLocation");
	char* slash="\\";
	if(!dirname) dirname = strdup(UIDIR);
	if(!dirname) { log_err("out of memory"); return 0; }
#else /* UNIX */
	char* dirname = "/tmp";
	char* slash="/";
#endif
	snprintf(buf, sizeof(buf), "%s%s%s", dirname, slash, se->filename);
	if(se->download_file)
		selfupdate_delete_file(se);
	se->download_file = strdup(buf);
	if(!se->download_file) {
		log_err("out of memory");
	fail:
		selfupdate_delete_file(se);
#ifdef USE_WINSOCK
		free(dirname);
#endif
		return 0;
	}
	out = fopen(se->download_file, "wb");
	if(!out) {
		log_err("cannot open file %s: %s", se->download_file,
			strerror(errno));
		goto fail;
	}
	if(!fwrite(ldns_buffer_begin(hg->data), 1, ldns_buffer_limit(hg->data),
		out)) {
		log_err("cannot write to file %s: %s", se->download_file,
			strerror(errno));
		goto fail;
	}
	fclose(out);
#ifdef USE_WINSOCK
	free(dirname);
#endif
	return 1;
}

static void stop_other_http(struct selfupdate* se, struct http_get* hg)
{
	if(hg == se->download_http4) {
		outq_delete(se->addr_6);
		se->addr_6 = NULL;
		ldns_rr_list_deep_free(se->addr_list_6);
		se->addr_list_6 = NULL;
		http_get_delete(se->download_http6);
		se->download_http6 = NULL;
	} else {
		outq_delete(se->addr_4);
		se->addr_4 = NULL;
		ldns_rr_list_deep_free(se->addr_list_4);
		se->addr_list_4 = NULL;
		http_get_delete(se->download_http4);
		se->download_http4 = NULL;
	}
}

void selfupdate_http_connected(struct selfupdate* se, struct http_get* hg)
{
	/* we do not need the other one any more (happy eyeballs) */
	stop_other_http(se, hg);
}

void
selfupdate_http_get_done(struct selfupdate* se, struct http_get* hg, 
	char* reason)
{
	ldns_rr_list* list = (hg == se->download_http4)?
		se->addr_list_4:se->addr_list_6;
	struct http_get** handle = (hg == se->download_http4)?
		&se->download_http4:&se->download_http6;
	verbose(VERB_ALGO, "selfupdate download done %s",
		reason?reason:"success");
	if(reason) {
	fail:
		/* try next address or fail completely */
		if(selfupdate_next_addr(se, list))
			return;
		/* we failed, see if the other is active or done */
		if(hg == se->download_http4 && se->addr_6) {
			outq_delete(se->addr_4);
			se->addr_4 = NULL;
		} else if(hg == se->download_http6 && se->addr_4) {
			outq_delete(se->addr_6);
			se->addr_6 = NULL;
		} else {
			selfupdate_start_retry_timer(se);
		}
		http_get_delete(*handle);
		*handle = NULL;
		return;
	}
	verbose(VERB_ALGO, "done with success");
	ldns_buffer_flip(hg->data);
	/* check data integrity */
	if(!software_hash_ok(se, hg)) {
		log_err("bad hash on download of %s from %s", hg->url, hg->dest);
		goto fail;
	}
	/* stop the other attempt (if any) */
	stop_other_http(se, hg);

	if(!selfupdate_write_file(se, hg)) {
		selfupdate_start_retry_timer(se);
		http_get_delete(*handle);
		*handle = NULL;
		return;
	}
	se->file_available = 1;

	http_get_delete(*handle);
	*handle = NULL;

	/* go and ask the user for permission */
	se->update_available = 1;
	/* signal panel and get return command */
	svr_signal_update(se->svr, se->version_available);
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
	if(outq->qtype == LDNS_RR_TYPE_A) {
		ldns_rr_list_deep_free(se->addr_list_4);
		se->addr_list_4 = addr;
	} else {
		ldns_rr_list_deep_free(se->addr_list_6);
		se->addr_list_6 = addr;
	}
	ldns_pkt_free(pkt);
	pkt = NULL;

	/* start the download of the file */
	if(!selfupdate_next_addr(se, addr)) {
		log_err("selfupdate could not initiate file download");
		goto failed;
	}
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
		log_info("reason: %s, outq %s %d %s %s %s",
			reason?reason:"null",
			outq->qname, (int)outq->qtype,
			outq->edns?"edns":"noedns",
			outq->cdflag?"cdflag":"nocdflag",
			outq->on_tcp?"tcp":"udp");
		/* and ignore this to continue ... */
	}
}

#ifdef HOOKS_OSX
/* fork and exec the script that opens the dmg and runs installer */
static void
osx_run_updater(char* filename)
{
	pid_t pid = fork();
	switch(pid) {
	default: /* main */
		return;
	case -1: /* error */
		log_err("cannot fork installscript: %s", strerror(errno));
		return;
	case 0: /* child */
		break;
	}
	/* run the install script */
	if(execl(LIBEXEC_DIR "/dnssec-trigger-setdns.sh", "install", filename,
		(char*)0) < 0) {
		log_err("cannot exec setdns install: %s", strerror(errno));
	}
	exit(1);
}
#endif /* HOOKS_OSX */

/** do the software update install (system specific) */
static void
selfupdate_do_install(struct selfupdate* se)
{
	if(!se) return;
	if(!se->update_available) return;
	if(!se->file_available || !se->download_file) return;
	verbose(VERB_OPS, "software update, install of %s", se->download_file);
	if(se->svr->cfg->noaction) {
		verbose(VERB_OPS, "noaction is true, no install action");
		return;
	}
#ifdef USE_WINSOCK
	/* fork and exec the installer that will stop this program and update*/
	/* Do not run updater from service, but from userspace, so that
	 * tray icon gets started correctly and so on, and reboot warn dialog*/
	/*win_run_updater(se->download_file);*/
	/* this stops the filename from being deleted when we exit,
	 * the installer deletes itself (with after reboot flag). */
	free(se->download_file);
	se->download_file = NULL;
	se->file_available = 0;
#elif defined(HOOKS_OSX)
	/* fork and exec installer */
	osx_run_updater(se->download_file);
	/* stops filename from deleted by this daemon on exit, since
	 * the postinstall makes us exit and the installer is deleted by
	 * the fork-exec-ed script */
	free(se->download_file);
	se->download_file = NULL;
	se->file_available = 0;
#else
	log_err("on unix, do not know how to install. tarball %s (is deleted"
		"on exit of the daemon)", se->download_file);
#endif
}

void selfupdate_userokay(struct selfupdate* se, int okay)
{
	if(!se)
		return;
	if(se->user_replied)
		return; /* already replied, this is a duplicate */
	/* is the user OK ? */
	/* if not, note so we do not ask him again for 24h or next start */
	se->user_replied = 1;
	se->user_okay = okay;

	/* if OK run installer (fork,exec because it updates this one) */
	if(se->user_okay) {
		selfupdate_do_install(se);
	}
}
