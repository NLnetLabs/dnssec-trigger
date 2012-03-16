/*
 * update.h - dnssec-trigger update
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
 * This file contains the functions to run update check and download the update
 */

#ifndef UPDATE_H
#define UPDATE_H
#include <ldns/packet.h>
struct outq;
struct http_get;
struct svr;
struct cfg;
struct comm_timer;

/**
 * The update data
 */
struct selfupdate {
	/** the server */
	struct svr* svr;
	/** the config to use  (reference) */
	struct cfg* cfg;

	/** when was the last time the update was performed, if 0 never. 
	 * At this time the version check TXT returned successfully. */
	time_t last_check;
	/** we have to update (and ask the user) */
	int update_available;
	/** did the user reply to the question */
	int user_replied;
	/** did the user agree to install the update */
	int user_okay;
	/** if this flag is on update with the unstable test version 
	 * This is used to test the software update mechanism.
	 * Or to distribute test software to some participants.
	 */
	int test_flag;

	/** query for TXT record with version and hash */
	struct outq* txt_query;
	/** the probed version (or NULL if not probed) as string */
	char* version_available;
	/** the hash of this installer version (or NULL if not probed) */
	uint8_t* hash;
	/** length of hash */
	size_t hashlen;

	/** get address for http fetch, or NULL on its failure */
	struct outq* addr_4;
	struct outq* addr_6;
	/** the address list for downloads */
	ldns_rr_list* addr_list_4;
	ldns_rr_list* addr_list_6;
	/** http get operation that fetches the installer (or NULL if not) */
	struct http_get* download_http4;
	struct http_get* download_http6;
	/** filename with downloaded file (or NULL) */
	char* download_file;
	/** filename of the download url (no directory part) */
	char* filename;
	/** if we have downloaded to file and hash is okay
	 * we have to delete this file so it does not clog up the system */
	int file_available;

	/** timer that sets selfupdate_desired after 24h in svr */
	struct comm_timer* timer;
};

/** retry time (in seconds) between version checks */
#define SELFUPDATE_RETRY (2*3600)
/** 24h time (in seconds) between version checks */
#define SELFUPDATE_NEXT_CHECK (24*3600)
/** 
 * The dnssec trigger domain name (where the TXT records are)
 * TXT records at {win,src,osx}.{test,version}.ourdomain
 * with TXT "version" "sha256"
 */
#define DNSSECTRIGGER_DOMAIN "dnssec-trigger.nlnetlabs.nl"
/** the download site for new software updates. */
#define DNSSECTRIGGER_DOWNLOAD_HOST "www.nlnetlabs.nl"
/** the download URL for the software updates, the directory (start with /) */
#define DNSSECTRIGGER_DOWNLOAD_URLPRE "/downloads/dnssec-trigger/"

/** create new selfupdate structure (empty). */
struct selfupdate* selfupdate_create(struct svr* svr, struct cfg* cfg);
/** delete selfupdate structure */
void selfupdate_delete(struct selfupdate* se);

/** start selfupdate
 * We must be in a DNSSEC secure state. unbound at 127.0.0.1 must then
 * be pointed at this DNSSEC secureness and its AD flag is trusted.
 */
void selfupdate_start(struct selfupdate* se);

/** the user indicates his support for the update (or nonsupport) */
void selfupdate_userokay(struct selfupdate* se, int okay);

/** the outq query is done, error reason (or NULL if works) */
void selfupdate_outq_done(struct selfupdate* se, struct outq* outq,
	ldns_pkt* pkt, const char* reason);

/** see if version x is newer than y */
int version_is_newer(const char* x, const char* y);

/** timeout handler for selfupdate timer */
void selfupdate_timeout(void* arg);

/** routine called when http is done */
void selfupdate_http_get_done(struct selfupdate* se, struct http_get* hg, 
	char* reason);

#endif /* UPDATE_H */
