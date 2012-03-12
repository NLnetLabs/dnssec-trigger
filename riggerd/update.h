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

struct outq;
struct http_get;
struct cfg;
struct comm_timer;

/**
 * The update data
 */
struct selfupdate {
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

	/** query for TXT record with version and hash */
	struct outq* txt_query;
	/** the probed version (or NULL if not probed) as string */
	char* version_available;
	/** the hash of this installer version (or NULL if not probed) */
	uint8_t* hash;
	/** length of hash */
	size_t hashlen;

	/** http get operation that fetches the installer (or NULL if not) */
	struct http_get* download_http;
	/** filename with downloaded file (or NULL) */
	char* download_file;
	/** if we have downloaded to file and hash is okay
	 * we have to delete this file so it does not clog up the system */
	int file_available;

	/** timer that sets selfupdate_desired after 24h in svr */
	struct comm_timer* retry;
};

/** 24h retry time (in seconds) between version checks */
#define SELFUPDATE_RETRY (24*3600)

/** create new selfupdate structure (empty). */
struct selfupdate* selfupdate_create(struct cfg* cfg);
/** delete selfupdate structure */
void selfupdate_delete(struct selfupdate* se);

/** start selfupdate
 * We must be in a DNSSEC secure state. unbound at 127.0.0.1 must then
 * be pointed at this DNSSEC secureness and its AD flag is trusted.
 */
void selfupdate_start(struct selfupdate* se);

/** the user indicates his support for the update (or nonsupport) */
void selfupdate_userokay(struct selfupdate* se, int okay);

#endif /* UPDATE_H */
