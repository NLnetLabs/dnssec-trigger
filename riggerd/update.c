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
#include "riggerd/update.h"
#include "riggerd/probe.h"
#include "riggerd/http.h"
#include "riggerd/netevent.h"
#include "riggerd/log.h"

struct selfupdate* selfupdate_create(struct cfg* cfg)
{
	struct selfupdate* se = (struct selfupdate*)calloc(1, sizeof(*se));
	if(!se) {
		log_err("out of memory");
		return NULL;
	}
	se->cfg = cfg;
	/* TODO: set svr that we desire to be updated */
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
	http_get_delete(se->download_http);
	se->download_http = NULL;
	free(se->download_file);
	se->download_file = NULL;
}

void selfupdate_delete(struct selfupdate* se)
{
	if(!se)
		return;
	selfupdate_init(se);
	comm_timer_delete(se->retry);
	free(se);
}

void selfupdate_start(struct selfupdate* se)
{
	char* domain = NULL;
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

	/* TODO */
	/* se->txt_record */
}

void selfupdate_userokay(struct selfupdate* se, int okay)
{
	/* is the user OK ? */
	/* if not, note so we do not ask him again for 24h or next start */
	se->user_replied = 1;
	se->user_okay = okay;

	/* TODO if OK run installer (fork,exec because it updates this one) */
}
