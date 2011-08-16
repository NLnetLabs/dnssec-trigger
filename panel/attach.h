/*
 * attach.h - dnssec-trigger acttachment from panel to daemon.
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
 * This file contains the code that attaches the panel to the daemon.
 */

#ifndef ATTACH_H
#define ATTACH_H
struct feed;
struct cfg;
#include <glib.h>
struct strlist;

/** attachment structure for the results read thread */
extern struct feed* feed;

/** structure for reading from the daemon */
struct feed {
	GMutex* lock;
	/* if connection with the daemon has been established. */
	int connected;
	/* non connection reason */
	char connect_reason[512];
	
	/* list of lines, last has status */
	struct strlist* results, *results_last;
	/* if we are in insecure mode - here to see if it has changed */
	int insecure_mode;

	/* config */
	struct cfg* cfg;
	/* ssl context with keys */
	SSL_CTX* ctx;
	/* ssl to read results from */
	SSL* ssl_read;
	/* ssl to write results to */
	SSL* ssl_write;
};

struct strlist {
	struct strlist* next;
	char* str;
};

/** start the connection thread */
void attach_start(struct cfg* cfg);

/** stop attach */
void attach_stop(void);

/** send insecure choice to the daemon */
void attach_send_insecure(int val);

void panel_alert_state(int last_insecure, int now_insecure, int dark,
	int cache, int auth, int disconn);

#endif /* ATTACH_H */
