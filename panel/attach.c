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
#include "config.h"
#include "panel/attach.h"
#include "riggerd/cfg.h"
#include "riggerd/log.h"
#include "riggerd/net_help.h"

/* the global feed structure */
struct feed* feed = NULL;

/* keep trying to open the read channel, blocking */
static SSL* try_contact_server(void)
{
	SSL* ssl = NULL;
	while(!ssl) {
		int fd;
		while( (fd=contact_server("127.0.0.1",
			feed->cfg->control_port, 0, feed->connect_reason,
			sizeof(feed->connect_reason))) == -1)
			sleep(1);
		ssl = setup_ssl_client(feed->ctx, fd, feed->connect_reason,
			sizeof(feed->connect_reason));
		if(!ssl) {
#ifndef USE_WINSOCK
			close(fd);
#else
			closesocket(fd);
#endif
		}
	}
	return ssl;
}

/* write the first command over SSL, blocking */
static void write_firstcmd(SSL* ssl, char* cmd)
{
	char pre[10];
	if(!ssl) return;
	snprintf(pre, sizeof(pre), "DNSTRIG%d ", CONTROL_VERSION);
	if(SSL_write(ssl, pre, (int)strlen(pre)) <= 0)
		fatal_exit("could not SSL_write");
	if(SSL_write(ssl, cmd, (int)strlen(cmd)) <= 0)
		fatal_exit("could not SSL_write");
}

void attach_start(struct cfg* cfg)
{
	snprintf(feed->connect_reason, sizeof(feed->connect_reason),
		"connecting to probe daemon");
	feed->cfg = cfg;
	feed->ctx = cfg_setup_ctx_client(cfg, feed->connect_reason,
		sizeof(feed->connect_reason));
	if(!feed->ctx) {
		fatal_exit("cannot setup ssl context: %s",
			feed->connect_reason);
	}
	feed->ssl_read = try_contact_server();
	feed->ssl_write = try_contact_server();
	printf("contacted server\n");
	write_firstcmd(feed->ssl_write, "cmdtray\n");
	write_firstcmd(feed->ssl_read, "results\n");
	printf("contacted server, first cmds written\n");
	/* TODO mainloop */
}
