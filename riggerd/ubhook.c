/*
 * ubhook.c - dnssec-trigger unbound control hooks for adjusting that server
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
 * This file contains the unbound hooks for adjusting the unbound validating
 * DNSSEC resolver.
 */
#include "config.h"
#include "ubhook.h"
#include "cfg.h"
#include "log.h"
#include "probe.h"

/**
 * Perform the unbound control command.
 * @param cfg: the config options with the command pathname.
 * @param cmd: the command.
 * @param args: arguments.
 */
static void
ub_ctrl(struct cfg* cfg, const char* cmd, const char* args)
{
	char command[12000];
	const char* ctrl = "unbound-control";
	int r;
	if(cfg->noaction)
		return;
	if(cfg->unbound_control)
		ctrl = cfg->unbound_control;
	verbose(VERB_ALGO, "system %s %s %s", ctrl, cmd, args);
	snprintf(command, sizeof(command), "%s %s %s", ctrl, cmd, args);
	r = system(command);
	if(r == -1) {
		log_err("system(%s) failed: %s", ctrl, strerror(errno));
	} else if(r != 0) {
		log_warn("unbound-control exited with status %d", r);
	}
}

void hook_unbound_auth(struct cfg* cfg)
{
	verbose(VERB_QUERY, "unbound hook to auth");
	if(cfg->noaction)
		return;
	ub_ctrl(cfg, "forward", "off");
}

void hook_unbound_cache(struct cfg* cfg, const char* ip)
{
	verbose(VERB_QUERY, "unbound hook to cache");
	if(cfg->noaction)
		return;
	ub_ctrl(cfg, "forward", ip); 
}

void hook_unbound_cache_list(struct cfg* cfg, struct probe_ip* list)
{
	/* create list of working ips */
	char buf[10240];
	char* now = buf;
	size_t left = sizeof(buf);
	verbose(VERB_QUERY, "unbound hook to cache list");
	if(cfg->noaction)
		return;
	buf[0]=0; /* safe, robust */
	while(list) {
		if(list->works && list->finished) {
			int len;
			if(left < strlen(list->name)+3)
				break; /* no space for more */
			len = snprintf(now, left, "%s%s",
				(now==buf)?"":" ", list->name);
			left -= len;
			now += len;
		}
		list = list->next;
	}
	ub_ctrl(cfg, "forward", buf); 
}

void hook_unbound_dark(struct cfg* cfg)
{
	verbose(VERB_QUERY, "unbound hook to dark");
	if(cfg->noaction)
		return;
	ub_ctrl(cfg, "forward", UNBOUND_DARK_IP); 
}
