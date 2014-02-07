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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
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
#ifdef USE_WINSOCK
#include "winrc/win_svc.h"
#endif

/* the state configured for unbound */
static int ub_has_tcp_upstream = 0;
static int ub_has_ssl_upstream = 0;

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
#ifdef USE_WINSOCK
	char* regctrl = NULL;
#endif
	int r;
	if(cfg->noaction)
		return;
#ifdef USE_WINSOCK
	if( (regctrl = get_registry_unbound_control()) != NULL) {
		ctrl = regctrl;
	} else
#endif
	if(cfg->unbound_control)
		ctrl = cfg->unbound_control;
	verbose(VERB_ALGO, "system %s %s %s", ctrl, cmd, args);
	snprintf(command, sizeof(command), "%s %s %s", ctrl, cmd, args);
#ifdef USE_WINSOCK
	r = win_run_cmd(command);
	free(regctrl);
#else
	r = system(command);
	if(r == -1) {
		log_err("system(%s) failed: %s", ctrl, strerror(errno));
	} else
#endif
	if(r != 0) {
		log_warn("unbound-control exited with status %d, cmd: %s",
			r, command);
	}
}

static void
disable_tcp_upstream(struct cfg* cfg)
{
	if(ub_has_tcp_upstream) {
		ub_ctrl(cfg, "set_option", "tcp-upstream: no");
		ub_has_tcp_upstream = 0;
	}
}

static void
disable_ssl_upstream(struct cfg* cfg)
{
	if(ub_has_ssl_upstream) {
		ub_ctrl(cfg, "set_option", "ssl-upstream: no");
		ub_has_ssl_upstream = 0;
	}
}


void hook_unbound_auth(struct cfg* cfg)
{
	verbose(VERB_QUERY, "unbound hook to auth");
	if(cfg->noaction)
		return;
	disable_tcp_upstream(cfg);
	disable_ssl_upstream(cfg);
	ub_ctrl(cfg, "forward", "off");
}

void hook_unbound_cache(struct cfg* cfg, const char* ip)
{
	verbose(VERB_QUERY, "unbound hook to cache");
	if(cfg->noaction)
		return;
	disable_tcp_upstream(cfg);
	disable_ssl_upstream(cfg);
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
		if(probe_is_cache(list) && list->works && list->finished) {
			int len;
			if(left < strlen(list->name)+3)
				break; /* no space for more */
			snprintf(now, left, "%s%s",
				(now==buf)?"":" ", list->name);
			len = strlen(now);
			left -= len;
			now += len;
		}
		list = list->next;
	}
	disable_tcp_upstream(cfg);
	disable_ssl_upstream(cfg);
	ub_ctrl(cfg, "forward", buf); 
}

void hook_unbound_dark(struct cfg* cfg)
{
	verbose(VERB_QUERY, "unbound hook to dark");
	if(cfg->noaction)
		return;
	disable_tcp_upstream(cfg);
	disable_ssl_upstream(cfg);
	ub_ctrl(cfg, "forward", UNBOUND_DARK_IP); 
}

static int hook_unbound_supports_option(struct cfg* cfg, const char* args)
{
	char command[12000];
	const char* ctrl = "unbound-control";
	const char* cmd = "get_option";
	int r;
	if(cfg->unbound_control)
		ctrl = cfg->unbound_control;
	verbose(VERB_ALGO, "system %s %s %s", ctrl, cmd, args);
	snprintf(command, sizeof(command), "%s %s %s", ctrl, cmd, args);
#ifdef USE_WINSOCK
	r = win_run_cmd(command);
#else
	r = system(command);
	if(r == -1) {
		log_err("system(%s) failed: %s", ctrl, strerror(errno));
	} else
#endif
	if(r != 0) {
		verbose(VERB_OPS, "unbound does not support option: %s", args);
		return 0;
	}
	verbose(VERB_OPS, "unbound supports option: %s", args);
	return 1;
}

int hook_unbound_supports_tcp_upstream(struct cfg* cfg)
{
	return hook_unbound_supports_option(cfg, "tcp-upstream");
}

int hook_unbound_supports_ssl_upstream(struct cfg* cfg)
{
	return hook_unbound_supports_option(cfg, "ssl-upstream");
}

static void append_str_port(char* buf, char** now, size_t* left,
	char* str, int port)
{
	int len;
	if(*left < strlen(str)+3)
		return; /* no more space */
	snprintf(*now, *left, "%s%s@%d", *now == buf?"":" ", str, port);
	len = strlen(*now);
	(*left) -= len;
	(*now) += len;
}

void hook_unbound_tcp_upstream(struct cfg* cfg, int tcp80_ip4, int tcp80_ip6,
	int tcp443_ip4, int tcp443_ip6)
{
	char buf[102400];
	char* now = buf;
	size_t left = sizeof(buf);
	struct strlist *p;
	verbose(VERB_QUERY, "unbound hook to tcp %s %s %s %s",
		tcp80_ip4?"tcp80_ip4":"", tcp80_ip6?"tcp80_ip6":"",
		tcp443_ip4?"tcp443_ip4":"", tcp443_ip6?"tcp443_ip6":"");
	if(cfg->noaction)
		return;
	buf[0] = 0;
	if(tcp80_ip4) {
		for(p=cfg->tcp80_ip4; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 80);
	}
	if(tcp80_ip6) {
		for(p=cfg->tcp80_ip6; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 80);
	}
	if(tcp443_ip4) {
		for(p=cfg->tcp443_ip4; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 443);
	}
	if(tcp443_ip6) {
		for(p=cfg->tcp443_ip6; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 443);
	}
	/* effectuate tcp upstream and new list of servers */
	disable_ssl_upstream(cfg);
	ub_ctrl(cfg, "set_option", "tcp-upstream: yes");
	ub_ctrl(cfg, "forward", buf);
	if(!ub_has_tcp_upstream) {
		ub_ctrl(cfg, "flush_requestlist", "");
		ub_ctrl(cfg, "flush_infra", "all");
	}
	ub_has_tcp_upstream = 1;
}

void hook_unbound_ssl_upstream(struct cfg* cfg, int ssl443_ip4, int ssl443_ip6)
{
	char buf[102400];
	char* now = buf;
	size_t left = sizeof(buf);
	struct ssllist *p;
	verbose(VERB_QUERY, "unbound hook to ssl %s %s",
		ssl443_ip4?"ssl443_ip4":"", ssl443_ip6?"ssl443_ip6":"");
	if(cfg->noaction)
		return;
	buf[0] = 0;
	if(ssl443_ip4) {
		for(p=cfg->ssl443_ip4; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 443);
	}
	if(ssl443_ip6) {
		for(p=cfg->ssl443_ip6; p; p=p->next)
			append_str_port(buf, &now, &left, p->str, 443);
	}
	/* effectuate ssl upstream and new list of servers */
	/* set SSL first, so no contact of this server over normal DNS,
	 * because the fake answer may cause it to be blacklisted then */
	disable_tcp_upstream(cfg);
	ub_ctrl(cfg, "set_option", "ssl-upstream: yes");
	ub_ctrl(cfg, "forward", buf);
	/* flush requestlist to remove queries over normal transport that
	 * may be waiting very long.  And remove bad timeouts from infra
	 * cache.  Removes edns and so on from all infra because the proxy
	 * that causes SSL to be used may have caused fake values for some. */
	if(!ub_has_ssl_upstream) {
		ub_ctrl(cfg, "flush_requestlist", "");
		ub_ctrl(cfg, "flush_infra", "all");
	}
	ub_has_ssl_upstream = 1;
}
