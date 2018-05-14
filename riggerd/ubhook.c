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
			size_t len;
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
	size_t len;
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

#ifdef FWD_ZONES_SUPPORT

struct nm_connection_list hook_unbound_list_forwards(struct cfg* cfg) {
	FILE *fp;
	fp = popen("unbound-control list_forwards", "r");
	struct nm_connection_list ret = hook_unbound_list_forwards_inner(cfg, fp);
	fclose(fp);
	return ret;
}

struct nm_connection_list hook_unbound_list_forwards_inner(struct cfg* cfg, FILE *fp) {
	// TODO: is there any other output??
	// Format: <ZONE> IN forward [+i] <list of addresses>
	
	struct nm_connection_list ret;
	nm_connection_list_init(&ret);
	struct nm_connection *new;

	size_t line_len = 1024;
    ssize_t read_len = 0;
    char *line = (char *)calloc_or_die(line_len);
    memset(line, 0, line_len);
    while ((read_len = getline(&line, &line_len, fp) != -1)){
		// XXX: line len is always 1??
		size_t i = 0;
		int parser_state = 0;
		size_t start = 0;
		bool run = true;
		new = (struct nm_connection *) calloc_or_die(sizeof(struct nm_connection));
		nm_connection_init(new);
		while(run) {
			switch (parser_state) {
				case 0:
					while (line[i] != ' ') {
						++i;
					}
					string_list_push_back(&new->zones, &line[start], i-start);
					++i;
					parser_state = 1;
					break;
				case 1:
				/* fallthrough */
				case 2:
					while (line[i] != ' ') {
						++i;
					}
					++i;
					++parser_state;
					break;
				default:
					if (line[i] == '+') {
						i += 3;
						// INSECURE
					} else {
						start = i;
						while (line[i] != ' ' && line[i] != '\n') {
							++i;
							if (line[i] == '\n') {
								run = false;
								break;
							}
						}
						string_list_push_back(&new->servers, &line[start], i-start);
						++i;
					}
				break;
			}
		}
		nm_connection_list_push_back(&ret, new);
		memset(line, 0, line_len);
	}
	free(line);
	return ret;
}

struct string_list hook_unbound_list_local_zones(struct cfg* cfg) {
	FILE *fp;
	fp = popen("unbound-control list_local_zones", "r");
	struct string_list ret = hook_unbound_list_local_zones_inner(cfg, fp);
	fclose(fp);
	return ret;
}

struct string_list hook_unbound_list_local_zones_inner(struct cfg* cfg, FILE *fp) {
	struct string_list ret;
	string_list_init(&ret);
	char zone[1024], label[1024];
    int r = 0;

	while ((r = fscanf(fp, "%s %s\n", zone, label)) > 0 ) {
        struct string_buffer label_static = string_builder("static");
        if (strncmp(label_static.string, label, label_static.length) != 0) {
            // TODO: log it? do sth about it?
        } else {
			string_list_push_back(&ret, zone, strlen(zone));
		}
    }

	return ret;
}

static int run_unbound_control(char *cmd) {
	FILE *fp;
	int ret = -1;
	
	fp = popen(cmd, "r");
	if (fscanf(fp, "ok\n") != -1) {
		ret = 0;
	}
	fclose(fp);
	return ret;
}

int hook_unbound_add_forward_zone_from_connection(struct nm_connection *con) {
	struct string_buffer zone = {
			.string = con->zones.first->string,
			.length = con->zones.first->length,
		};
	struct string_buffer servers = {
				.string = (char *)calloc_or_die(4000),
				.length = 4000,
			};
	string_list_sprint(&(con->servers), servers.string, servers.length);
	hook_unbound_add_forward_zone(zone, servers);
	free(servers.string);
}

int hook_unbound_add_forward_zone(struct string_buffer zone, struct string_buffer servers) {
	struct string_buffer exe = string_builder("unbound-control");
	return hook_unbound_add_forward_zone_inner(exe, zone, servers);
}

int hook_unbound_add_forward_zone_inner(struct string_buffer exe, struct string_buffer zone, struct string_buffer servers) {
	char cmd[4000] = {'\0'};
	sprintf(cmd, "%s forward_add +i %s %s", exe.string, zone.string, servers.string);
	return run_unbound_control(cmd);
}

int hook_unbound_remove_forward_zone(struct string_buffer zone) {
	struct string_buffer exe = string_builder("unbound-control");
	return hook_unbound_remove_forward_zone_inner(exe, zone);
}

int hook_unbound_remove_forward_zone_inner(struct string_buffer exe, struct string_buffer zone) {
	char cmd[4000] = {'\0'};
	sprintf(cmd, "%s forward_remove %s", exe.string, zone.string);
	return run_unbound_control(cmd);
}

int hook_unbound_add_local_zone(struct string_buffer zone, struct string_buffer type) {
	struct string_buffer exe = string_builder("unbound-control");
	return hook_unbound_add_local_zone_inner(exe, zone, type);
}

int hook_unbound_add_local_zone_inner(struct string_buffer exe, struct string_buffer zone, struct string_buffer type) {
	char cmd[1000] = {'\0'};
	sprintf(cmd, "%s local_zone %s %s", exe.string, zone.string, type.string);
	return run_unbound_control(cmd);
}

int hook_unbound_remove_local_zone(struct string_buffer zone) {
	struct string_buffer exe = string_builder("unbound-control");
	return hook_unbound_remove_local_zone_inner(exe, zone);
}

int hook_unbound_remove_local_zone_inner(struct string_buffer exe, struct string_buffer zone) {
	char cmd[1000] = {'\0'};
	sprintf(cmd, "%s local_zone_remove %s", exe.string, zone.string);
	return run_unbound_control(cmd);
}

#endif