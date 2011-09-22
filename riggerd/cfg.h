/*
 * cfg.h - dnssec-trigger config
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
 * This file contains config file options.
 */

#ifndef CFG_H
#define CFG_H
struct strlist;

/* version of control proto */
#define CONTROL_VERSION 1

/**
 * The configuration options
 */
struct cfg {
	/** verbosity */
	int verbosity;
	/** pid file */
	char* pidfile;
	/** log file (or NULL) */
	char* logfile;
	/** use syslog (bool) */
	int use_syslog;
	/** chroot dir (or NULL) */
	char* chroot;

	/** path to unbound-control, can have space and commandline options */
	char* unbound_control;
	/** path to resolv.conf */
	char* resolvconf;
	/** resolv.conf domain line (or NULL) */
	char* rescf_domain;
	/** resolv.conf search line (or NULL) */
	char* rescf_search;
	/** noaction option does no actions to resolv.conf or unbound */
	int noaction;

	/** list of port 80 open resolvers on ip4 and ip6 */
	struct strlist* tcp80_ip4, *tcp80_ip4_last;
	int num_tcp80_ip4;
	struct strlist* tcp80_ip6, *tcp80_ip6_last;
	int num_tcp80_ip6;
	/** list of port 443 open resolvers on ip4 and ip6*/
	struct strlist* tcp443_ip4, *tcp443_ip4_last;
	int num_tcp443_ip4;
	struct strlist* tcp443_ip6, *tcp443_ip6_last;
	int num_tcp443_ip6;

	/** port number for the control port */
	int control_port;
	/** private key file for server */
	char* server_key_file;
	/** certificate file for server */
	char* server_cert_file;
	/** private key file for control */
	char* control_key_file;
	/** certificate file for control */
	char* control_cert_file;
};

/** simple list of strings */
struct strlist {
	struct strlist* next;
	char* str;
};

/** create config and read in */
struct cfg* cfg_create(const char* cfgfile);
/** delete config */
void cfg_delete(struct cfg* cfg);

/** setup SSL context for client usage, or NULL and error in err */
SSL_CTX* cfg_setup_ctx_client(struct cfg* cfg, char* err, size_t errlen);
/** setup SSL on the connection, blocking, or NULL and string in err */
SSL* setup_ssl_client(SSL_CTX* ctx, int fd, char* err, size_t errlen);

/** append to strlist, first=last=NULL to start empty. fatal if malloc fails */
void strlist_append(struct strlist** first, struct strlist** last, char* str);
/** free strlist */
void strlist_delete(struct strlist* first);
/** get nth element of strlist */
char* strlist_get_num(struct strlist* list, unsigned n);

/** have tcp80 or tcp443 configured */
int cfg_have_dnstcp(struct cfg* cfg);

#endif /* CFG_H */
