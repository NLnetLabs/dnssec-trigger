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
 * This file contains config file options.
 */

#ifndef CFG_H
#define CFG_H
struct strlist;
struct ssllist;

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

	/** web browser to open login windows */
	char* login_command;
	/** url to open for login windows */
	char* login_location;

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
	/** list of ssl port 443 resolvers on ip4 and ip6 */
	struct ssllist* ssl443_ip4, *ssl443_ip4_last;
	int num_ssl443_ip4;
	struct ssllist* ssl443_ip6, *ssl443_ip6_last;
	int num_ssl443_ip6;

	/** list of http probe urls */
	struct strlist2* http_urls, *http_urls_last;
	int num_http_urls;

	/** if we should perform version check (and ask user to update)
	 * enabled on windows and osx. */
	int check_updates;

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

	/** use DNS forwarders provided by VPN connection instead of the forwarders
	 * from the default connection. Use 0 or 1 to indicate the value. */
	int use_vpn_forwarders;

	/** TODO: write documentation
	 * */
	int use_private_address_ranges;
	int add_wifi_provided_zones;
};

/** simple list of strings */
struct strlist {
	struct strlist* next;
	char* str;
};

/** simple list of two strings */
struct strlist2 {
	struct strlist2* next;
	char* str1;
	char* str2;
};

/** list of hashes */
struct hashlist {
	struct hashlist* next;
	unsigned char hash[64]; /* hash (SHA256) */
	unsigned int hashlen; /* number of bytes used in hash */
};

/** list of ssl servers */
struct ssllist {
	struct ssllist* next; /* must be first for compatibility with strlist */
	char* str; /* ip address */
	struct hashlist* hashes; /* zero or more hashes to check */
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

/** append to ssllist, first=last=NULL to start empty. fatal if malloc fails */
void ssllist_append(struct ssllist** first, struct ssllist** last,
	struct ssllist* e);
/** free ssllist */
void ssllist_delete(struct ssllist* first);
/** get nth element of ssllist */
struct ssllist* ssllist_get_num(struct ssllist* list, unsigned n);

/** free hashlist */
void hashlist_delete(struct hashlist* first);
/** prepend to hashlist */
void hashlist_prepend(struct hashlist** first, unsigned char* hash,
	unsigned int len);

/** append to strlist2 */
void strlist2_append(struct strlist2** first, struct strlist2** last,
	char* s, char* t);
/** free strlist2 */
void strlist2_delete(struct strlist2* first);

/** have tcp80 or tcp443 configured */
int cfg_have_dnstcp(struct cfg* cfg);
/** have ssl443 configured */
int cfg_have_ssldns(struct cfg* cfg);

#ifdef UB_ON_WINDOWS
/**
 * Obtain registry string (if it exists).
 * @param key: key string
 * @param name: name of value to fetch.
 * @return malloced string with the result or NULL if it did not
 * 	exist on an error (logged with log_err) was encountered.
 */
char* w_lookup_reg_str(const char* key, const char* name);
#endif /* UB_ON_WINDOWS */


#endif /* CFG_H */
