/*
 * cfg.c - dnssec-trigger config
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
 * This file contains config file options implementation.
 */
#include "config.h"
#include "cfg.h"
#include "log.h"
#include "net_help.h"
#include <ctype.h>

/** append to strlist */
void
strlist_append(struct strlist** first, struct strlist** last, char* str)
{
	struct strlist* e = (struct strlist*)malloc(sizeof(*e));
	if(!e) fatal_exit("out of memory");
	e->next = NULL;
	e->str = strdup(str);
	if(!e->str) fatal_exit("out of memory");
	if(*last)
		(*last)->next = e;
	else	*first = e;
	*last = e;
}

/** free strlist */
void
strlist_delete(struct strlist* e)
{
	struct strlist* p = e, *np;
	while(p) {
		np = p->next;
		free(p->str);
		free(p);
		p = np;
	}
}

/** append to ssllist */
void
ssllist_append(struct ssllist** first, struct ssllist** last, struct ssllist* e)
{
	e->next = NULL;
	if(*last)
		(*last)->next = e;
	else	*first = e;
	*last = e;
}

/** free ssllist */
void
ssllist_delete(struct ssllist* e)
{
	struct ssllist* p = e, *np;
	while(p) {
		np = p->next;
		free(p->str);
		free(p);
		p = np;
	}
}

/** get arg in line */
static char* get_arg(char* line)
{
	while(isspace(line[0]))
		line++;
	while(strlen(line) > 0 && isspace(line[strlen(line)-1]))
		line[strlen(line)-1] = 0;
	if(strlen(line) > 1 && line[0]=='"' && line[strlen(line)-1]=='"') {
		line++;
		line[strlen(line)-1] = 0;
	} else if(strlen(line) > 1 && line[0]=='\''
		&& line[strlen(line)-1]=='\'') {
		line++;
		line[strlen(line)-1] = 0;
	}
	return line;
}

/** get two arguments from the line */
static void get_arg2(char* line, char** a1, char** a2)
{
	char* sp = strchr(line, ' ');
	if(!sp) {
		*a1 = line;
		*a2 = NULL;
		return;
	}
	*a1 = line;
	*sp = 0;
	*a2 = sp+1;
}

/** strdup the argument on the line */
static void str_arg(char** dest, char* line)
{
	char* s = strdup(get_arg(line));
	if(!s)
		fatal_exit("out of memory");
	free(*dest);
	*dest = s;
}

/** append the argument on the line */
static void tcp_arg(struct strlist** first4, struct strlist** last4, int* num4,
	struct strlist** first6, struct strlist** last6, int* num6, char* line)
{
	struct sockaddr_storage addr;
	socklen_t len;
	line = get_arg(line);
	if(line[0] == 0) return; /* ignore empty ones */
	if(!ipstrtoaddr(line, DNS_PORT, &addr, &len)) {
		log_err("cannot parse IP address: '%s', ignored", line);
		return;
	}
	if(strchr(line, ':')) {
		strlist_append(first6, last6, line);
		(*num6) ++;
	} else {
		strlist_append(first4, last4, line);
		(*num4) ++;
	}
}

static int read_hash(char* arg, struct ssllist* e)
{
	int i;
	const int len = 32;
	char* at = arg;
	if(!arg || arg[0] == 0) {
		e->has_hash = 0;
		return 1;
	}
	if(strlen(arg) != len*3-1) { /* sha256, 32bytes of xx:xx:xx:xx */
		return 0;
	}
	e->has_hash = 1;
	e->hashlen = len;
	for(i=0; i<len; i++) {
		char *n = NULL;
		e->hash[i] = strtol(at, &n, 16);
		if(n != at+2) {
			return 0;
		}
		/* skip two hex digits */
		at += 2;
		/* skip ':' (unless at EOS) */
		if(*at) at ++;
	}
	return 1;
}

/** append the argument on the line */
static void ssl_arg(struct ssllist** first4, struct ssllist** last4, int* num4,
	struct ssllist** first6, struct ssllist** last6, int* num6, char* line)
{
	struct sockaddr_storage addr;
	socklen_t len;
	struct ssllist* e;
	char* arg1=NULL, *arg2=NULL;
	line = get_arg(line);
	if(line[0] == 0) return; /* ignore empty ones */
	e = (struct ssllist*)calloc(1, sizeof(*e));
	if(!e) fatal_exit("out of memory");
	get_arg2(line, &arg1, &arg2);
	if(!ipstrtoaddr(arg1, DNS_PORT, &addr, &len)) {
		log_err("cannot parse IP address: '%s', ssl ignored", arg1);
		free(e);
		return;
	}
	if(!read_hash(arg2, e)) {
		log_err("cannot parse hash: '%s', ssl ignored", arg2);
		free(e);
		return;
	}
	e->str = strdup(arg1);
	if(!e->str) fatal_exit("out of memory");
	if(strchr(arg1, ':')) {
		ssllist_append(first6, last6, e);
		(*num6) ++;
	} else {
		ssllist_append(first4, last4, e);
		(*num4) ++;
	}
}

/** handle bool arg */
static void bool_arg(int* dest, char* line)
{
	line = get_arg(line);
	if(strcmp(line, "yes") != 0 && strcmp(line, "no") != 0) {
		fatal_exit("expected yes or no, but got %s", line);
	}
	*dest = (strcmp(line, "yes")==0);
}

/** read keyword and put into cfg */
static int
keyword(struct cfg* cfg, char* p)
{
	if(strncmp(p, "verbosity:", 10) == 0) {
		cfg->verbosity = atoi(get_arg(p+10));
	} else if(strncmp(p, "pidfile:", 8) == 0) {
		str_arg(&cfg->pidfile, p+8);
	} else if(strncmp(p, "logfile:", 8) == 0) {
		str_arg(&cfg->logfile, p+8);
		cfg->use_syslog = 0;
	} else if(strncmp(p, "use-syslog:", 11) == 0) {
		bool_arg(&cfg->use_syslog, p+11);
	} else if(strncmp(p, "chroot:", 7) == 0) {
		str_arg(&cfg->chroot, p+7);
	} else if(strncmp(p, "unbound-control:", 16) == 0) {
		str_arg(&cfg->unbound_control, p+16);
	} else if(strncmp(p, "resolvconf:", 11) == 0) {
		str_arg(&cfg->resolvconf, p+11);
	} else if(strncmp(p, "domain:", 7) == 0) {
		str_arg(&cfg->rescf_domain, p+7);
	} else if(strncmp(p, "search:", 7) == 0) {
		str_arg(&cfg->rescf_search, p+7);
	} else if(strncmp(p, "noaction:", 9) == 0) {
		bool_arg(&cfg->noaction, p+9);
	} else if(strncmp(p, "port:", 5) == 0) {
		cfg->control_port = atoi(get_arg(p+5));
	} else if(strncmp(p, "server-key-file:", 16) == 0) {
		str_arg(&cfg->server_key_file, p+16);
	} else if(strncmp(p, "server-cert-file:", 17) == 0) {
		str_arg(&cfg->server_cert_file, p+17);
	} else if(strncmp(p, "control-key-file:", 17) == 0) {
		str_arg(&cfg->control_key_file, p+17);
	} else if(strncmp(p, "control-cert-file:", 18) == 0) {
		str_arg(&cfg->control_cert_file, p+18);
	} else if(strncmp(p, "tcp80:", 6) == 0) {
		tcp_arg(&cfg->tcp80_ip4, &cfg->tcp80_ip4_last,
			&cfg->num_tcp80_ip4, &cfg->tcp80_ip6,
			&cfg->tcp80_ip6_last, &cfg->num_tcp80_ip6, p+6);
	} else if(strncmp(p, "tcp443:", 7) == 0) {
		tcp_arg(&cfg->tcp443_ip4, &cfg->tcp443_ip4_last,
			&cfg->num_tcp443_ip4, &cfg->tcp443_ip6,
			&cfg->tcp443_ip6_last, &cfg->num_tcp443_ip6, p+7);
	} else if(strncmp(p, "ssl443:", 7) == 0) {
		ssl_arg(&cfg->ssl443_ip4, &cfg->ssl443_ip4_last,
			&cfg->num_ssl443_ip4, &cfg->ssl443_ip6,
			&cfg->ssl443_ip6_last, &cfg->num_ssl443_ip6, p+7);
	} else if(strncmp(p, "url:", 4) == 0) {
		strlist_append(&cfg->http_urls, &cfg->http_urls_last,
			get_arg(p+4));
		cfg->num_http_urls++;
	} else {
		return 0;
	}
	return 1;
}

static void
attempt_readfile(struct cfg* cfg, const char* file)
{
	FILE* in = fopen(file, "r");
	int line = 0;
	char buf[1024];
	if(!in) {
		if(errno == ENOENT) {
			verbose(VERB_OPS, "no config file, using defaults");
			return;
		}
		log_err("%s: %s", file, strerror(errno));
		return;
	}
	while(fgets(buf, (int)sizeof(buf), in)) {
		char* p = buf;
		line++;
		/* whitespace at start of line */
		while(isspace(*p)) p++;
		/* comment */
		if(p[0] == '#' || p[0] == ';' || p[0] == 0)
			continue;
		/* keyword */
		if(!keyword(cfg, p)) {
			log_err("cannot read %s:%d %s", file, line, p);
			exit(1);
		}
	}
	fclose(in);
}

struct cfg* cfg_create(const char* cfgfile)
{
	struct cfg* cfg = (struct cfg*)calloc(1, sizeof(*cfg));
	if(!cfg) return NULL;
	cfg->use_syslog = 1;
	cfg->control_port = 8955;
	cfg->server_key_file=strdup(KEYDIR"/dnssec_trigger_server.key");
	cfg->server_cert_file=strdup(KEYDIR"/dnssec_trigger_server.pem");
	cfg->control_key_file=strdup(KEYDIR"/dnssec_trigger_control.key");
	cfg->control_cert_file=strdup(KEYDIR"/dnssec_trigger_control.pem");
	cfg->unbound_control = strdup(UNBOUND_CONTROL);
	cfg->pidfile = strdup(PIDFILE);
	cfg->resolvconf = strdup("/etc/resolv.conf");

	if(!cfg->unbound_control || !cfg->pidfile || !cfg->server_key_file ||
		!cfg->server_cert_file || !cfg->control_key_file ||
		!cfg->control_cert_file || !cfg->resolvconf) {
		cfg_delete(cfg);
		return NULL;
	}

	attempt_readfile(cfg, cfgfile);

	/* apply */
	verbosity = cfg->verbosity;
	return cfg;
}

void cfg_delete(struct cfg* cfg)
{
	if(!cfg) return;
	strlist_delete(cfg->tcp80_ip4);
	strlist_delete(cfg->tcp80_ip6);
	strlist_delete(cfg->tcp443_ip4);
	strlist_delete(cfg->tcp443_ip6);
	ssllist_delete(cfg->ssl443_ip4);
	ssllist_delete(cfg->ssl443_ip6);
	strlist_delete(cfg->http_urls);
	free(cfg->pidfile);
	free(cfg->logfile);
	free(cfg->chroot);
	free(cfg->unbound_control);
	free(cfg->resolvconf);
	free(cfg->rescf_domain);
	free(cfg->rescf_search);
	free(cfg->server_key_file);
	free(cfg->server_cert_file);
	free(cfg->control_key_file);
	free(cfg->control_cert_file);
	free(cfg);
}

int cfg_have_dnstcp(struct cfg* cfg)
{
	return cfg->num_tcp80_ip4 || cfg->num_tcp80_ip6
		|| cfg->num_tcp443_ip4 || cfg->num_tcp443_ip6;
}

int cfg_have_ssldns(struct cfg* cfg)
{
	return cfg->num_ssl443_ip4 || cfg->num_ssl443_ip6;
}

/** find nth element in strlist */
char* strlist_get_num(struct strlist* list, unsigned n)
{
	unsigned i = 0;
	while(list) {
		if(i==n) return list->str;
		list = list->next;
		i++;
	}
	return NULL;
}

/** find nth element in ssllist */
struct ssllist* ssllist_get_num(struct ssllist* list, unsigned n)
{
	unsigned i = 0;
	while(list) {
		if(i==n) return list;
		list = list->next;
		i++;
	}
	return NULL;
}

/** give errors and return NULL */
static SSL_CTX*
ctx_err_ret(SSL_CTX* ctx, char* err, size_t errlen, const char* msg)
{
	char sslerr[512];
	sslerr[0]=0;
	ERR_error_string_n(ERR_get_error(), sslerr, sizeof(sslerr));
	snprintf(err, errlen, "%s %s", msg, sslerr);
	if(ctx) SSL_CTX_free(ctx);
	return NULL;
}

/** give errors and return NULL */
static SSL*
ssl_err_ret(SSL* ssl, char* err, size_t errlen, const char* msg)
{
	(void)ctx_err_ret(NULL, err, errlen, msg);
	if(ssl) SSL_free(ssl);
	return NULL;
}

/** setup SSL context */
SSL_CTX*
cfg_setup_ctx_client(struct cfg* cfg, char* err, size_t errlen)
{
	char* s_cert, *c_key, *c_cert;
	SSL_CTX* ctx;

	s_cert = cfg->server_cert_file;
	c_key = cfg->control_key_file;
	c_cert = cfg->control_cert_file;
	ctx = SSL_CTX_new(SSLv23_client_method());
	if(!ctx)
		return ctx_err_ret(ctx, err, errlen,
			"could not allocate SSL_CTX pointer");
	if(!(SSL_CTX_set_options(ctx, SSL_OP_NO_SSLv2) & SSL_OP_NO_SSLv2))
		return ctx_err_ret(ctx, err, errlen, 
			"could not set SSL_OP_NO_SSLv2");
	if(!SSL_CTX_use_certificate_file(ctx,c_cert,SSL_FILETYPE_PEM) ||
		!SSL_CTX_use_PrivateKey_file(ctx,c_key,SSL_FILETYPE_PEM)
		|| !SSL_CTX_check_private_key(ctx))
		return ctx_err_ret(ctx, err, errlen,
			"Error setting up SSL_CTX client key and cert");
	if (SSL_CTX_load_verify_locations(ctx, s_cert, NULL) != 1)
		return ctx_err_ret(ctx, err, errlen,
			"Error setting up SSL_CTX verify, server cert");
	SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

	return ctx;
}

/** setup SSL on the connection, blocking, or NULL and string in err */
SSL* setup_ssl_client(SSL_CTX* ctx, int fd, char* err, size_t errlen)
{
	SSL* ssl;
	X509* x;
	int r;

	ssl = SSL_new(ctx);
	if(!ssl)
		return ssl_err_ret(ssl, err, errlen, "could not SSL_new");
	SSL_set_connect_state(ssl);
	(void)SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);
	if(!SSL_set_fd(ssl, fd))
		return ssl_err_ret(ssl, err, errlen, "could not SSL_set_fd");
	while(1) {
		ERR_clear_error();
		if( (r=SSL_do_handshake(ssl)) == 1)
			break;
		r = SSL_get_error(ssl, r);
		if(r != SSL_ERROR_WANT_READ && r != SSL_ERROR_WANT_WRITE)
			return ssl_err_ret(ssl, err, errlen,
				"SSL handshake failed");
		/* wants to be called again */
	}

	/* check authenticity of server */
	if(SSL_get_verify_result(ssl) != X509_V_OK)
		return ssl_err_ret(ssl, err, errlen,
			"SSL verification failed");
	x = SSL_get_peer_certificate(ssl);
	if(!x)
		return ssl_err_ret(ssl, err, errlen,
			"Server presented no peer certificate");
	X509_free(x);
	return ssl;
}

#ifdef UB_ON_WINDOWS
char*
w_lookup_reg_str(const char* key, const char* name)
{
	HKEY hk = NULL;
	DWORD type = 0;
	BYTE buf[1024];
	DWORD len = (DWORD)sizeof(buf);
	LONG ret;
	char* result = NULL;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk);
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* key does not exist */
	else if(ret != ERROR_SUCCESS) {
		log_err("RegOpenKeyEx failed");
		return NULL;
	}
	ret = RegQueryValueEx(hk, (LPCTSTR)name, 0, &type, buf, &len);
	if(RegCloseKey(hk))
		log_err("RegCloseKey");
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* name does not exist */
	else if(ret != ERROR_SUCCESS) {
		log_err("RegQueryValueEx failed");
		return NULL;
	}
	if(type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ) {
		buf[sizeof(buf)-1] = 0;
		buf[sizeof(buf)-2] = 0; /* for multi_sz */
		result = strdup((char*)buf);
		if(!result) log_err("out of memory");
	}
	return result;
}
#endif /* UB_ON_WINDOWS */

