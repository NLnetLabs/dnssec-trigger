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

struct cfg* cfg_create(const char* cfgfile)
{
	struct cfg* cfg = (struct cfg*)calloc(1, sizeof(*cfg));
	if(!cfg) return NULL;
	cfg->use_syslog = 1;
	cfg->control_port = 8955;
	//cfg->server_key_file=strdup(KEYDIR"/dnssec_trigger_server.key");
	//cfg->server_cert_file=strdup(KEYDIR"/dnssec_trigger_server.pem");
	//cfg->control_key_file=strdup(KEYDIR"/dnssec_trigger_control.key");
	//cfg->control_cert_file=strdup(KEYDIR"/dnssec_trigger_control.pem");
	//cfg->unbound_control = strdup("unbound-control");
	//cfg->pidfile = strdup(PIDFILE);
	cfg->resolvconf = strdup("/etc/resolv.conf");

	/* test settings */
	cfg->pidfile = strdup("test.pid");
	cfg->use_syslog = 0;
	//cfg->logfile = strdup("test.log");
	cfg->server_key_file=strdup("keys""/dnssec_trigger_server.key");
	cfg->server_cert_file=strdup("keys""/dnssec_trigger_server.pem");
	cfg->control_key_file=strdup("keys""/dnssec_trigger_control.key");
	cfg->control_cert_file=strdup("keys""/dnssec_trigger_control.pem");
	cfg->unbound_control = strdup("echo unbound-control");
	cfg->resolvconf = strdup("test.resconf");

	if(!cfg->unbound_control || !cfg->pidfile || !cfg->server_key_file ||
		!cfg->server_cert_file || !cfg->control_key_file ||
		!cfg->control_cert_file || !cfg->resolvconf) {
		cfg_delete(cfg);
		return NULL;
	}
	/* TODO read cfgfile */

	/* apply */
	verbosity = cfg->verbosity;
	return cfg;
}

void cfg_delete(struct cfg* cfg)
{
	if(!cfg) return;
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


