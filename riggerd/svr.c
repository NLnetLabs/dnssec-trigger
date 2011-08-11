/*
 * svr.c - dnssec-trigger server implementation
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
 * This file contains the server implementation.
 */
#include "config.h"
#include "svr.h"
#include "cfg.h"
#include "log.h"
#include "probe.h"
#include "netevent.h"
#include "net_help.h"

struct svr* global_svr = NULL;

static int setup_ssl_ctx(struct svr* svr);
static int setup_listen(struct svr* svr);
static void sslconn_delete(struct sslconn* sc);
static int sslconn_readline(struct sslconn* sc);
static void sslconn_command(struct sslconn* sc);

/** log ssl crypto err */
static void
log_crypto_err(const char* str)
{
	/* error:[error code]:[library name]:[function name]:[reason string] */
	char buf[128];
	unsigned long e;
	ERR_error_string_n(ERR_get_error(), buf, sizeof(buf));
	log_err("%s crypto %s", str, buf);
	while( (e=ERR_get_error()) ) {
		ERR_error_string_n(e, buf, sizeof(buf));
		log_err("and additionally crypto %s", buf);
	}
}

struct svr* svr_create(struct cfg* cfg)
{
	struct svr* svr = (struct svr*)calloc(1, sizeof(*svr));
	if(!svr) return NULL;
	global_svr = svr;
	svr->max_active = 32;
	svr->cfg = cfg;
	svr->base = comm_base_create(0);
	if(!svr->base) {
		log_err("cannot create base");
		svr_delete(svr);
		return NULL;
	}
	svr->udp_buffer = ldns_buffer_new(65553);
	if(!svr->udp_buffer) {
		log_err("out of memory");
		svr_delete(svr);
		return NULL;
	}

	/* setup SSL_CTX */
	if(!setup_ssl_ctx(svr)) {
		log_err("cannot setup SSL context");
		svr_delete(svr);
		return NULL;
	}
	/* create listening */
	if(!setup_listen(svr)) {
		log_err("cannot setup listening socket");
		svr_delete(svr);
		return NULL;
	}

	return svr;
}

void svr_delete(struct svr* svr)
{
	struct listen_list* ll, *nll;
	if(!svr) return;
	/* delete busy */
	while(svr->busy_list)
		sslconn_delete(svr->busy_list);

	/* delete listening */
	ll = svr->listen;
	while(ll) {
		nll = ll->next;
		comm_point_delete(ll->c);
		free(ll);
		ll=nll;
	}

	/* delete probes */
	probe_list_delete(svr->probes);

	if(svr->ctx) {
		SSL_CTX_free(svr->ctx);
	}
	ldns_buffer_free(svr->udp_buffer);
	comm_base_delete(svr->base);
	free(svr);
}

static int setup_ssl_ctx(struct svr* s)
{
	char* s_cert;
	char* s_key;
	s->ctx = SSL_CTX_new(SSLv23_server_method());
	if(!s->ctx) {
		log_crypto_err("could not SSL_CTX_new");
		return 0;
	}
	/* no SSLv2 because has defects */
	if(!(SSL_CTX_set_options(s->ctx, SSL_OP_NO_SSLv2) & SSL_OP_NO_SSLv2)){
		log_crypto_err("could not set SSL_OP_NO_SSLv2");
		return 0;
	}
	s_cert = s->cfg->server_cert_file;
	s_key = s->cfg->server_key_file;
	verbose(VERB_ALGO, "setup SSL certificates");
	if (!SSL_CTX_use_certificate_file(s->ctx,s_cert,SSL_FILETYPE_PEM)) {
		log_err("Error for server-cert-file: %s", s_cert);
		log_crypto_err("Error in SSL_CTX use_certificate_file");
		return 0;
	}
	if(!SSL_CTX_use_PrivateKey_file(s->ctx,s_key,SSL_FILETYPE_PEM)) {
		log_err("Error for server-key-file: %s", s_key);
		log_crypto_err("Error in SSL_CTX use_PrivateKey_file");
		return 0;
	}
	if(!SSL_CTX_check_private_key(s->ctx)) {
		log_err("Error for server-key-file: %s", s_key);
		log_crypto_err("Error in SSL_CTX check_private_key");
		return 0;
	}
	if(!SSL_CTX_load_verify_locations(s->ctx, s_cert, NULL)) {
		log_crypto_err("Error setting up SSL_CTX verify locations");
		return 0;
	}
	SSL_CTX_set_client_CA_list(s->ctx, SSL_load_client_CA_file(s_cert));
	SSL_CTX_set_verify(s->ctx, SSL_VERIFY_PEER, NULL);
	return 1;
}

static int setup_listen(struct svr* svr)
{
	const char* str="127.0.0.1";
	struct sockaddr_storage addr;
	socklen_t len;
	int s;
	int fam;
	struct listen_list* e;
#if defined(SO_REUSEADDR) || defined(IPV6_V6ONLY)
	int on = 1;
#endif
	if(!ipstrtoaddr(str, svr->cfg->control_port, &addr, &len)) {
		log_err("cannot parse ifname %s", str);
		return 0;
	}
	if(strchr(str, ':')) fam = AF_INET6;
	else fam = AF_INET;
	s = socket(fam, SOCK_STREAM, 0);
	if(s == -1) {
		log_err("socket %s: %s", str, strerror(errno));
		return 0;
	}
#ifdef SO_REUSEADDR
	if(setsockopt(s, SOL_SOCKET, SO_REUSEADDR, (void*)&on,
		(socklen_t)sizeof(on)) < 0) {
		log_err("setsockopt(.. SO_REUSEADDR ..) failed: %s",
			strerror(errno));
	}
#endif
#if defined(IPV6_V6ONLY)
	if(fam == AF_INET6) {
		if(setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY,
			(void*)&on, (socklen_t)sizeof(on)) < 0) {
			log_err("setsockopt(..., IPV6_V6ONLY, ...) failed: %s",
				strerror(errno));
		}
	}
#endif
	if(bind(s, (struct sockaddr*)&addr, len) != 0) {
		log_err("can't bind tcp socket %s: %s", str, strerror(errno));
	}
	fd_set_nonblock(s);
	if(listen(s, 15) == -1) {
		log_err("can't listen: %s", strerror(errno));
	}
	/* add entry */
	e = (struct listen_list*)calloc(1, sizeof(*e));
	if(!e) {
		fatal_exit("out of memory");
	}
	e->c = comm_point_create_raw(svr->base, s, 0, handle_ssl_accept, NULL);
	e->c->do_not_close = 0;
	e->next = svr->listen;
	svr->listen = e;
	return 1;
}

void svr_service(struct svr* svr)
{
	comm_base_dispatch(svr->base);
}

static void sslconn_delete(struct sslconn* sc)
{
	struct sslconn** pp;
	if(!sc) return;
	/* delete and remove from busylist */
	for(pp = &global_svr->busy_list; *pp; pp = &((*pp)->next)) {
		if((*pp) == sc) {
			(*pp) = sc->next;
			break;
		}
	}
	if(sc->buffer)
		ldns_buffer_free(sc->buffer);
	comm_point_delete(sc->c);
	if(sc->ssl)
		SSL_free(sc->ssl);
	free(sc);
}

int handle_ssl_accept(struct comm_point* c, void* ATTR_UNUSED(arg), int err,
	struct comm_reply* ATTR_UNUSED(reply_info))
{
	struct sockaddr_storage addr;
	socklen_t addrlen;
	int s;
	struct svr* svr = global_svr;
	struct sslconn* sc;
        if(err != NETEVENT_NOERROR) {
                log_err("error %d on remote_accept_callback", err);
                return 0;
        }
        /* perform the accept */
        s = comm_point_perform_accept(c, &addr, &addrlen);
        if(s == -1)
                return 0;
        /* create new commpoint unless we are servicing already */
        if(svr->active >= svr->max_active) {
                log_warn("drop incoming remote control: too many connections");
        close_exit:
#ifndef USE_WINSOCK
                close(s);
#else
                closesocket(s);
#endif
                return 0;
        }

	/* setup commpoint to service the remote control command */
        sc = (struct sslconn*)calloc(1, sizeof(*sc));
        if(!sc) {
                log_err("out of memory");
                goto close_exit;
        }

	/* start in reading state */
        sc->c = comm_point_create_raw(svr->base, s, 0, &control_callback, sc);
        if(!sc->c) {
                log_err("out of memory");
                free(sc);
                goto close_exit;
        }
	log_addr(VERB_QUERY, "new control connection from", &addr, addrlen);

	sc->c->do_not_close = 0;
	/* no timeout on the connection: the panel stays connected for long */
	memcpy(&sc->c->repinfo.addr, &addr, addrlen);
        sc->c->repinfo.addrlen = addrlen;
        sc->shake_state = rc_hs_read;
        sc->ssl = SSL_new(svr->ctx);
        if(!sc->ssl) {
                log_crypto_err("could not SSL_new");
		comm_point_delete(sc->c);
                free(sc);
                goto close_exit;
        }
        SSL_set_accept_state(sc->ssl);
        (void)SSL_set_mode(sc->ssl, SSL_MODE_AUTO_RETRY);
        if(!SSL_set_fd(sc->ssl, s)) {
                log_crypto_err("could not SSL_set_fd");
                SSL_free(sc->ssl);
                comm_point_delete(sc->c);
                free(sc);
                goto close_exit;
        }
	sc->buffer = ldns_buffer_new(65536);
	if(!sc->buffer) {
		log_err("out of memory");
                SSL_free(sc->ssl);
                comm_point_delete(sc->c);
                free(sc);
                goto close_exit;
	}
        sc->next = svr->busy_list;
        svr->busy_list = sc;
        svr->active ++;

        /* perform the first nonblocking read already, for windows, 
         * so it can return wouldblock. could be faster too. */
        (void)control_callback(sc->c, sc, NETEVENT_NOERROR, NULL);
	return 0;
}

int control_callback(struct comm_point* c, void* arg, int err,
	struct comm_reply* ATTR_UNUSED(reply_info))
{
        struct sslconn* s = (struct sslconn*)arg;
        int r;
        if(err != NETEVENT_NOERROR) {
                if(err==NETEVENT_TIMEOUT)
                        log_err("remote control timed out");
		sslconn_delete(s);
                return 0;
        }
        /* (continue to) setup the SSL connection */
	if(s->shake_state == rc_hs_read || s->shake_state == rc_hs_write) {
		ERR_clear_error();
		r = SSL_do_handshake(s->ssl);
		if(r != 1) {
			int r2 = SSL_get_error(s->ssl, r);
			if(r2 == SSL_ERROR_WANT_READ) {
				if(s->shake_state == rc_hs_read) {
					/* try again later */
					return 0;
				}
				s->shake_state = rc_hs_read;
				comm_point_listen_for_rw(c, 1, 0);
				return 0;
			} else if(r2 == SSL_ERROR_WANT_WRITE) {
				if(s->shake_state == rc_hs_write) {
					/* try again later */
					return 0;
				}
				s->shake_state = rc_hs_write;
				comm_point_listen_for_rw(c, 0, 1);
				return 0;
			} else {
				if(r == 0)
					log_err("remote control connection closed prematurely");
				log_addr(1, "failed connection from",
					&s->c->repinfo.addr, s->c->repinfo.addrlen);
				log_crypto_err("remote control failed ssl");
				sslconn_delete(s);
				return 0;
			}
		}
		/* once handshake has completed, check authentication */
		if(SSL_get_verify_result(s->ssl) == X509_V_OK) {
			X509* x = SSL_get_peer_certificate(s->ssl);
			if(!x) {
				verbose(VERB_DETAIL, "remote control connection "
					"provided no client certificate");
				sslconn_delete(s);
				return 0;
			}
			verbose(VERB_ALGO, "remote control connection authenticated");
			X509_free(x);
		} else {
			verbose(VERB_DETAIL, "remote control connection failed to "
				"authenticate with client certificate");
			sslconn_delete(s);
			return 0;
		}
		/* set to read state */
		s->line_state = line_read;
		if(s->shake_state == rc_hs_write)
			comm_point_listen_for_rw(c, 1, 0);
		s->shake_state = rc_hs_none;
		ldns_buffer_clear(s->buffer);
	}
	if(s->shake_state == rc_hs_want_write) {
		/* we have satisfied the condition that the socket is
		 * writable, remove the handshake state, and continue */
		comm_point_listen_for_rw(c, 1, 0); /* back to reading */
		s->shake_state = rc_hs_none;
	}

	if(s->line_state == line_read) {
		if(!sslconn_readline(s))
			return 0;
		/* we are done handle it */
		sslconn_command(s);
	}
	/* TODO persistent connection communication with panel */
	return 0;
}

static int sslconn_readline(struct sslconn* sc)
{
        int r;
	while(ldns_buffer_available(sc->buffer, 1)) {
		ERR_clear_error();
		if((r=SSL_read(sc->ssl, ldns_buffer_current(sc->buffer), 1))
			<= 0) {
			int want = SSL_get_error(sc->ssl, r);
			if(want == SSL_ERROR_ZERO_RETURN) {
				ldns_buffer_write_u8(sc->buffer, 0);
				ldns_buffer_flip(sc->buffer);
				return 1;
			} else if(want == SSL_ERROR_WANT_READ) {
				return 0;
			} else if(want == SSL_ERROR_WANT_WRITE) {
				sc->shake_state = rc_hs_want_write;
				comm_point_listen_for_rw(sc->c, 0, 1);
				return 0;
			}
			log_crypto_err("could not SSL_read");
			sslconn_delete(sc);
			return 0;
		}
		if(ldns_buffer_current(sc->buffer)[0] == '\n') {
			/* return string without \n */
			ldns_buffer_write_u8(sc->buffer, 0);
			ldns_buffer_flip(sc->buffer);
			return 1;
		}
		ldns_buffer_skip(sc->buffer, 1);
	}
	log_err("ssl readline too long");
	sslconn_delete(sc);
	return 0;
}

static void handle_submit(char* ips)
{
	/* start probing the servers */
	probe_start(ips);
}

static void sslconn_command(struct sslconn* sc)
{
	char header[10];
	char* str = (char*)ldns_buffer_begin(sc->buffer);
	snprintf(header, sizeof(header), "DNSTRIG%d ", CONTROL_VERSION);
	if(strncmp(str, header, strlen(header)) != 0) {
		log_err("bad version in control connection");
		sslconn_delete(sc);
		return;
	}
	str += strlen(header);
	while(*str == ' ')
		str++;
	verbose(VERB_ALGO, "command: %s", str);
	if(strncmp(str, "submit ", 7) == 0) {
		handle_submit(str+7);
		SSL_shutdown(sc->ssl);
		sslconn_delete(sc);
	} else {
		log_err("unknown command: %s", str);
		sslconn_delete(sc);
	}
}
