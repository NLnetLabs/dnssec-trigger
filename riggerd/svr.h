/*
 * svr.h - dnssec-trigger server
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
 * This file contains the server definition.
 */

#ifndef SVR_H
#define SVR_H
struct cfg;
struct comm_base;
struct comm_reply;
struct sslconn;
struct listen_list;
struct comm_point;
struct ldns_struct_buffer;
struct probe_ip;

/**
 * The server
 */
struct svr {
	struct cfg* cfg;
	struct comm_base* base;

	/** SSL context with keys */
	SSL_CTX* ctx;
	/** number of active commpoints that are handling remote control */
	int active;
	/** max active commpoints */
	int max_active;
	/** commpoints for accepting remote control connections */
	struct listen_list* listen;
	/** busy commpoints */
	struct sslconn* busy_list;

	/** udp buffer */
	struct ldns_struct_buffer* udp_buffer;

	/** probes for the IP addresses */
	struct probe_ip* probes;
	/** numprobes in list */
	int num_probes;
	/** number done */
	int num_probes_done;
	/** number of probes to cache servers (i.e. number of DHCP IPs) */
	int num_probes_to_cache;
	/** saw the first working probe */
	int saw_first_working;
	/** saw direct work */
	int saw_direct_work;
	/** attempt to access DNS authority servers directly */
	int probe_direct;


	/* result of probes */
	enum res_state { res_auth, res_cache, res_dark, res_disconn} res_state;
	/* insecure state entered */
	int insecure_state;
};

/** list of commpoints */
struct listen_list {
	struct listen_list* next;
	struct comm_point* c;
};

/** busy ssl connection */
struct sslconn {
	/** the next item in list */
	struct sslconn* next;
	/** the commpoint */
	struct comm_point* c;
	/** in the handshake part */
	enum { rc_hs_none, rc_hs_read, rc_hs_write, rc_hs_want_write,
		rc_hs_want_read, rc_hs_shutdown } shake_state;
	/** the ssl state */
	SSL* ssl;
	/** line state: read or write */
	enum { command_read, persist_read, persist_write,
		persist_write_checkclose } line_state;
	/** buffer with info to send or receive */
	struct ldns_struct_buffer* buffer;
	/** have to fetch another status update right away */
	int fetch_another_update;
};

extern struct svr* global_svr;

/** create server */
struct svr* svr_create(struct cfg* cfg);
/** delete server */
void svr_delete(struct svr* svr);
/** perform the service */
void svr_service(struct svr* svr);
/** send results to clients */
void svr_send_results(struct svr* svr);

int handle_ssl_accept(struct comm_point* c, void* arg, int error,
        struct comm_reply* reply_info);
int control_callback(struct comm_point* c, void* arg, int error,
        struct comm_reply* reply_info);

#endif /* SVR_H */
