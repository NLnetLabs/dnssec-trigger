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

	/* test settings */
	cfg->pidfile = strdup("test.pid");
	cfg->use_syslog = 0;
	//cfg->logfile = strdup("test.log");
	cfg->server_key_file=strdup("keys""/dnssec_trigger_server.key");
	cfg->server_cert_file=strdup("keys""/dnssec_trigger_server.pem");
	cfg->control_key_file=strdup("keys""/dnssec_trigger_control.key");
	cfg->control_cert_file=strdup("keys""/dnssec_trigger_control.pem");
	cfg->unbound_control = strdup("echo unbound-control");

	if(!cfg->unbound_control || !cfg->pidfile || !cfg->server_key_file ||
		!cfg->server_cert_file || !cfg->control_key_file ||
		!cfg->control_cert_file) {
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
	free(cfg->server_key_file);
	free(cfg->server_cert_file);
	free(cfg->control_key_file);
	free(cfg->control_cert_file);
	free(cfg);
}
