/*
 * ubhook.h - dnssec-trigger unbound control hooks for adjusting that server
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

#ifndef UBHOOKS_H
#define UBHOOKS_H
struct cfg;
struct probe_ip;

/**
 * Set the unbound server to go to the authorities
 * @param cfg: the config options.
 */
void hook_unbound_auth(struct cfg* cfg);

/**
 * Set the unbound server to go to the given cache
 * @param cfg: the config options.
 */
void hook_unbound_cache(struct cfg* cfg, const char* ip);

/**
 * Set the unbound server to go to the working probed servers. 
 * @param cfg: the config options.
 * @param list: the working servers in this list are used.
 */
void hook_unbound_cache_list(struct cfg* cfg, struct probe_ip* list);

/**
 * Set the unbound server to go dark.  It gets no connections.
 * In reality, it sets unbound to forward to 127.0.0.127 and thus no upstream.
 * Unbound by default does not send queries to 127/8.
 * @param cfg: the config options.
 */
void hook_unbound_dark(struct cfg* cfg);

/* IP address that makes unbound go dark, no upstream. unbound has
 * donotquery 127.0.0.0/8 by default */
#define UNBOUND_DARK_IP "127.0.0.127"

/**
 * Detect if unbound supports the tcp-upstream option (since 1.4.13).
 * @param cfg: the config options.
 */
int hook_unbound_supports_tcp_upstream(struct cfg* cfg);

/**
 * Detect if unbound supports the ssl-upstream option (since 1.4.14).
 * @param cfg: the config options.
 */
int hook_unbound_supports_ssl_upstream(struct cfg* cfg);

/**
 * Set unbound to use tcp upstream.
 * @param cfg: the config options.
 * @param tcp80_ip4: if true, use those IP addresses.
 * @param tcp80_ip6: if true, use those IP addresses.
 * @param tcp443_ip4: if true, use those IP addresses.
 * @param tcp443_ip6: if true, use those IP addresses.
 */
void hook_unbound_tcp_upstream(struct cfg* cfg, int tcp80_ip4, int tcp80_ip6,
	int tcp443_ip4, int tcp443_ip6);

/**
 * Set unbound to use ssl upstream.
 * @param cfg: the config options.
 * @param ssl443_ip4: if true, use those IP addresses.
 * @param ssl443_ip6: if true, use those IP addresses.
 */
void hook_unbound_ssl_upstream(struct cfg* cfg, int ssl443_ip4, int ssl443_ip6);

#endif /* UBHOOKS_H */
