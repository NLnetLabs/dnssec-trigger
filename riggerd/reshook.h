/*
 * reshook.h - dnssec-trigger resolv.conf hooks for adjusting name resolution 
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
 * This file contains the unbound hooks for adjusting the name resolution
 * on the system (to 127.0.0.1).
 */

#ifndef RESHOOKS_H
#define RESHOOKS_H
struct cfg;
struct probe_ip;

/**
 * Set the system to resolve at 127.0.0.1 (where unbound is running)
 * @param cfg: with config options.
 */
void hook_resolv_localhost(struct cfg* cfg);

/**
 * Set the system to resolve at the list of 'cache' (recursive) probes in
 * the given list.
 * @param cfg: with config options.
 */
void hook_resolv_iplist(struct cfg* cfg, struct probe_ip* list);

/**
 * Flush the DNS caches on the system, if somehow possible
 * @param cfg: with config options.
 */
void hook_resolv_flush(struct cfg* cfg);

#endif /* RESHOOKS_H */
