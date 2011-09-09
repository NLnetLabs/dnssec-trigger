/*
 * winrc/win_svc.h - windows services API implementation for dnssec-trigger
 *
 * Copyright (c) 2009, NLnet Labs. All rights reserved.
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
 * This file contains functions to integrate with the windows services API.
 * This means it handles the commandline switches to install and remove
 * the service (via CreateService and DeleteService), it handles
 * the ServiceMain() main service entry point when started as a service,
 * and it handles the Handler[_ex]() to process requests to the service
 * (such as start and stop and status).
 */

#ifndef WINRC_WIN_SVC_H
#define WINRC_WIN_SVC_H
struct comm_base;

/** service name for unbound (internal to ServiceManager) */
#define SERVICE_NAME "dnssectrigger"

/** from gen_msg.h - success message record for windows message log */
#define MSG_GENERIC_SUCCESS              ((DWORD)0x20010001L)
/** from gen_msg.h - informational message record for windows message log */
#define MSG_GENERIC_INFO                 ((DWORD)0x60010002L)
/** from gen_msg.h - warning message record for windows message log */
#define MSG_GENERIC_WARN                 ((DWORD)0xA0010003L)
/** from gen_msg.h - error message record for windows message log */
#define MSG_GENERIC_ERR                  ((DWORD)0xE0010004L)

/**
 * Handle commandline service for windows.
 * @param wopt: windows option string (install, remove, service). 
 * @param cfgfile: configfile to open (default or passed with -c).
 * @param v: amount of commandline verbosity added with -v.
 * @param c: true if cfgfile was set by commandline -c option.
 */
void wsvc_command_option(const char* wopt, const char* cfgfile, int v, int c);

/**
 * Setup lead worker events.
 */
void wsvc_setup_worker(struct comm_base* base);

/**
 * Desetup lead worker events.
 */
void wsvc_desetup_worker(void);

/** windows worker stop event callback handler */
void worker_win_stop_cb(int fd, short ev, void* arg);

/** windows cron timer callback handler */
void wsvc_cron_cb(void* arg);

/**
 * Obtain registry string (if it exists).
 * @param key: key string
 * @param name: name of value to fetch.
 * @return malloced string with the result or NULL if it did not
 * exist on an error (logged) was encountered.
 */
char* lookup_reg_str(const char* key, const char* name);

/** log a windows GetLastError message */
void log_win_err(const char* str, DWORD err);

/**
 * Run command, and wait for result.
 * @param cmd: the command and arguments.
 * @return: return code of the program.  If -1, errno.
 */
int win_run_cmd(char* cmd);

/**
 * Set resolver to use on windows
 * @param ip: list of ips with spaces.
 */
void win_set_resolv(char* ip);

/**
 * Remove resolver entry
 */
void win_clear_resolv(void);

/** sets NameServer in HKEY(registry space) to the arg(string or NULL) */
void enum_reg_set_nameserver(HKEY hk, void* arg);

#endif /* WINRC_WIN_SVC_H */
