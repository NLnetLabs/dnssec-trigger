/*
 * winrc/netlist.c - windows DHCP network listing service for dnssec trigger
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
 */
#include "config.h"
#include <windows.h>
#include <nspapi.h>
#include "winrc/netlist.h"
#include "riggerd/log.h"

/** log a windows GetLastError message */
static void log_win_err(const char* str, DWORD err)
{
	LPTSTR buf;
	if(FormatMessage(FORMAT_MESSAGE_FROM_SYSTEM |
		FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_ALLOCATE_BUFFER,
		NULL, err, 0, (LPTSTR)&buf, 0, NULL) == 0) {
		/* could not format error message */
		log_err("%s, GetLastError=%d", str, (int)err);
		return;
	}
	log_err("%s, (err=%d): %s", str, (int)err, buf);
	LocalFree(buf);
}

/** start lookup and notify daemon of the current list */
static HANDLE notify_nets(void)
{
	HANDLE lookup;
	WSAQUERYSET qset;
	DWORD flags = LUP_DEEP;
	memset(&qset, 0, sizeof(qset));
	qset.dwSize = sizeof(qset);
	qset.dwNameSpace = NS_DNS;
	while(WSALookupServiceBegin(&qset, flags, &lookup) != 0) {
		log_err("WSALookupServiceBegin: %s",
			wsa_strerror(WSAGetLastError()));
		sleep(1);
	}
	return lookup;
}

/** wait for net list info to change */
static void wait_for_change(HANDLE lookup)
{
	/* TODO */
}

/** stop and close lookup */
static void stop_lookup(HANDLE lookup)
{
	/* TODO */
}

/** the netlist main function */
static void* netlist_main(void* ATTR_UNUSED(arg))
{
	printf("started netlist\n");
	while(1) {
		HANDLE lookup = notify_nets();
		wait_for_change(lookup);
		stop_lookup(lookup);
	}
	return NULL;
}

void start_netlist(void)
{
	HANDLE thr;
	void* arg=NULL;
#ifndef HAVE__BEGINTHREADEX
	thr = CreateThread(NULL, /* default security (no inherit handle) */
		0, /* default stack size */
		(LPTHREAD_START_ROUTINE)&netlist_main, arg,
		0, /* default flags, run immediately */
		NULL); /* do not store thread identifier anywhere */
#else
	/* the begintheadex routine setups for the C lib; aligns stack */
	thr=(HANDLE)_beginthreadex(NULL, 0, (void*)&netlist_main, arg, 0, NULL);
#endif
	if(thr == NULL) {
		log_win_err("CreateThread failed", GetLastError());
		fatal_exit("thread create failed");
	}
}

