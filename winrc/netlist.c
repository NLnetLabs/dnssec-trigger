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
#include <winsock2.h>
#include <mswsock.h>
#include <nspapi.h>
#include "winrc/netlist.h"
#include "riggerd/log.h"
#include "riggerd/net_help.h"

/* API constants for the Network Location Awareness API (winXP and later)
 * should be in mswsock.h but some crosscompile environments omit the API */
#ifndef NS_NLA
/* the defines that we need to get adapter GUIDs */
#define NS_NLA 15
/* 6642243A-3BA8-4aa6-BAA5-2E0BD71FDD83 */
#define NLA_SERVICE_CLASS_GUID {0x37e515,0xb5c9,0x4a43,{0xba,0xda,0x8b,0x48,0xa8,0x7a,0xd2,0x39}}
enum blobtype { NLA_INTERFACE = 1 };
typedef struct _NLA_BLOB {
	struct {
		enum blobtype type;
		DWORD dwSize;
		DWORD nextOffset;
	} header;
	union {
		struct {
			DWORD dwType;
			DWORD dwSpeed;
			CHAR adapterName[1];
		} interfaceData;
	} data;
} NLA_BLOB;
#endif /* NS_NLA */

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

/** stop and close lookup */
static void stop_lookup(HANDLE lookup)
{
	if(WSALookupServiceEnd(lookup) != 0) {
		log_err("WSALookupServiceEnd: %s",
			wsa_strerror(WSAGetLastError()));
	}
}

/** process network adapter */
static void process_adapter(const char* guid)
{
	if(1) {
		/* debug print */
		printf("adapter %s\n", guid);
	}
	/* TODO : registry lookups of the DNS servers */
	
}

/** start lookup and notify daemon of the current list */
static HANDLE notify_nets(void)
{
	int r;
	HANDLE lookup;
	char buf[65535];
	WSAQUERYSET *qset = (WSAQUERYSET*)buf;
	DWORD flags = LUP_DEEP | LUP_RETURN_ALL;
	DWORD len;
	GUID nlaguid = NLA_SERVICE_CLASS_GUID;
	memset(qset, 0, sizeof(*qset));
	qset->dwSize = sizeof(*qset);
	qset->dwNameSpace = NS_NLA;
	qset->lpServiceClassId = &nlaguid;
	/* not set ServiceInstance to a single network name */

	/* open it */
	if(WSALookupServiceBegin(qset, flags, &lookup) != 0) {
		log_err("WSALookupServiceBegin: %s",
			wsa_strerror(WSAGetLastError()));
		sleep(1);
		return NULL;
	}

	/* check for available networks */
	memset(qset, 0, sizeof(*qset));
	len = sizeof(buf);
	while(WSALookupServiceNext(lookup, flags, &len, qset) == 0) {
		if(len > sizeof(buf)) {
			/* sanity check on the buffer */
			stop_lookup(lookup);
			return NULL;
		}
		if(1) {
			/* debug output */
			printf("service name %s\n",
				qset->lpszServiceInstanceName);
			printf("comment %s\n", qset->lpszComment);
			printf("context %s\n", qset->lpszContext);
		}
		/* obtain GUID of interface names of the networks */
		if(qset->lpBlob != NULL) {
			DWORD off = 0;
			do {
				NLA_BLOB* p = (NLA_BLOB*)&(qset->lpBlob->
					pBlobData[off]);
				if( (size_t)((void*)p - (void*)buf)
					>= sizeof(buf))
					break; /* sanity check */
				if(p->header.type == NLA_INTERFACE) {
					/* process it (registry lookup) */
					process_adapter(p->data.
						interfaceData.adapterName);
				}
				off = p->header.nextOffset;
			} while(off != 0);
		}
		memset(qset, 0, sizeof(*qset));
		len = sizeof(qset);
	}
	/* see if we terminated OK or with an error. */
	r = WSAGetLastError();
	if( 1
#ifdef WSAENOMORE
		|| r == WSAENOMORE
#endif
#ifdef WSA_E_NO_MORE
		|| r == WSA_E_NO_MORE
#endif
		) {
		return lookup;
	}
	/* we failed */
	log_err("WSALookupServiceNext: %s", wsa_strerror(r));
	stop_lookup(lookup);
	return NULL;
}

/** wait for net list info to change */
static void wait_for_change(HANDLE lookup)
{
	WSAOVERLAPPED overlap;
	WSACOMPLETION complete;
	DWORD bytesret = 0;
	WSAEVENT event = WSACreateEvent();
	if(event == WSA_INVALID_EVENT) {
		log_err("WSACreateEvent: %s", wsa_strerror(WSAGetLastError()));
		return;
	}
	overlap.hEvent = event;
	complete.Type = NSP_NOTIFY_EVENT;
	complete.Parameters.Event.lpOverlapped = &overlap;
	if(WSANSPIoctl(lookup, SIO_NSP_NOTIFY_CHANGE, NULL, 0,
		NULL, 0, &bytesret, &complete) != NO_ERROR) {
		int r = WSAGetLastError();
		if(r != WSA_IO_PENDING) {
			log_err("WSANSPIoctl: %s",
				wsa_strerror(WSAGetLastError()));
			WSACloseEvent(event);
			return;
		}
	}
	/* wait blockingly */
	if(WSAWaitForMultipleEvents(1, &event, TRUE, WSA_INFINITE, FALSE)
		== WSA_WAIT_FAILED) {
		log_err("WSAWaitForMultipleEvents(NS_NLA): %s",
			wsa_strerror(WSAGetLastError()));
	}
	WSACloseEvent(event);
	/* the list in lookup is no longer valid, re-probe the list */
}

/** the netlist main function */
static void* netlist_main(void* ATTR_UNUSED(arg))
{
	printf("started netlist\n");
	while(1) {
		HANDLE lookup = notify_nets();
		if(!lookup) continue;
		printf("initiate wait\n");
		wait_for_change(lookup);
		printf("wait done\n");
		stop_lookup(lookup);
	}
	return NULL;
}

void start_netlist(void)
{
	/* DEBUG */
	netlist_main(NULL);
	return;

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

