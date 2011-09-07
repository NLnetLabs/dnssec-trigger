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
#include "winrc/win_svc.h"
#include "riggerd/log.h"
#include "riggerd/net_help.h"
#include "riggerd/svr.h"
#include "riggerd/probe.h"
#include "riggerd/netevent.h"
#include "riggerd/winsock_event.h"

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

static WSAOVERLAPPED netlist_overlap;
static WSACOMPLETION netlist_complete;
static WSAEVENT netlist_event;
static struct event netlist_ev;
static HANDLE netlist_lookup;

/** stop and close lookup */
static void stop_lookup(HANDLE lookup)
{
	if(WSALookupServiceEnd(lookup) != 0) {
		log_err("WSALookupServiceEnd: %s",
			wsa_strerror(WSAGetLastError()));
	}
}

/** replace characters with other characters */
static void replace_str(char* s, char a, char b)
{
	while(*s) {
		if(*s == a)
			*s = b;
		s++;
	}
}

/** process network adapter */
static void process_adapter(const char* guid, char* dest, size_t len)
{
	char key[256];
	char* res;
	verbose(VERB_ALGO, "adapter %s", guid);
	/* registry lookups of the DNS servers */
	/* replace , and ; with spaces */
	/* append to the total string list */
	snprintf(key, sizeof(key), "SYSTEM\\CurrentControlSet\\services"
		"\\Tcpip\\Parameters\\Interfaces\\%s", guid);
	res = lookup_reg_str(key, "DhcpNameServer");
	if(res && strlen(res)>0) {
		size_t dlen = strlen(dest);
		replace_str(res, ',', ' ');
		replace_str(res, ';', ' ');
		verbose(VERB_ALGO, "dhcpnameserver %s", res);
		if(dlen + strlen(res) + 1 < len) {
			/* it fits in the dest array */
			memmove(dest+dlen, res, strlen(res)+1);
		}
	}
	free(res);
}

/** start lookup and notify daemon of the current list */
static HANDLE notify_nets(void)
{
	int r;
	HANDLE lookup;
	char result[10240];
	char buf[20480];
	WSAQUERYSET *qset = (WSAQUERYSET*)buf;
	DWORD flags = LUP_DEEP | LUP_RETURN_ALL;
	DWORD len;
	GUID nlaguid = NLA_SERVICE_CLASS_GUID;
	result[0]=0;
	memset(qset, 0, sizeof(*qset));
	qset->dwSize = sizeof(*qset);
	qset->dwNameSpace = NS_NLA;
	qset->lpServiceClassId = &nlaguid;
	/* not set ServiceInstance to a single network name */

	verbose(VERB_ALGO, "netlist sweep");

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
	while(WSALookupServiceNext(lookup, LUP_RETURN_ALL, &len, qset) == 0) {
		if(len > sizeof(buf)) {
			/* sanity check on the buffer */
			stop_lookup(lookup);
			return NULL;
		}
		verbose(VERB_ALGO, "service name %s",
				qset->lpszServiceInstanceName);
		verbose(VERB_ALGO, "comment %s", qset->lpszComment);
		verbose(VERB_ALGO, "context %s", qset->lpszContext);
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
						interfaceData.adapterName,
						result, sizeof(result));
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
		/* start the probe for the notified IPs from up networks */
		probe_start(result);
		return lookup;
	}
	/* we failed */
	log_err("WSALookupServiceNext: %s", wsa_strerror(r));
	stop_lookup(lookup);
	return NULL;
}

/** add an event to the server to wait for changes */
static void
netlist_add_event(HANDLE lookup, struct svr* svr)
{
	DWORD bytesret = 0;
	netlist_event = WSACreateEvent();
	if(netlist_event == WSA_INVALID_EVENT) {
		fatal_exit("WSACreateEvent: %s", wsa_strerror(WSAGetLastError()));
	}
	netlist_overlap.hEvent = netlist_event;
	netlist_complete.Type = NSP_NOTIFY_EVENT;
	netlist_complete.Parameters.Event.lpOverlapped = &netlist_overlap;
	if(WSANSPIoctl(lookup, SIO_NSP_NOTIFY_CHANGE, NULL, 0,
		NULL, 0, &bytesret, &netlist_complete) != NO_ERROR) {
		int r = WSAGetLastError();
		if(r != WSA_IO_PENDING) {
			WSACloseEvent(netlist_event);
			fatal_exit("WSANSPIoctl: %s",
				wsa_strerror(WSAGetLastError()));
		}
	}
	if(!winsock_register_wsaevent(comm_base_internal(svr->base),
		&netlist_ev, &netlist_event, &netlist_change_cb, lookup)) {
		fatal_exit("cannot register netlist event");
	}
	netlist_lookup = lookup;
}

/** remove and close netlist event */
static void netlist_remove_event(HANDLE* lookup)
{
	winsock_unregister_wsaevent(&netlist_ev);
	stop_lookup(lookup);
	WSACloseEvent(netlist_event);
}

/** callback for change */
void netlist_change_cb(int ATTR_UNUSED(fd), short ATTR_UNUSED(ev), void* arg)
{
	HANDLE lookup = (HANDLE)arg;
	netlist_remove_event(lookup);
	lookup = notify_nets();
	while(!lookup) {
		sleep(1); /* wait until netinfo is possible */
		lookup = notify_nets();
	}
	netlist_add_event(lookup, global_svr);
}

void netlist_start(struct svr* svr)
{
	HANDLE lookup = NULL;
	while(!lookup) {
		lookup = notify_nets();
		if(!lookup) sleep(1); /* wait until netinfo is possible */
	}
	netlist_add_event(lookup, svr);
}

void netlist_stop(void)
{
	netlist_remove_event(netlist_lookup);
}

