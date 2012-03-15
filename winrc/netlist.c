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
#ifdef HAVE_IPHLPAPI_H
#include <iphlpapi.h>
#endif
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
static char* netlist_netnames = NULL;
static char* netlist_ips = NULL;
static char* netlist_ssid = NULL;

/** WLAN API (if not available). it should be in wlanapi.h and windot11.h, but
 * crosscompile environments may not have those header files */
#ifndef WLAN_API_VERSION
#define WLAN_API_VERSION 0x1
#define WLAN_MAX_NAME_LENGTH 256
typedef enum {
	wlan_interface_state_not_ready = 0,
	wlan_interface_state_connected }
	WLAN_INTERFACE_STATE;
typedef struct {
	GUID InterfaceGuid;
	WCHAR strInterfaceDescription[WLAN_MAX_NAME_LENGTH];
	WLAN_INTERFACE_STATE isState;
} WLAN_INTERFACE_INFO;
typedef struct {
	DWORD dwNumberOfItems;
	DWORD dwIndex;
	WLAN_INTERFACE_INFO InterfaceInfo[1];
} WLAN_INTERFACE_INFO_LIST;
#define DOT11_SSID_MAX_LENGTH 32
typedef struct {
	ULONG uSSIDLength;
	UCHAR ucSSID[DOT11_SSID_MAX_LENGTH];
} DOT11_SSID;
typedef struct {
	DOT11_SSID dot11Ssid;
	/* .. BSSID, MacADDRESS, phytype, phytindex, quality, rrate, trate */
} WLAN_ASSOCIATION_ATTRIBUTES;
typedef struct {
	WLAN_INTERFACE_STATE isState;
	enum { wlan_connection_mode_profile = 0 } wlanConnectionMode;
	WCHAR strProfileName[WLAN_MAX_NAME_LENGTH];
	WLAN_ASSOCIATION_ATTRIBUTES wlanAssociationAttributes;
	/* .. wlanSecurityAttributes; */
} WLAN_CONNECTION_ATTRIBUTES;
typedef enum {
	wlan_intf_opcode_current_connection = 7
} WLAN_INTF_OPCODE;
typedef enum {
	wlan_opcode_value_type_query_only = 0
} WLAN_OPCODE_VALUE_TYPE;
#endif

/** fetch list of wlan SSIDs */
static void fetch_wlan_ssid(char* res, size_t reslen)
{
	DWORD serviceVersion = 0;
	HANDLE client = NULL;
	DWORD r ;
	WLAN_INTERFACE_INFO_LIST* infolist = NULL;
	unsigned int i;
	char* p;
	static HMODULE wlandll = NULL;
	static DWORD WINAPI (*myWlanOpenHandle)(DWORD dwClientVersion,
		PVOID pReserved, PDWORD pdwNegotiatedVersion,
		PHANDLE phClientHandle);
	static DWORD WINAPI (*myWlanCloseHandle)(HANDLE hClientHandle,
		PVOID pReserved);
	static DWORD WINAPI (*myWlanEnumInterfaces)(HANDLE hClientHandle,
		PVOID pReserved, WLAN_INTERFACE_INFO_LIST **ppInterfaceList);
	static VOID WINAPI (*myWlanFreeMemory)(PVOID pMemory);
	static DWORD WINAPI (*myWlanQueryInterface)(HANDLE hClientHandle,
		const GUID *pInterfaceGuid, WLAN_INTF_OPCODE OpCode,
		PVOID pReserved, PDWORD pdwDataSize, PVOID *ppData,
		WLAN_OPCODE_VALUE_TYPE* pWlanOpcodeValueType);

	res[0] = 0;

	if(!wlandll) {
		/* see if we canload the wlan API dll (to get wlan SSID) */
		wlandll = LoadLibrary("Wlanapi.dll");
		if(!wlandll) {
			log_win_err("cannot LoadLibrary wlanapi.dll",
				GetLastError());
			return;
		}
		/* get funcs */
		myWlanOpenHandle = (DWORD(WINAPI*)(DWORD, PVOID, PDWORD,
			PHANDLE))
			GetProcAddress(wlandll, "WlanOpenHandle");
		myWlanCloseHandle = (DWORD(WINAPI*)(HANDLE, PVOID))
			GetProcAddress(wlandll, "WlanCloseHandle");
		myWlanEnumInterfaces = (DWORD(WINAPI*)(HANDLE, PVOID,
			WLAN_INTERFACE_INFO_LIST **))
			GetProcAddress(wlandll, "WlanEnumInterfaces");
		myWlanFreeMemory = (VOID(WINAPI*)(PVOID))
			GetProcAddress(wlandll, "WlanFreeMemory");
		myWlanQueryInterface = (DWORD(WINAPI*)(HANDLE, const GUID *,
			WLAN_INTF_OPCODE, PVOID, PDWORD, PVOID *,
			WLAN_OPCODE_VALUE_TYPE*))
			GetProcAddress(wlandll, "WlanQueryInterface");
	}

	r = myWlanOpenHandle(WLAN_API_VERSION, NULL, &serviceVersion,
		&client);
	if(r != ERROR_SUCCESS || client == NULL) {
		if(r == ERROR_SERVICE_NOT_ACTIVE)
			return; /* no wifi, or not started, no reason to err */
		log_win_err("cannot WlanOpenHandle", r);
		return;
	}
	if( (r=myWlanEnumInterfaces(client, 0, &infolist)) != ERROR_SUCCESS) {
		log_win_err("cannot WlanEnumInterfaces", r);
		if(infolist) myWlanFreeMemory(infolist);
		myWlanCloseHandle(client, 0);
		return;
	}
	for(i=0; i<infolist->dwNumberOfItems; i++) {
		WLAN_CONNECTION_ATTRIBUTES* attr = NULL;
		PVOID data = NULL;
		DWORD sz = 0;
		if( (r=myWlanQueryInterface(client, &infolist->InterfaceInfo[i].
			InterfaceGuid, wlan_intf_opcode_current_connection,
			0, &sz, &data, 0)) != ERROR_SUCCESS) {
			log_win_err("cannot WlanQueryInterface", r);
			if(data) myWlanFreeMemory(data);
			continue;
		}
		attr = (WLAN_CONNECTION_ATTRIBUTES*)data;
		if(attr->isState != wlan_interface_state_connected) {
			/* not connected, not listed right now */
			myWlanFreeMemory(data);
			continue;
		}
		if(strlen(res) + attr->wlanAssociationAttributes.dot11Ssid.
			uSSIDLength + 2 >= reslen) {
			/* too long */
			myWlanFreeMemory(data);
			break;
		}
		p = res+strlen(res);
		p[0] = ' ';
		memmove(p+1, attr->wlanAssociationAttributes.dot11Ssid.ucSSID,
			attr->wlanAssociationAttributes.dot11Ssid.uSSIDLength);
		p[attr->wlanAssociationAttributes.dot11Ssid.uSSIDLength+1]=0;
		myWlanFreeMemory(data);
	}
	myWlanFreeMemory(infolist);
	myWlanCloseHandle(client, 0);
}

/** stop and close lookup */
static void stop_lookup(HANDLE lookup)
{
	if(WSALookupServiceEnd(lookup) != 0) {
		log_err("WSALookupServiceEnd: %s",
			wsa_strerror(WSAGetLastError()));
	}
}

static int has_changed(char* netnames, char* ips, char* ssid)
{
	if(!netlist_ips || !netlist_netnames || !netlist_ssid ||
		strcmp(netlist_ips, ips) != 0 ||
		strcmp(netlist_netnames, netnames) != 0 ||
		strcmp(netlist_ssid, ssid) != 0) {
		verbose(VERB_DETAIL, "netlist is now: %s %s %s",
			netnames, ips, ssid);
		free(netlist_ips);
		free(netlist_netnames);
		free(netlist_ssid);
		netlist_ips = strdup(ips);
		netlist_netnames = strdup(netnames);
		netlist_ssid = strdup(ssid);
		return 1;
	}
	verbose(VERB_DETAIL, "netlist unchanged: %s", netnames);
	return 0;
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
static void process_adapter(const char* guid, char* dest, size_t len,
	char* netnames, size_t netlen)
{
	char key[256];
	char* res;
	uint8_t* bin = NULL;
	size_t binlen = 0;
	if(!guid) return;
	verbose(VERB_ALGO, "adapter %s", guid);
	snprintf(netnames+strlen(netnames), netlen-strlen(netnames),
		" %s", guid);
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

	/* ipv6 */
	snprintf(key, sizeof(key), "SYSTEM\\CurrentControlSet\\services"
		"\\Tcpip6\\Parameters\\Interfaces\\%s", guid);
	bin = lookup_reg_binary(key, "Dhcpv6DNSServers", &binlen);
	if(bin) {
		/* every 16 bytes is an IPv6 address (hopefully) */
		size_t at = 0;
		while(at < binlen && binlen - at >= 16) {
			/* get the ipv6 server added */
			size_t dlen = strlen(dest);
			char t[128];
			if(inet_ntop(AF_INET6, &bin[at], t, sizeof(t))==0) {
				t[0] = 0;
			}
			verbose(VERB_ALGO, "dhcp6dnsservers (byte %d/%d) %s",
				(int)at, (int)binlen, t);
			/* add str + space + eos */
			if(dlen + strlen(t) + 1 + 1 < len) {
				/* it fits in the dest array */
				dest[dlen] = ' ';
				memmove(dest+dlen+1, t, strlen(t)+1);
			}
			at += 16;
		}
		free(bin);
	}
}

#ifdef HAVE_GETADAPTERSADDRESSES
/** use the (XP) getAdaptersAddresses to look for UP networks and their DHCP,
 * because VirtualBox installs weird network adapters that make us have an
 * empty set of networks from WSALookupServiceBegin. */
static void
sweep_adapters(char* netnames, size_t netnames_sz, char* result,
	size_t result_sz) {
	char buf[40960];
	int unused; /* DEBUG */
	IP_ADAPTER_ADDRESSES *p, *list = (IP_ADAPTER_ADDRESSES*)&buf;
	ULONG r, sz = sizeof(buf), flags = 0;
	if((r=GetAdaptersAddresses(AF_UNSPEC, flags, NULL, list, &sz))
		!= ERROR_SUCCESS) {
		log_win_err("GetAdaptersAddresses", r);
		return;
	}
	if(sz > sizeof(buf)) {
		/* sanity check on buffer */
		return;
	}
	/* inspect the adapters, to find ones we skipped and are UP with DHCP */
	for(p=list; p; p=p->Next) {
		if( (p->Flags&IP_ADAPTER_DHCP_ENABLED) && 
			(p->OperStatus&IfOperStatusUp) &&
			!strstr(netnames, p->AdapterName)) {
			/* note that the dnsServers list for this structure
			 * is now (likely) filled with 127.0.0.1 that
			 * dnssec-trigger has configured itself, so we have
			 * to go look in the registry */
			verbose(VERB_ALGO, "GetAdaptersAddresses says %s is "
				"UP DHCP", p->AdapterName);
			process_adapter(p->AdapterName,
				result, result_sz, netnames, netnames_sz);
		}
	}
}
#endif /* HAVE_GETADAPTERSADDRESSES */

/** start lookup and notify daemon of the current list */
static HANDLE notify_nets(void)
{
	int r;
	HANDLE lookup;
	char result[10240];
	char netnames[10240];
	char buf[20480];
	WSAQUERYSET *qset = (WSAQUERYSET*)buf;
	DWORD flags = LUP_DEEP | LUP_RETURN_ALL;
	DWORD len;
	GUID nlaguid = NLA_SERVICE_CLASS_GUID;
	result[0]=0;
	netnames[0]=0;
	memset(qset, 0, sizeof(*qset));
	qset->dwSize = sizeof(*qset);
	qset->dwNameSpace = NS_NLA;
	qset->lpServiceClassId = &nlaguid;
	/* not set ServiceInstance to a single network name */

	verbose(VERB_ALGO, "netlist sweep");

	/* open it */
	if(WSALookupServiceBegin(qset, flags, &lookup) != 0) {
		DWORD r = WSAGetLastError();
		if(r == RPC_S_SERVER_UNAVAILABLE) {
			/* do not log 'RPC server not there yet', that happens
			 * when we reboot and we came up before xx service */
			verbose(VERB_ALGO, "WSALookupServiceBegin: %s",
				wsa_strerror(r));
		} else
			log_err("WSALookupServiceBegin: %s", wsa_strerror(r));
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
		snprintf(netnames+strlen(netnames),
			sizeof(netnames)-strlen(netnames), " * %s",
			qset->lpszServiceInstanceName?
			qset->lpszServiceInstanceName:"-");
		if(qset->lpszServiceInstanceName)
			verbose(VERB_ALGO, "service name %s",
				qset->lpszServiceInstanceName);
		if(qset->lpszComment)
			verbose(VERB_ALGO, "comment %s", qset->lpszComment);
		if(qset->lpszContext)
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
						result, sizeof(result),
						netnames, sizeof(netnames));
				}
				if(p->header.nextOffset <= off)
					break; /* no endless loop */
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
		char ssid[10240];
#ifdef HAVE_GETADAPTERSADDRESSES
		/* see if we have additional information, on XP and later */
		@@@ /* DEBUG */
		sweep_adapters(netnames, sizeof(netnames), result,
			sizeof(result));
#endif /* HAVE_GETADAPTERSADDRESSES */
		/* start the probe for the notified IPs from up networks */
		fetch_wlan_ssid(ssid, sizeof(ssid));
		if(has_changed(netnames, result, ssid)) {
			probe_start(result);
		}
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
		&netlist_ev, netlist_event, &netlist_change_cb, lookup)) {
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

