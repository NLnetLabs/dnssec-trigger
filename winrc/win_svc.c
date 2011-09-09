/*
 * winrc/win_svc.c - windows services API implementation for dnssec-trigger
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
#include "config.h"
#include "winrc/win_svc.h"
#include "winrc/w_inst.h"
#include "winrc/netlist.h"
#include "riggerd/log.h"
#include "riggerd/cfg.h"
#include "riggerd/svr.h"
#include "riggerd/reshook.h"
#include "riggerd/netevent.h"
#include "riggerd/winsock_event.h"

/** global service status */
static SERVICE_STATUS	service_status;
/** global service status handle */
static SERVICE_STATUS_HANDLE service_status_handle;
/** global service stop event */
static WSAEVENT service_stop_event = NULL;
/** event struct for stop callbacks */
static struct event service_stop_ev;
/** if stop even means shutdown or restart */
static int service_stop_shutdown = 0;
/** config file to open. global communication to service_main() */
static char* service_cfgfile = CONFIGFILE;
/** commandline verbosity. global communication to service_main() */
static int service_cmdline_verbose = 0;
/** the cron callback */
static struct comm_timer* service_cron = NULL;
/** the cron thread */
static HANDLE cron_thread = NULL;
/** if cron has already done its quick check */
static int cron_was_quick = 0;

/**
 * Report current service status to service control manager
 * @param state: current state
 * @param exitcode: error code (when stopped)
 * @param wait: pending operation estimated time in milliseconds.
 */
static void report_status(DWORD state, DWORD exitcode, DWORD wait)
{
	static DWORD checkpoint = 1;
	service_status.dwCurrentState = state;
	service_status.dwWin32ExitCode = exitcode;
	service_status.dwWaitHint = wait;
	if(state == SERVICE_START_PENDING)
		service_status.dwControlsAccepted = 0;
	else 	service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP;
	if(state == SERVICE_RUNNING || state == SERVICE_STOPPED)
		service_status.dwCheckPoint = 0;
	else	service_status.dwCheckPoint = checkpoint++;
	SetServiceStatus(service_status_handle, &service_status);
}

/**
 * Service control handler. Called by serviceControlManager when a control
 * code is sent to the service (with ControlService).
 * @param ctrl: control code
 */
static void 
hdlr(DWORD ctrl)
{
	if(ctrl == SERVICE_CONTROL_STOP) {
		report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
		service_stop_shutdown = 1;
		/* send signal to stop */
		if(!WSASetEvent(service_stop_event))
			log_err("Could not WSASetEvent: %s",
				wsa_strerror(WSAGetLastError()));
		return;
	} else {
		/* ctrl == SERVICE_CONTROL_INTERROGATE or whatever */
		/* update status */
		report_status(service_status.dwCurrentState, NO_ERROR, 0);
	}
}

/**
 * report event to system event log
 * For use during startup and shutdown.
 * @param str: the error
 */
static void
reportev(const char* str)
{
	char b[256];
	char e[256];
	HANDLE* s;
	LPCTSTR msg = b;
	/* print quickly to keep GetLastError value */
	wsvc_err2str(e, sizeof(e), str, GetLastError());
	snprintf(b, sizeof(b), "%s: %s", SERVICE_NAME, e);
	s = RegisterEventSource(NULL, SERVICE_NAME);
	if(!s) return;
	ReportEvent(s, /* event log */
		EVENTLOG_ERROR_TYPE, /* event type */
		0, /* event category */
		MSG_GENERIC_ERR, /* event ID (from gen_msg.mc) */
		NULL, /* user security context */
		1, /* numstrings */
		0, /* binary size */
		&msg, /* strings */
		NULL); /* binary data */
	DeregisterEventSource(s);
}

/**
 * Obtain registry string (if it exists).
 * @param key: key string
 * @param name: name of value to fetch.
 * @return malloced string with the result or NULL if it did not
 * exist on an error (logged) was encountered.
 */
char*
lookup_reg_str(const char* key, const char* name)
{
	HKEY hk = NULL;
	DWORD type = 0;
	BYTE buf[1024];
	DWORD len = (DWORD)sizeof(buf);
	LONG ret;
	char* result = NULL;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk);
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* key does not exist */
	else if(ret != ERROR_SUCCESS) {
		reportev("RegOpenKeyEx failed");
		return NULL;
	}
	ret = RegQueryValueEx(hk, (LPCTSTR)name, 0, &type, buf, &len);
	if(RegCloseKey(hk))
		reportev("RegCloseKey");
	if(ret == ERROR_FILE_NOT_FOUND)
		return NULL; /* name does not exist */
	else if(ret != ERROR_SUCCESS) {
		reportev("RegQueryValueEx failed");
		return NULL;
	}
	if(type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ) {
		buf[sizeof(buf)-1] = 0;
		buf[sizeof(buf)-2] = 0; /* for multi_sz */
		result = strdup((char*)buf);
		if(!result) reportev("out of memory");
	}
	return result;
}

/**
 * Obtain registry integer (if it exists).
 * @param key: key string
 * @param name: name of value to fetch.
 * @return integer value (if it exists), or 0 on error.
 */
static int
lookup_reg_int(const char* key, const char* name)
{
	HKEY hk = NULL;
	DWORD type = 0;
	BYTE buf[1024];
	DWORD len = (DWORD)sizeof(buf);
	LONG ret;
	int result = 0;
	ret = RegOpenKeyEx(HKEY_LOCAL_MACHINE, key, 0, KEY_READ, &hk);
	if(ret == ERROR_FILE_NOT_FOUND)
		return 0; /* key does not exist */
	else if(ret != ERROR_SUCCESS) {
		reportev("RegOpenKeyEx failed");
		return 0;
	}
	ret = RegQueryValueEx(hk, (LPCTSTR)name, 0, &type, buf, &len);
	if(RegCloseKey(hk))
		reportev("RegCloseKey");
	if(ret == ERROR_FILE_NOT_FOUND)
		return 0; /* name does not exist */
	else if(ret != ERROR_SUCCESS) {
		reportev("RegQueryValueEx failed");
		return 0;
	}
	if(type == REG_SZ || type == REG_MULTI_SZ || type == REG_EXPAND_SZ) {
		buf[sizeof(buf)-1] = 0;
		buf[sizeof(buf)-2] = 0; /* for multi_sz */
		result = atoi((char*)buf);
	} else if(type == REG_DWORD) {
		DWORD r;
		memmove(&r, buf, sizeof(r));
		result = r;
	} 
	return result;
}

/**
 * Init service. Keeps calling status pending to tell service control
 * manager that this process is not hanging.
 * @param r: restart, true on restart
 * @param d: daemon returned here.
 * @param c: config file returned here.
 * @return false if failed.
 */
static int
service_init(struct svr** d, struct cfg** c)
{
	struct cfg* cfg = NULL;
	struct svr* svr = NULL;

	if(!service_cfgfile) {
		char* newf = lookup_reg_str("Software\\DnssecTrigger", "ConfigFile");
		if(newf) service_cfgfile = newf;
		else 	service_cfgfile = strdup(CONFIGFILE);
		if(!service_cfgfile) fatal_exit("out of memory");
	}

	/* create config */
	cfg = cfg_create(service_cfgfile);
	if(!cfg) return 0;
	report_status(SERVICE_START_PENDING, NO_ERROR, 2800);

	/* create daemon */
	svr = svr_create(cfg);
	if(!svr) return 0;
	report_status(SERVICE_START_PENDING, NO_ERROR, 2600);

	verbose(VERB_QUERY, "winservice - apply settings");
	/* apply settings and init */
	verbosity = cfg->verbosity + service_cmdline_verbose;
	log_init(cfg->logfile, cfg->use_syslog, cfg->chroot);
	report_status(SERVICE_START_PENDING, NO_ERROR, 2400);

	hook_resolv_localhost(cfg);
	report_status(SERVICE_START_PENDING, NO_ERROR, 2300);

	*d = svr;
	*c = cfg;
	return 1;
}

/**
 * Deinit the service
 */
static void
service_deinit(struct svr* svr, struct cfg* cfg)
{
	svr_delete(svr);
	cfg_delete(cfg);
	win_clear_resolv();
}

/**
 * The main function for the service.
 * Called by the services API when starting on windows in background.
 * Arguments could have been present in the string 'path'.
 * @param argc: nr args
 * @param argv: arg text.
 */
static void 
service_main(DWORD ATTR_UNUSED(argc), LPTSTR* ATTR_UNUSED(argv))
{
	struct cfg* cfg = NULL;
	struct svr* svr = NULL;

	service_status_handle = RegisterServiceCtrlHandler(SERVICE_NAME, 
		(LPHANDLER_FUNCTION)hdlr);
	if(!service_status_handle) {
		reportev("Could not RegisterServiceCtrlHandler");
		return;
	}
	
	service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
	service_status.dwServiceSpecificExitCode = 0;

	/* we are now starting up */
	report_status(SERVICE_START_PENDING, NO_ERROR, 3000);
	if(!service_init(&svr, &cfg)) {
		reportev("Could not service_init");
		report_status(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}

	/* event that gets signalled when we want to quit */
	service_stop_event = WSACreateEvent();
	if(service_stop_event == WSA_INVALID_EVENT) {
		log_err("WSACreateEvent: %s", wsa_strerror(WSAGetLastError()));
		reportev("Could not WSACreateEvent");
		report_status(SERVICE_STOPPED, NO_ERROR, 0);
		return;
	}
	if(!WSAResetEvent(service_stop_event)) {
		log_err("WSAResetEvent: %s", wsa_strerror(WSAGetLastError()));
	}
	wsvc_setup_worker(svr->base);

	/* SetServiceStatus SERVICE_RUNNING;*/
	report_status(SERVICE_RUNNING, NO_ERROR, 0);
	verbose(VERB_QUERY, "winservice - init complete");
	
	/* register DHCP hook and perform first sweep */
	netlist_start(svr);

	/* daemon performs work */
	svr_service(svr);

	/* exit */
	verbose(VERB_ALGO, "winservice - cleanup.");
	report_status(SERVICE_STOP_PENDING, NO_ERROR, 0);
	netlist_stop();
	wsvc_desetup_worker();
	service_deinit(svr, cfg);
	free(service_cfgfile);
	if(service_stop_event) (void)WSACloseEvent(service_stop_event);
	verbose(VERB_QUERY, "winservice - full stop");
	report_status(SERVICE_STOPPED, NO_ERROR, 0);
}

/** start the service */
static void 
service_start(const char* cfgfile, int v, int c)
{
	SERVICE_TABLE_ENTRY myservices[2] = {
		{SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)service_main},
		{NULL, NULL} };
	verbosity=v;
	if(verbosity >= VERB_QUERY) {
		/* log to file about start sequence */
		fclose(fopen("C:\\dnssectrigger.log", "w"));
		log_init("C:\\dnssectrigger.log", 0, 0);
		verbose(VERB_QUERY, "open logfile");
	} else log_init(0, 1, 0); /* otherwise, use Application log */
	if(c) {
		service_cfgfile = strdup(cfgfile);
		if(!service_cfgfile) fatal_exit("out of memory");
	} else 	service_cfgfile = NULL;
	service_cmdline_verbose = v;
	/* this call returns when service has stopped. */
	if(!StartServiceCtrlDispatcher(myservices)) {
		reportev("Could not StartServiceCtrlDispatcher");
	}
}

void
wsvc_command_option(const char* wopt, const char* cfgfile, int v, int c)
{
	if(strcmp(wopt, "install") == 0)
		wsvc_install(stdout, NULL);
	else if(strcmp(wopt, "remove") == 0)
		wsvc_remove(stdout);
	else if(strcmp(wopt, "service") == 0)
		service_start(cfgfile, v, c);
	else fatal_exit("unknown option: %s", wopt);
}

void
worker_win_stop_cb(int ATTR_UNUSED(fd), short ATTR_UNUSED(ev),
	void* ATTR_UNUSED(arg))
{
        verbose(VERB_QUERY, "caught stop signal (wsaevent)");
        comm_base_exit(global_svr->base);
}

/** log a windows GetLastError message */
void log_win_err(const char* str, DWORD err)
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

typedef HANDLE ub_thread_t;
void ub_thread_create(ub_thread_t* thr, void* (*func)(void*), void* arg)
{
#ifndef HAVE__BEGINTHREADEX
	*thr = CreateThread(NULL, /* default security (no inherit handle) */
		0, /* default stack size */
		(LPTHREAD_START_ROUTINE)func, arg,
		0, /* default flags, run immediately */
		NULL); /* do not store thread identifier anywhere */
#else
	/* the begintheadex routine setups for the C lib; aligns stack */
	*thr=(ub_thread_t)_beginthreadex(NULL, 0, (void*)func, arg, 0, NULL);
#endif
	if(*thr == NULL) {
		log_win_err("CreateThread failed", GetLastError());
		fatal_exit("thread create failed");
	}
}

/** wait for cron process to finish */
static void
waitforit(PROCESS_INFORMATION* pinfo)
{
	DWORD ret = WaitForSingleObject(pinfo->hProcess, INFINITE);
	verbose(VERB_ALGO, "cronaction done");
	if(ret != WAIT_OBJECT_0) {
		return; /* did not end successfully */
	}
	if(!GetExitCodeProcess(pinfo->hProcess, &ret)) {
		log_err("GetExitCodeProcess failed");
		return;
	}
	verbose(VERB_ALGO, "exit code is %d", (int)ret);
	if(ret != 1) {
		if(!WSASetEvent(service_stop_event))
			log_err("Could not WSASetEvent: %s",
			wsa_strerror(WSAGetLastError()));
	}
}

/** Do the cron action and wait for result exit value */
static void*
win_do_cron(void* ATTR_UNUSED(arg))
{
	char* cronaction;
 	cronaction = lookup_reg_str("Software\\DnssecTrigger", "CronAction");
	if(cronaction && strlen(cronaction)>0) {
		STARTUPINFO sinfo;
		PROCESS_INFORMATION pinfo;
		memset(&pinfo, 0, sizeof(pinfo));
		memset(&sinfo, 0, sizeof(sinfo));
		sinfo.cb = sizeof(sinfo);
		verbose(VERB_ALGO, "cronaction: %s", cronaction);
		if(!CreateProcess(NULL, cronaction, NULL, NULL, 0, 
			CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo))
			log_err("CreateProcess error");
		else {
			waitforit(&pinfo);
			CloseHandle(pinfo.hProcess);
			CloseHandle(pinfo.hThread);
		}
	}
	free(cronaction);
	/* stop self */
	CloseHandle(cron_thread);
	cron_thread = NULL;
	return NULL;
}

/** Set the timer for cron for the next wake up */
static void
set_cron_timer()
{
	struct timeval tv;
	int crontime;
	if(cron_was_quick == 0) {
		cron_was_quick = 1;
		crontime = 3600; /* first update some time after boot */
	} else {
		crontime = lookup_reg_int("Software\\DnssecTrigger", "CronTime");
		if(crontime == 0) crontime = 60*60*24; /* 24 hours */
	}
	memset(&tv, 0, sizeof(tv));
	tv.tv_sec = (time_t)crontime;
	comm_timer_set(service_cron, &tv);
}

void
wsvc_cron_cb(void* arg)
{
	/* perform cronned operation */
	verbose(VERB_ALGO, "cron timer callback");
	if(cron_thread == NULL) {
		/* create new thread to do it */
		ub_thread_create(&cron_thread, win_do_cron, arg);
	}
	/* reschedule */
	set_cron_timer();
}

void wsvc_setup_worker(struct comm_base* base)
{
	/* if not started with -w service, do nothing */
	if(!service_stop_event)
		return;
	if(!winsock_register_wsaevent(comm_base_internal(base),
		&service_stop_ev, service_stop_event,
		&worker_win_stop_cb, NULL)) {
		fatal_exit("could not register wsaevent");
		return;
	}
	if(!service_cron) {
		service_cron = comm_timer_create(base, 
			&wsvc_cron_cb, NULL);
		if(!service_cron)
			fatal_exit("could not create cron timer");
		set_cron_timer();
	}
}

void wsvc_desetup_worker(void)
{
	comm_timer_delete(service_cron);
	service_cron = NULL;
}

int win_run_cmd(char* cmd)
{
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	DWORD ret;
	memset(&pinfo, 0, sizeof(pinfo));
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);

	/* start it */
	if(!CreateProcess(NULL, cmd, NULL, NULL, 0, CREATE_NO_WINDOW,
		NULL, NULL, &sinfo, &pinfo)) {
		log_win_err(cmd, GetLastError());
		return -1;
	}

	/* wait for it */
	if(WaitForSingleObject(pinfo.hProcess, INFINITE) == WAIT_FAILED) {
		log_win_err("cannot WaitForSingleObject(exe):", GetLastError());
	}
	if(!GetExitCodeProcess(pinfo.hProcess, &ret)) {
		log_win_err("cannot GetExitCodeProcess", GetLastError());
		ret = -1;
	}
	CloseHandle(pinfo.hProcess);
	CloseHandle(pinfo.hThread);
	return ret;
}

/** enumerate all subkeys of base, and call process(hk, arg) on them */
void enum_guids(const char* base, void (*process_it)(HKEY,void*), void* arg)
{
	char subname[1024];
	HKEY base_hk, sub_hk;
	DWORD sz = sizeof(subname);
	DWORD i = 0, ret;
	if(RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)base,
		0, /* reserved, mustbezero */
		NULL, /* class of key, ignored */
		REG_OPTION_NON_VOLATILE, /* values saved on disk */
		KEY_WRITE|KEY_ENUMERATE_SUB_KEYS,
		NULL, /* use default security descriptor */
		&base_hk, /* result */
		NULL)) /* not interested if key new or existing */
	{
		log_win_err("could not open enum registry key", GetLastError());
		return;
	}
	while( (ret=RegEnumKeyEx(base_hk, i, (LPTSTR)subname, &sz, NULL, NULL,
		0, NULL)) == ERROR_SUCCESS) {
		verbose(VERB_ALGO, "enum %d %s", (int)i, subname);
		/* process it */
		if(RegOpenKeyEx(base_hk, (LPCTSTR)subname, 0, KEY_WRITE,
			&sub_hk)) {
			log_win_err("enum cannot RegOpenKey", GetLastError());
		} else {
			(*process_it)(sub_hk, arg);
			RegCloseKey(sub_hk);
		}
		/* prepare for next iteration */
		i++;
		sz = sizeof(subname);
	}
	if(ret == ERROR_MORE_DATA) {
		log_err("part of %s has registry keys that are too long", base);
	} else if(ret != ERROR_NO_MORE_ITEMS) {
		log_win_err("cannot RegEnumKey", GetLastError());
	}
	RegCloseKey(base_hk);	
}

static void
enum_set_nameserver(HKEY hk, void* arg)
{
	DWORD len = 0;
	if(arg) len = strlen((char*)arg);
	if(RegSetValueEx(hk, (LPCTSTR)"NameServer", 0, REG_SZ,
		(BYTE*)arg, (DWORD)len)) {
		log_win_err("could not enumset regkey NameServer", GetLastError());
	}
}

void win_set_resolv(char* ip)
{
	const char* key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip"
		"\\Parameters";
	const char* ifs = "SYSTEM\\CurrentControlSet\\services\\Tcpip"
		"\\Parameters\\Interfaces";
	HKEY hk;
	verbose(VERB_DETAIL, "set reg %s", ip);

	/* needs administrator permissions */
	if(RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)key,
		0, /* reserved, mustbezero */
		NULL, /* class of key, ignored */
		REG_OPTION_NON_VOLATILE, /* values saved on disk */
		KEY_WRITE, /* we want write permission */
		NULL, /* use default security descriptor */
		&hk, /* result */
		NULL)) /* not interested if key new or existing */
	{
		log_win_err("could not open registry key", GetLastError());
	} else {
		/* set NameServer */
		if(RegSetValueEx(hk, (LPCTSTR)"NameServer", 0, REG_SZ,
			(BYTE*)ip, (DWORD)strlen(ip)+1)) {
			log_win_err("could not set regkey NameServer", GetLastError());
		}
		RegCloseKey(hk);
	}

	/* set all interfaces/guid/nameserver */
	enum_guids(ifs, &enum_set_nameserver, ip);
}

void win_clear_resolv(void)
{
	const char* key = "SYSTEM\\CurrentControlSet\\Services\\Tcpip"
		"\\Parameters";
	const char* ifs = "SYSTEM\\CurrentControlSet\\services\\Tcpip"
		"\\Parameters\\Interfaces";
	HKEY hk;
	verbose(VERB_DETAIL, "clear reg");
	if(RegCreateKeyEx(HKEY_LOCAL_MACHINE, (LPCTSTR)key,
		0, /* reserved, mustbezero */
		NULL, /* class of key, ignored */
		REG_OPTION_NON_VOLATILE, /* values saved on disk */
		KEY_WRITE, /* we want write permission */
		NULL, /* use default security descriptor */
		&hk, /* result */
		NULL)) /* not interested if key new or existing */
	{
		log_win_err("could not create registry key", GetLastError());
	} else {
		if(RegSetValueEx(hk, (LPCTSTR)"NameServer", 0, REG_SZ,
			(BYTE*)NULL, (DWORD)0)) {
			log_win_err("could not zero regkey NameServer", GetLastError());
		}
		RegCloseKey(hk);
	}
	enum_guids(ifs, &enum_set_nameserver, NULL);
}
