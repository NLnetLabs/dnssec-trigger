/**
 * Trayicon.c -- show tray icon in system notification area.
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
 * This file is a windows WinMain() tray icon.  It works as the 
 * dnssec-trigger-panel that shows the state of dnssec.
 */
#include "config.h"
#define _WIN32_IE 0x0502
#include <windows.h>
#include <windowsx.h>
#include <shellapi.h>
#include <commctrl.h>
#include <signal.h>
#include "riggerd/log.h"
#include "riggerd/cfg.h"
#include "panel/attach.h"

static UINT WM_TASKBARCREATED;
static NOTIFYICONDATA notifydata;
static TCHAR trayclassname[] = TEXT("dnssec trigger tray icon");
static TCHAR insecclassname[] = TEXT("Network DNSSEC Failure");
static TCHAR hotsignclassname[] = TEXT("Hotspot Signon");
static TCHAR nowebclassname[] = TEXT("No Web Access");
static TCHAR updateclassname[] = TEXT("Dnssec Trigger Software Update");
#define ID_TRAY_APP_ICON 5000
#define WM_TRAYICON (WM_USER + 1)
#define WM_PANELALERT (WM_USER + 2)
#define WM_PANELUPDATEALERT (WM_USER + 3)
#define ID_TRAY_MENU_QUIT 3000
#define ID_TRAY_MENU_REPROBE 3001
#define ID_TRAY_MENU_PROBERESULTS 3002
#define ID_TRAY_MENU_HOTSPOTSIGNON 3003
static HWND mainwnd;
static HMENU mainmenu;
/* this one is small */
static HICON status_icon;
/* high def version */
static HICON status_icon_big;

/* alert icons */
static HICON status_icon_alert;
static HICON status_icon_alert_big;

/* the edit box with text list of probe results */
static HWND resultbox;
/* the OK button on the probe results page */
static HWND resultok;

/* the insecure window */
static HWND insec_wnd;
/* insecure 'go insecure' button */
static HWND insec_unsafe;
/* insecure 'disconnect' button */
static HWND insec_discon;

/* the hotspot signon dialog */
static HWND hotsign_wnd;
/* hotsign 'OK' button */
static HWND hotsign_ok;
/* hotsign 'Cancel' button */
static HWND hotsign_cancel;

/* the noweb dialog */
static HWND noweb_wnd;
/* the 'Skip' button */
static HWND noweb_skip;
/* the 'Login' button */
static HWND noweb_login;

/* the update dialog */
static HWND update_wnd;
/* the update text */
static HWND update_label;
/* the 'OK' button on update */
static HWND update_ok;
/* the 'Cancel' button on update */
static HWND update_cancel;
/* new version for update */
static char* update_new_version;

/** if we have asked about disconnect or insecure */
static int unsafe_asked = 0;
/** if we should ask unsafe */
static int unsafe_should = 0;
/** if we have asked about noweb */
static int noweb_asked = 0;

static void panel_alert(void);
static void panel_dialog(void);
static void noweb_dialog(void);
static void panel_update_alert(void);

static HFONT font;
static HFONT font_bold;

static void init_font(void)
{
	/* normal font */
	font = CreateFont(16, 0, 0, 0, 550, FALSE, FALSE, FALSE, ANSI_CHARSET,
		OUT_TT_ONLY_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
		DEFAULT_PITCH, "MS Outlook"); 
	if(!font) log_err("CreateFont failed");
	font_bold = CreateFont(16, 0, 0, 0, 700, FALSE, FALSE, FALSE, 
		ANSI_CHARSET, OUT_TT_ONLY_PRECIS, CLIP_DEFAULT_PRECIS,
		DEFAULT_QUALITY, DEFAULT_PITCH, "MS Outlook"); 
	if(!font_bold) log_err("CreateFont failed");
}

static void
init_insecwnd(HINSTANCE hInstance)
{
	HWND statictext;
	/* insecure window:
	 * static text with explanation.
	 * Disconnect and Insecure buttons */
	insec_wnd = CreateWindowEx(0, insecclassname,
		TEXT("Network DNSSEC Failure"),
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
		WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
		455, 450, NULL, NULL, hInstance, NULL);
	statictext = CreateWindow(TEXT("STATIC"), TEXT(
"The Network Fails to Support DNSSEC\r\n"
"\r\n"
"The network you are connected to does not allow DNSSEC, via\r\n"
"the provided DNS caches, nor via contacting servers on the\r\n"
"internet directly (it filters traffic to this end).  It is not possible\r\n"
"to provide DNSSEC security, but you can connect insecurely.\r\n"
"\r\n"
"Do you want to connect insecurely?\r\n"
"\r\n"
"* if you choose Disconnect then DNS is disabled. It is safe,\r\n"
"but there is very little that works.\r\n"
"\r\n"
"* if you choose Insecure then the DNSSEC security is lost.\r\n"
"You can connect and work. But there is no safety. The network\r\n"
"interferes with DNSSEC, it may also interfere with other things.\r\n"
"Have caution and work with sensitive personal and financial\r\n"
"things some other time.\r\n"
"\r\n"
"Some hotspots may work after you have gained access via\r\n"
"its signon page. Then use Reprobe from the menu to retry.\r\n"
"\r\n"
"Stay safe out there!\r\n"
		), WS_CHILD | WS_VISIBLE | SS_LEFT,
		10, 10, 430, 370, insec_wnd, NULL, hInstance, NULL);
	insec_discon = CreateWindow(TEXT("BUTTON"), TEXT("Disconnect"),
		WS_CHILD | WS_VISIBLE,
		180, 390, 100, 25, insec_wnd, NULL, hInstance, NULL);
	insec_unsafe = CreateWindow(TEXT("BUTTON"), TEXT("Insecure"),
		WS_CHILD | WS_VISIBLE,
		300, 390, 100, 25, insec_wnd, NULL, hInstance, NULL);
	SendMessage(statictext, WM_SETFONT, (WPARAM)font, TRUE);
	SendMessage(insec_discon, WM_SETFONT, (WPARAM)font_bold, TRUE);
	SendMessage(insec_unsafe, WM_SETFONT, (WPARAM)font_bold, TRUE);
	ShowWindow(insec_wnd, SW_HIDE);
}

static void
init_hotsignwnd(HINSTANCE hInstance)
{
	HWND statictext;
	/* hotspot signon dialog:
	 * static text with explanation.
	 * Cancel and OK buttons */
	hotsign_wnd = CreateWindowEx(0, hotsignclassname,
		TEXT("Hotspot Signon"),
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
		WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
		455, 150, NULL, NULL, hInstance, NULL);
	statictext = CreateWindow(TEXT("STATIC"), TEXT(
"Some networks need insecure signon. After you log in to the\r\n"
"network via its portal page, select Reprobe to get secure again.\r\n"
"\r\n"
"Please, stay safe out there.\r\n"
	), WS_CHILD | WS_VISIBLE | SS_LEFT,
		10, 10, 430, 70, hotsign_wnd, NULL, hInstance, NULL);
	hotsign_cancel = CreateWindow(TEXT("BUTTON"), TEXT("Cancel"),
		WS_CHILD | WS_VISIBLE,
		180, 90, 100, 25, hotsign_wnd, NULL, hInstance, NULL);
	hotsign_ok = CreateWindow(TEXT("BUTTON"), TEXT("OK"),
		WS_CHILD | WS_VISIBLE,
		300, 90, 100, 25, hotsign_wnd, NULL, hInstance, NULL);
	SendMessage(statictext, WM_SETFONT, (WPARAM)font, TRUE);
	SendMessage(hotsign_cancel, WM_SETFONT, (WPARAM)font_bold, TRUE);
	SendMessage(hotsign_ok, WM_SETFONT, (WPARAM)font_bold, TRUE);
	ShowWindow(hotsign_wnd, SW_HIDE);
}

static void
init_nowebwnd(HINSTANCE hInstance)
{
	HWND statictext;
	/* no web access dialog:
	 * static text with explanation.
	 * Skip and Login buttons */
	noweb_wnd = CreateWindowEx(0, nowebclassname,
		TEXT("No Web Access"),
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
		WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
		455, 190, NULL, NULL, hInstance, NULL);
	statictext = CreateWindow(TEXT("STATIC"), TEXT(
"There is no web access on this network. Do you have to login for that?\r\n"
"\r\n"
"While you login you are insecure, for backwards compatibility, until\r\n"
"dnssec-trigger can detect web access.\r\n"
"\r\n"
"Skip this if you do not have to log in on this network.\r\n"
	), WS_CHILD | WS_VISIBLE | SS_LEFT,
		10, 10, 430, 110, noweb_wnd, NULL, hInstance, NULL);
	noweb_skip = CreateWindow(TEXT("BUTTON"), TEXT("Skip"),
		WS_CHILD | WS_VISIBLE,
		190, 130, 100, 25, noweb_wnd, NULL, hInstance, NULL);
	noweb_login = CreateWindow(TEXT("BUTTON"), TEXT("Log in"),
		WS_CHILD | WS_VISIBLE,
		310, 130, 100, 25, noweb_wnd, NULL, hInstance, NULL);
	SendMessage(statictext, WM_SETFONT, (WPARAM)font, TRUE);
	SendMessage(noweb_skip, WM_SETFONT, (WPARAM)font_bold, TRUE);
	SendMessage(noweb_login, WM_SETFONT, (WPARAM)font_bold, TRUE);
	ShowWindow(noweb_wnd, SW_HIDE);
}

static void
init_updatewnd(HINSTANCE hInstance)
{
	/* update dialog:
	 * text with explanation (and version number)
	 * Cancel and OK buttons */
	update_wnd = CreateWindowEx(0, updateclassname,
		TEXT("Software Update Dnssec Trigger"),
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX |
		WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
		455, 150, NULL, NULL, hInstance, NULL);
	update_label = CreateWindow(TEXT("STATIC"), TEXT(
"There is a software update available for dnssec-trigger.\r\n"
"Do you wish to install the update?\r\n"
	), WS_CHILD | WS_VISIBLE | SS_LEFT,
		10, 10, 430, 70, update_wnd, NULL, hInstance, NULL);
	update_cancel = CreateWindow(TEXT("BUTTON"), TEXT("Cancel"),
		WS_CHILD | WS_VISIBLE,
		180, 90, 100, 25, update_wnd, NULL, hInstance, NULL);
	update_ok = CreateWindow(TEXT("BUTTON"), TEXT("OK"),
		WS_CHILD | WS_VISIBLE,
		300, 90, 100, 25, update_wnd, NULL, hInstance, NULL);
	SendMessage(update_label, WM_SETFONT, (WPARAM)font, TRUE);
	SendMessage(update_cancel, WM_SETFONT, (WPARAM)font_bold, TRUE);
	SendMessage(update_ok, WM_SETFONT, (WPARAM)font_bold, TRUE);
	ShowWindow(update_wnd, SW_HIDE);
}

static void
init_mainwnd(HINSTANCE hInstance)
{
	/* probe results dialog:
	 * multiline edit with the results.
	 * OK button */
	mainwnd = CreateWindowEx(0, trayclassname, TEXT("Probe Results"),
		WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU | WS_MINIMIZEBOX | WS_MAXIMIZEBOX, CW_USEDEFAULT, CW_USEDEFAULT,
		450, 280, NULL, NULL, hInstance, NULL);
	resultbox = CreateWindow(TEXT("EDIT"), TEXT("probe results"),
		WS_CHILD | WS_VISIBLE | WS_VSCROLL |
		ES_MULTILINE | ES_READONLY | ES_AUTOVSCROLL | ES_AUTOHSCROLL,
		10, 10, 420, 195, mainwnd, NULL, hInstance, NULL);
	resultok = CreateWindow(TEXT("BUTTON"), TEXT("OK"),
		WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
		290, 215, 100, 25, mainwnd, NULL, hInstance, NULL);
	SendMessage(resultbox, WM_SETFONT, (WPARAM)font, TRUE);
	SendMessage(resultok, WM_SETFONT, (WPARAM)font_bold, TRUE);
}

static void
init_icon(void)
{
	memset(&notifydata, 0, sizeof(notifydata));
	notifydata.cbSize = sizeof(notifydata);
	notifydata.hWnd = mainwnd;
	notifydata.uID = ID_TRAY_APP_ICON;
	/* flags for icon, wndmessage on click, and show tooltip */
	notifydata.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
	notifydata.uCallbackMessage = WM_TRAYICON;
	notifydata.hIcon = status_icon;
	/* tooltip (less than 64 chars) */
	strcpy(notifydata.szTip, TEXT("dnssec-trigger"));
	if(!Shell_NotifyIcon(NIM_ADD, &notifydata)) {	
		log_err("cannot Shell_NotifyIcon");
	}
}

static void
panel_proberesults(void)
{
	char buf[102400];
	fetch_proberesults(buf, sizeof(buf), "\r\n");
	Edit_SetText(resultbox, buf);
	ShowWindow(mainwnd, SW_SHOW);
}

/* run software updater on windows: create the process */
static void win_run_updater(char* filename)
{
	char* ubdir = w_lookup_reg_str("Software\\Unbound", "InstallLocation");
	char cmdline[1024];
	STARTUPINFO sinfo;
	PROCESS_INFORMATION pinfo;
	memset(&pinfo, 0, sizeof(pinfo));
	memset(&sinfo, 0, sizeof(sinfo));
	sinfo.cb = sizeof(sinfo);
	if(!ubdir) {
		log_err("out of memory or improper registry in reinstall, "
			"please reinstall manually");
		return;
	}
	/* case sensitive /S and /D. /D must be last on the line and without
	   quotes (even if there are spaces in the path) */
	/* CMD /C shows UAC privilege elevation dialog to the user */
	snprintf(cmdline, sizeof(cmdline), "CMD /C \"%s\" /S /delself /D=%s", filename, ubdir);
	free(ubdir);
	if(!CreateProcess(NULL, cmdline, NULL, NULL, 0,
		CREATE_NO_WINDOW, NULL, NULL, &sinfo, &pinfo))
		log_err("CreateProcess Error %d for cmdline: %s",
			(int)GetLastError(), cmdline);
		/*log_win_err("CreateProcess failed", GetLastError());*/
	else {
		/* we do not wait for this, it will attempt to stop the
		   service to update this executable, so we need to go back
		   to our runloop */
		CloseHandle(pinfo.hProcess);
		CloseHandle(pinfo.hThread);
	}
}

/* start software updater given version number */
static void win_update_to_version(char* version)
{
	char* uidir = w_lookup_reg_str("Software\\Unbound", "InstallLocation");
	char fname[260];
	if(!uidir) {
		log_err("out of memory or improper registry in reinstall, "
			"please reinstall manually");
		return;
	}
	snprintf(fname, sizeof(fname), "%s\\dnssec_trigger_setup_%s.exe",
		uidir, version);
	free(uidir);
	win_run_updater(fname);
}

LRESULT CALLBACK InsecWndProc(HWND hwnd, UINT message, WPARAM wParam,
	LPARAM lParam)
{
	switch(message) {
	case WM_SYSCOMMAND:
		switch(wParam & 0xfff0) { /* removes reserved lower 4 bits */
		case SC_MINIMIZE:
			break;
		case SC_CLOSE:
			unsafe_asked = 1;
			unsafe_should = 0;
			attach_send_insecure(0);
			ShowWindow(insec_wnd, SW_HIDE);
			return 0;
			break;
		}
		break;
	case WM_COMMAND:
		/* buttons pressed */
		if((HWND)lParam == insec_discon) {
			unsafe_asked = 1;
			unsafe_should = 0;
			attach_send_insecure(0);
			ShowWindow(insec_wnd, SW_HIDE);
		} else if((HWND)lParam == insec_unsafe) {
			unsafe_asked = 1;
			unsafe_should = 0;
			attach_send_insecure(1);
			ShowWindow(insec_wnd, SW_HIDE);
		}
		break;
	case WM_CLOSE:
		unsafe_asked = 1;
		unsafe_should = 0;
		attach_send_insecure(0);
		ShowWindow(insec_wnd, SW_HIDE);
		return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK HotsignWndProc(HWND hwnd, UINT message, WPARAM wParam,
	LPARAM lParam)
{
	switch(message) {
	case WM_SYSCOMMAND:
		switch(wParam & 0xfff0) { /* removes reserved lower 4 bits */
		case SC_MINIMIZE:
			break;
		case SC_CLOSE:
			ShowWindow(hotsign_wnd, SW_HIDE);
			if(unsafe_should) panel_dialog();
			return 0;
			break;
		}
		break;
	case WM_COMMAND:
		/* buttons pressed */
		if((HWND)lParam == hotsign_cancel) {
			ShowWindow(hotsign_wnd, SW_HIDE);
			if(unsafe_should) panel_dialog();
		} else if((HWND)lParam == hotsign_ok) {
			attach_send_hotspot_signon();
			ShowWindow(hotsign_wnd, SW_HIDE);
			unsafe_asked = 1;
			unsafe_should = 0;
		}
		break;
	case WM_CLOSE:
		ShowWindow(hotsign_wnd, SW_HIDE);
		if(unsafe_should) panel_dialog();
		return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK NowebWndProc(HWND hwnd, UINT message, WPARAM wParam,
	LPARAM lParam)
{
	switch(message) {
	case WM_SYSCOMMAND:
		switch(wParam & 0xfff0) { /* removes reserved lower 4 bits */
		case SC_MINIMIZE:
			break;
		case SC_CLOSE:
			ShowWindow(noweb_wnd, SW_HIDE);
			attach_send_skip_http();
			noweb_asked = 1;
			return 0;
			break;
		}
		break;
	case WM_COMMAND:
		/* buttons pressed */
		if((HWND)lParam == noweb_skip) {
			ShowWindow(noweb_wnd, SW_HIDE);
			attach_send_skip_http();
			noweb_asked = 1;
		} else if((HWND)lParam == noweb_login) {
			ShowWindow(noweb_wnd, SW_HIDE);
			attach_send_insecure(1);
			noweb_asked = 1;
			/* show web browser */
			if(feed->cfg->login_command &&
				feed->cfg->login_command[0]) {
				sleep(1); /* wait for DNS to percolate */
				(void)ShellExecute(NULL,
					feed->cfg->login_command,
					feed->cfg->login_location,
					NULL, NULL, SW_SHOWNORMAL);
			}
		}
		break;
	case WM_CLOSE:
		ShowWindow(noweb_wnd, SW_HIDE);
		attach_send_skip_http();
		noweb_asked = 1;
		return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK UpdateWndProc(HWND hwnd, UINT message, WPARAM wParam,
	LPARAM lParam)
{
	switch(message) {
	case WM_SYSCOMMAND:
		switch(wParam & 0xfff0) { /* removes reserved lower 4 bits */
		case SC_MINIMIZE:
			break;
		case SC_CLOSE:
			ShowWindow(update_wnd, SW_HIDE);
			attach_send_update_cancel();
			return 0;
			break;
		}
		break;
	case WM_COMMAND:
		/* buttons pressed */
		if((HWND)lParam == update_cancel) {
			ShowWindow(update_wnd, SW_HIDE);
			attach_send_update_cancel();
		} else if((HWND)lParam == update_ok) {
			ShowWindow(update_wnd, SW_HIDE);
			attach_send_update_ok();
			if(update_new_version)
				win_update_to_version(update_new_version);
			free(update_new_version);
			update_new_version = NULL;
		}
		break;
	case WM_CLOSE:
		ShowWindow(update_wnd, SW_HIDE);
		attach_send_update_cancel();
		return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam)
{
	if(message==WM_TASKBARCREATED) {
		Shell_NotifyIcon(NIM_ADD, &notifydata);
		return 0;
	}
	switch(message) {
	case WM_CREATE:
		/* create the menu */
		mainmenu = CreatePopupMenu();
		AppendMenu(mainmenu, MF_STRING, ID_TRAY_MENU_REPROBE,
			TEXT("Reprobe"));
		AppendMenu(mainmenu, MF_STRING, ID_TRAY_MENU_PROBERESULTS,
			TEXT("Probe Results"));
		AppendMenu(mainmenu, MF_STRING, ID_TRAY_MENU_HOTSPOTSIGNON,
			TEXT("Hotspot Signon"));
		AppendMenu(mainmenu, MF_SEPARATOR, 0, NULL);
		AppendMenu(mainmenu, MF_STRING, ID_TRAY_MENU_QUIT,
			TEXT("Quit"));
		break;
	case WM_SYSCOMMAND:
		switch(wParam & 0xfff0) { /* removes reserved lower 4 bits */
		case SC_MINIMIZE:
			break;
		case SC_CLOSE:
			ShowWindow(mainwnd, SW_HIDE);
			return 0;
			break;
		}
		break;
	/* our own systray message */
	case WM_TRAYICON:
		if(wParam != ID_TRAY_APP_ICON) {
			/* warning: not from our tray icon */
		}
		/* left mousebutton press */
		if(lParam == WM_LBUTTONUP) {
			/* left mouse on tray icon */
			break;
		} else if(lParam == WM_RBUTTONDOWN) {
			POINT cur;
			GetCursorPos(&cur);
			/* make our popup show on top */
			SetForegroundWindow(hwnd);
			/* sends WM_COMMAND with the chosen menu item */
			if(!TrackPopupMenu(mainmenu, 0, cur.x, cur.y, 0,
				hwnd, NULL)) {
				log_err("cannot TrackPopupmenu");
			}
			/* force task switch to the app of the menu, this
			 * is an empty message to achieve it */
			PostMessage(hwnd, WM_NULL, 0, 0);
		}
		break;
	/* our own panel alert message */
	case WM_PANELALERT:
		panel_alert();
		break;
	/* our own panel update alert message */
	case WM_PANELUPDATEALERT:
		panel_update_alert();
		break;
	case WM_COMMAND:
		/* result window OK */
		if((HWND)lParam == resultok) {
			ShowWindow(mainwnd, SW_HIDE);
		}
		/* menu item is chosen */
		if(lParam == 0) {
			if(wParam == ID_TRAY_MENU_QUIT) {
				PostQuitMessage(0);
			} else if(wParam == ID_TRAY_MENU_REPROBE) {
				attach_send_reprobe();
			} else if(wParam == ID_TRAY_MENU_PROBERESULTS) {
				panel_proberesults();
			} else if(wParam == ID_TRAY_MENU_HOTSPOTSIGNON) {
				if(IsWindowVisible(insec_wnd)) {
					ShowWindow(insec_wnd, SW_HIDE);
				}
				ShowWindow(hotsign_wnd, SW_SHOW);
				SetForegroundWindow(hotsign_wnd);
			}
		}
		break;
	case WM_CLOSE:
		ShowWindow(mainwnd, SW_HIDE);
		return 0;
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	}
	return DefWindowProc(hwnd, message, wParam, lParam);
}

static void panel_danger(void)
{
	notifydata.hIcon = status_icon_alert;
	if(!Shell_NotifyIcon(NIM_MODIFY, &notifydata)) {
		log_err("cannot Shell_NotifyIcon modify icon");
	}
}

static void panel_safe(void)
{
	notifydata.hIcon = status_icon;
	if(!Shell_NotifyIcon(NIM_MODIFY, &notifydata)) {
		log_err("cannot Shell_NotifyIcon modify icon");
	}
}

static void panel_dialog(void)
{
	unsafe_should = 1;
	if(IsWindowVisible(hotsign_wnd))
		return; /* wait for hotspot signon question to finish */
	ShowWindow(insec_wnd, SW_SHOW);
	SetForegroundWindow(insec_wnd);
}

static void noweb_dialog(void)
{
	ShowWindow(noweb_wnd, SW_SHOW);
	SetForegroundWindow(noweb_wnd);
}

static void update_dialog(char* new_version)
{
	char update_text[1024];
	snprintf(update_text, sizeof(update_text),
		"There is a software update available for dnssec-trigger\r\n"
		"from %s to %s.\r\n"
		"Do you wish to install the update now?\r\n",
		PACKAGE_VERSION, new_version);
	if(!SetWindowText(update_label, update_text))
		log_err("Could not SetWindowText: %s",
			wsa_strerror(GetLastError()));
	ShowWindow(update_wnd, SW_SHOW);
	SetForegroundWindow(update_wnd);
	free(update_new_version);
	update_new_version = strdup(new_version);
}

static void do_args(char* str, int* debug, const char** cfgfile)
{
	char* p = str;
	/* find ' -dEOS' or ' -d ' or ' -c <file>' */
	while(p && *p) {
		while(*p == ' ')
			p++;
		if(strcmp(p, "-d") == 0 || strncmp(p, "-d ", 3) == 0) {
			*debug = 1;
		}
		else if(strncmp(p, "-c ", 3) == 0) {
			p += 3;
			while(*p == ' ')
				p++;
			*cfgfile = strdup(p);
			continue;
		}
		p = strchr(p, ' ');
	}
}

static const char*
get_ui_file(int debug, const char* uidir, const char* file)
{
	static char res[1024];
	if(debug)
		snprintf(res, sizeof(res), "winrc\\%s", file);
	else 	snprintf(res, sizeof(res), "%s\\%s", uidir, file);
	return res;
}

static RETSIGTYPE record_sigh(int sig)
{
	if(sig == SIGINT) {
		PostQuitMessage(0);
	}
	/* else ignored */
}

/* the threading and mutexes */
typedef LONG lock_basic_t;
static lock_basic_t feed_lock;
static lock_basic_t alert_lock;
static struct alert_arg alertinfo;
static char* updateinfo;
static HANDLE feed_thread;

void lock_basic_init(lock_basic_t* lock)
{
	/* implement own lock, because windows HANDLE as Mutex usage
	 * uses too many handles and would bog down the whole system. */
	(void)InterlockedExchange(lock, 0);
}

void lock_basic_destroy(lock_basic_t* lock)
{
	(void)InterlockedExchange(lock, 0);
}

void lock_basic_lock(lock_basic_t* lock)
{
	LONG wait = 1; /* wait 1 msec at first */

	while(InterlockedExchange(lock, 1)) {
		/* if the old value was 1 then if was already locked */
		Sleep(wait); /* wait with sleep */
		wait *= 2;   /* exponential backoff for waiting */
	}
	/* the old value was 0, but we inserted 1, we locked it! */
}

void lock_basic_unlock(lock_basic_t* lock)
{
	/* unlock it by inserting the value of 0. xchg for cache coherency. */
	(void)InterlockedExchange(lock, 0);
}

static void lock_feed_lock(void)
{
	lock_basic_lock(&feed_lock);
}

static void unlock_feed_lock(void)
{
	lock_basic_unlock(&feed_lock);
}

static void feed_quit(void)
{
	/* post a message to the main window (in another thread) */
	PostMessage(mainwnd, WM_DESTROY, 0, 0);
}

static void panel_update_alert(void)
{
	/* get info */
	char* new_version = NULL;
	lock_basic_lock(&alert_lock);
	new_version = updateinfo;
	updateinfo = NULL;
	lock_basic_unlock(&alert_lock);
	if(!new_version)
		return;

	update_dialog(new_version);
	free(new_version);
}

static void feed_update_alert(char* new_version)
{
	lock_basic_lock(&alert_lock);
	free(updateinfo);
	updateinfo = new_version;
	lock_basic_unlock(&alert_lock);
	/* post a message to the main window, so that it gets received
	 * by the main thread, since it has to do the GUI functions */
	if(!PostMessage(mainwnd, WM_PANELUPDATEALERT, 0, 0))
		log_err("could not PostMessage");
}

static void panel_alert(void)
{
	/* get info */
	struct alert_arg a;
	lock_basic_lock(&alert_lock);
	a = alertinfo;
	lock_basic_unlock(&alert_lock);
	
	/* update tooltip */
	snprintf(notifydata.szTip, sizeof(notifydata.szTip), "%s",
		state_tooltip(&a));

	/* twiddle the NIF_TIP flag to get the tooltip to update */
	notifydata.uFlags ^= NIF_TIP;
	if(!Shell_NotifyIcon(NIM_MODIFY, &notifydata)) {
		log_err("cannot Shell_NotifyIcon modify");
	}
	notifydata.uFlags ^= NIF_TIP;
	if(!Shell_NotifyIcon(NIM_MODIFY, &notifydata)) {
		log_err("cannot Shell_NotifyIcon modify");
	}

	/* handle it */
	process_state(&a, &unsafe_asked, &noweb_asked, &panel_danger,
		&panel_safe, &panel_dialog, &noweb_dialog);
	if(!a.now_dark) unsafe_should = 0;
}

static void feed_alert(struct alert_arg* a)
{
	lock_basic_lock(&alert_lock);
	alertinfo = *a;
	lock_basic_unlock(&alert_lock);
	/* post a message to the main window, so that it gets received
	 * by the main thread, since it has to do the GUI functions */
	if(!PostMessage(mainwnd, WM_PANELALERT, 0, 0))
		log_err("could not PostMessage");
}

static void* feed_start(void* arg)
{
	attach_start((struct cfg*)arg);
	return NULL;
}

static void spawn_feed(struct cfg* cfg)
{
	/* setup */
	attach_create();
	lock_basic_init(&feed_lock);
	lock_basic_init(&alert_lock);
	feed->lock = &lock_feed_lock;
	feed->unlock = &unlock_feed_lock;
	feed->quit = &feed_quit;
	feed->alert = &feed_alert;
	feed->update_alert = &feed_update_alert;

	/* run thread */
#ifndef HAVE__BEGINTHREADEX
	feed_thread = CreateThread(NULL, /* default security (no inherit handle) */
		0, /* default stack size */
		(LPTHREAD_START_ROUTINE)&feed_start, cfg,
		0, /* default flags, run immediately */
		NULL); /* do not store thread identifier anywhere */
#else
	/* the begintheadex routine setups for the C lib; aligns stack */
	feed_thread=(HANDLE)_beginthreadex(NULL, 0, (void*)&feed_start, cfg,
		0, NULL);
#endif
	if(feed_thread == NULL) {
		/*log_win_err("CreateThread failed", GetLastError());*/
		fatal_exit("thread create failed");
	}
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR args,
	int iCmdShow)
{
	MSG msg;
	WNDCLASSEX wnd;
	INITCOMMONCONTROLSEX icc;
	int debug = 0;
	const char* cfgfile = NULL;
	const char* uidir = NULL;
	int r;
	int smsz = 0;
	WSADATA wsa_data;
	struct cfg* cfg;
	(void)hPrevInstance;
	(void)iCmdShow;

	/* init wsa and log */
	log_ident_set("dnssec-trigger-panel");
	log_init(NULL, 0, NULL);
	if((r = WSAStartup(MAKEWORD(2,2), &wsa_data)) != 0)
		fatal_exit("WSAStartup failed: %s", wsa_strerror(r));

	/* inits common controls for vista/7 GUI looks */
	memset(&icc, 0, sizeof(icc));
	icc.dwSize = sizeof(icc);
	icc.dwICC = ICC_WIN95_CLASSES | ICC_STANDARD_CLASSES;
	InitCommonControlsEx(&icc);

	ERR_load_crypto_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	(void)SSL_library_init();
	
	/* get args */
	cfgfile = w_lookup_reg_str("Software\\DnssecTrigger", "ConfigFile");
	if(!cfgfile) cfgfile = CONFIGFILE;
	uidir = w_lookup_reg_str("Software\\DnssecTrigger", "InstallLocation");
	if(!uidir) uidir = UIDIR;
	do_args(args, &debug, &cfgfile);

	cfg = cfg_create(cfgfile);
	if(!cfg) fatal_exit("cannot read config %s", cfgfile);
	/* start signal handlers */
	if( signal(SIGTERM, record_sigh) == SIG_ERR ||
#ifdef SIGQUIT
		signal(SIGQUIT, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGBREAK
		signal(SIGBREAK, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGHUP
		signal(SIGHUP, record_sigh) == SIG_ERR ||
#endif
#ifdef SIGPIPE
		signal(SIGPIPE, SIG_IGN) == SIG_ERR ||
#endif
		signal(SIGINT, record_sigh) == SIG_ERR
	)
		log_err("install sighandler failed: %s\n", strerror(errno));

	/* if the taskbar crashes and is restarted (explorer.exe) then this
	 * message is sent so we can re-enter ourselves */
	WM_TASKBARCREATED = RegisterWindowMessageA("TaskbarCreated");
	if(GetSystemMetrics(SM_CXSMICON) > 16)
		smsz = 32;
	status_icon = (HICON)LoadImage(NULL,
		get_ui_file(debug, uidir, "status.ico"),
		IMAGE_ICON, smsz, smsz, LR_LOADFROMFILE);
	status_icon_big = (HICON)LoadImage(NULL,
		get_ui_file(debug, uidir, "status.ico"),
		IMAGE_ICON, 64, 64, LR_LOADFROMFILE);
	status_icon_alert = (HICON)LoadImage(NULL,
		get_ui_file(debug, uidir, "alert.ico"),
		IMAGE_ICON, smsz, smsz, LR_LOADFROMFILE);
	status_icon_alert_big = (HICON)LoadImage(NULL,
		get_ui_file(debug, uidir, "alert.ico"),
		IMAGE_ICON, 64, 64, LR_LOADFROMFILE);

	memset(&wnd, 0, sizeof(wnd));
	wnd.hInstance = hInstance;
	wnd.lpszClassName = trayclassname;
	wnd.lpfnWndProc = WndProc;
	wnd.style = CS_HREDRAW|CS_VREDRAW;
	wnd.cbSize = sizeof(wnd);
	wnd.hIcon = status_icon_big;
	wnd.hIconSm = status_icon;
	wnd.hCursor = LoadCursor(NULL, IDC_ARROW);
	wnd.hbrBackground = (HBRUSH)COLOR_APPWORKSPACE;
	if(!RegisterClassEx(&wnd)) {
		FatalAppExit(0, TEXT("Cannot RegisterClassEx"));
	}
	wnd.lpszClassName = insecclassname;
	wnd.hIcon = status_icon_alert_big;
	wnd.hIconSm = status_icon_alert;
	wnd.lpfnWndProc = InsecWndProc;
	if(!RegisterClassEx(&wnd)) {
		FatalAppExit(0, TEXT("Cannot RegisterClassEx"));
	}
	wnd.lpszClassName = hotsignclassname;
	wnd.hIcon = status_icon_alert_big;
	wnd.hIconSm = status_icon_alert;
	wnd.lpfnWndProc = HotsignWndProc;
	if(!RegisterClassEx(&wnd)) {
		FatalAppExit(0, TEXT("Cannot RegisterClassEx"));
	}
	wnd.lpszClassName = nowebclassname;
	wnd.hIcon = status_icon_alert_big;
	wnd.hIconSm = status_icon_alert;
	wnd.lpfnWndProc = NowebWndProc;
	if(!RegisterClassEx(&wnd)) {
		FatalAppExit(0, TEXT("Cannot RegisterClassEx"));
	}
	wnd.lpszClassName = updateclassname;
	wnd.hIcon = status_icon_big;
	wnd.hIconSm = status_icon;
	wnd.lpfnWndProc = UpdateWndProc;
	if(!RegisterClassEx(&wnd)) {
		FatalAppExit(0, TEXT("Cannot RegisterClassEx"));
	}

	init_font();
	init_mainwnd(hInstance);
	init_insecwnd(hInstance);
	init_hotsignwnd(hInstance);
	init_nowebwnd(hInstance);
	init_updatewnd(hInstance);
	ShowWindow(mainwnd, SW_HIDE);
	init_icon();
	spawn_feed(cfg);

	while(GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}
	Shell_NotifyIcon(NIM_DELETE, &notifydata);
	attach_stop();
	lock_basic_destroy(&feed_lock);
	lock_basic_destroy(&alert_lock);
	free(updateinfo);
	free(update_new_version);
	WSACleanup();
	return msg.wParam;
}

