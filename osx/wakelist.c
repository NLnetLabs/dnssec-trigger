/*
 * wakelist.c - dnssec-trigger OSX sleep and wake listener.
 *
 * Copyright (c) 2013, NLnet Labs. All rights reserved.
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
 * This file contains the OSX sleep and wakeup listener service.
 */
#include "config.h"
#include "riggerd/cfg.h"
#include "riggerd/log.h"
#include "osx/wakelist.h"

#include <pthread.h>

#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>

#include <mach/mach_port.h>
#include <mach/mach_interface.h>
#include <mach/mach_init.h>

#include <IOKit/pwr_mgt/IOPMLib.h>
#include <IOKit/IOMessage.h>

/* a reference to the Root Power Domain IOService */
static io_connect_t root_port; 
static char* unbound_control;

/* perform unbound command, from OSX thread */
static void
osx_ub_ctrl(const char* cmd)
{
	char s[12000];
	int r;

	verbose(VERB_ALGO, "system %s %s", unbound_control, cmd);
	snprintf(s, sizeof(s), "%s %s", unbound_control, cmd);
	r = system(command);
	if(r == -1) {
		log_err("system(%s) failed: %s", ctrl, strerror(errno));
	} else if(r != 0) {
		log_warn("unbound-control exited with status %d, cmd: %s", r, s);
	}

}

/* called when OSX power status changes notifications happen */
static void
sleepcallback(void* arg, io_service_t ATTR_UNUSED(service),
	natural_t messageType, void* messageArgument )
{
	verbose(VERB_ALGO, "OSX sleepIO messageType %08lx, arg %08lx\n",
		(long unsigned int)messageType,
		(long unsigned int)messageArgument );
	if(messageType == kIOMessageCanSystemSleep) {
		/* allow the system to sleep */
		IOAllowPowerChange(root_port, (long)messageArgument);
	} else if(messageType == kIOMessageSystemWillSleep) {
		/* do not delay sleep */
		IOAllowPowerChange(root_port, (long)messageArgument);
	} else if(messageType == kIOMessageSystemWillPowerOn) {
		/* system has started the wake up process */
		/* assume we are on a new network */
		osx_ub_ctrl("flush_infra all");
		osx_ub_ctrl("flush_bogus");
		osx_ub_ctrl("flush_requestlist");
	} else if(messageType == kIOMessageSystemHasPoweredOn) {
		/* system has finished the wake up process */
		log_info("finishwake");
	}
}

static void*
osx_wakesleep_thread(void* ATTR_UNUSED(arg))
{
	/* attach sleep and wake listener as described in apple note QA1340.
	 * http://developer.apple.com/library/mac/#qa/qa1340/_index.html
	 * This creates a thread that listens to the sleep and wake up
	 * notifications (it allows sleep), and notifies dnssec-trigger about
	 * these events.  The thread is killed when the process exits.
	 */
	/* notification port allocated by IORegisterForSystemPower */
	IONotificationPortRef notifyPortRef; 
	/* notifier object, used to deregister later,
	 * but we let the system cleanup this thread */
	io_object_t notifierObject; 

	/* register to receive system sleep notifications */
	root_port = IORegisterForSystemPower(NULL/*myarg*/, &notifyPortRef,
		sleepcallback, &notifierObject);
	if(!root_port) {
		/* could this be a permission issue? if so, just exit thread,
		 * and do not monitor for system power changes */
		log_err("IORegisterForSystemPower failed: %s", strerror(errno));
		return NULL;
	}

	/* add notification port to the runloop */
	CFRunLoopAddSource(CFRunLoopGetCurrent(),
		IONotificationPortGetRunLoopSource(notifyPortRef),
		kCFRunLoopCommonModes ); 
	/* run the loop to get notifications. */
	CFRunLoopRun();

	/* free(unbound_control) */
	/* deregister and cleanup notification */
	/* ENOTREACH */
	return NULL;
}

void osx_wakelistener_start(struct cfg* cfg)
{
	/* create the thread */
	/* marks the thread as detached, so that on exit() the thread can
	 * get removed by the operating system quickly */
    	pthread_attr_t attr;
        pthread_t id;

	if(cfg->noaction)
		return;

	/* copy cfg elements of interest for threadsafe access.
	 * The cfg itself can be detroyed when sighup causes a reload. */
	if(cfg->unbound_control)
		unbound_control = strdup(cfg->unbound_control);
	else	unbound_control = strdup("unbound-control");
	if(!unbound_control)
		fatal_exit("malloc failure");

	if(pthread_attr_init(&attr) != 0)
		fatal_exit("osxsleepwake: could not pthread_attr_init");
	if(pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED) != 0)
		fatal_exit("osxsleepwake: could not pthread_attr_setdetach");
	if(pthread_create(&id, &attr, osx_wakesleep_thread, NULL) != 0)
		fatal_exit("osxsleepwake: could not pthread_create");
	if(pthread_attr_destroy(&attr) != 0)
		fatal_exit("osxsleepwake: could not pthread_attr_destroy");
}
