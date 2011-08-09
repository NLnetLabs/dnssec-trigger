/*
 * riggerd/riggerd.c - implementation of dnssec-trigger daemon
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
 * Implementation of dnssec-trigger daemon.
 */

#include "config.h"
#include "log.h"
#include "netevent.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <signal.h>

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-triggerd [options]\n");
	printf(" -h             this help\n");
	printf(" -v             increase verbosity\n");
	printf(" -d             do not fork into the background\n");
	printf(" -c file        config file to read (default none)\n");
}

/** sighandler.  Since we must have one
 *  * @param sig: signal number.
 *   * @return signal handler return type (void or int).
 *    */
static RETSIGTYPE record_sigh(int sig)
{
	switch(sig) {
	case SIGHUP:
	case SIGTERM:
#ifdef SIGQUIT
	case SIGQUIT:
#endif
#ifdef SIGBREAK
	case SIGBREAK:
#endif
	case SIGINT:
		comm_base_exit(global_svr->base);
	break;
#ifdef SIGPIPE
	case SIGPIPE:
	break;
#endif
	default:
		log_err("ignoring signal %d", sig);
	}
}

/** store pid in pidfile */
static void
store_pid(char* pidfile)
{
	FILE* f;
	if(!pidfile || pidfile[0]==0)
		return;
	f = fopen(pidfile, "w");
	if(!f) fatal_exit("could not write pid %s: %s",
		pidfile, strerror(errno));
	if(fprintf(f, "%u\n", (unsigned)getpid()) < 0)
		fatal_exit("could not write pid %s: %s",
			pidfile, strerror(errno));
	fclose(f);
}

/** delete pidfile */
static void
unlink_pid(char* pidfile)
{
        unlink(pidfile);
}

/** do main work of daemon */
static void
do_main_work(const char* cfgfile, int nodaemonize)
{
        struct cfg* cfg;
        struct svr* svr;
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
                log_err("install sighandler: %s", strerror(errno));
        /* start daemon */
        cfg = cfg_create(cfgfile);
        if(!cfg) fatal_exit("could not create config");
        cfg_check_rlimit(cfg);
        svr = svr_create(cfg);
        if(!svr) fatal_exit("could not init server");
        log_open(cfg->logfile);
        if(!nodaemonize)
                if(daemon(1, 0) != 0)
                        fatal_exit("could not daemonize: %s", strerror(errno));
        store_pid(cfg->pidfile);
        svr_service(svr);
        unlink_pid(cfg->pidfile);
        svr_delete(svr);
        cfg_delete(cfg);
}

/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/**
 * main program. Set options given commandline arguments.
 * @param argc: number of commandline arguments.
 * @param argv: array of commandline arguments.
 * @return: exit status of the program.
 */
int main(int argc, char *argv[])
{
        int c;
        const char* cfgfile = NULL;
        int nodaemonize = 0;
        while( (c=getopt(argc, argv, "c:dhv")) != -1) {
                switch(c) {
                case 'c':
                        cfgfile = optarg;
                        break;
                case 'v':
                        verbosity++;
                        break;
                case 'd':
                        nodaemonize=1;
                        break;
                default:
                case 'h':
                        usage();
                        return 1;
                }
        }
        argc -= optind;
        argv += optind;
        if(argc != 0) {
                usage();
                return 1;
        }

        do_main_work(cfgfile, nodaemonize);

	return 0;
}
