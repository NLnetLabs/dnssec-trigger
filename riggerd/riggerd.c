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
#include "cfg.h"
#include "svr.h"
#include "netevent.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#include <signal.h>
#include <fcntl.h>
#ifdef HAVE_OPENSSL_ENGINE_H
#include <openssl/engine.h>
#endif
#ifdef HAVE_OPENSSL_CONF_H
#include <openssl/conf.h>
#endif

/** print usage text */
static void
usage(void)
{
	printf("usage:  dnssec-triggerd [options]\n");
	printf(" -h		this help\n");
	printf(" -v		increase verbosity\n");
	printf(" -d		do not fork into the background\n");
	printf(" -c file	config file, default %s\n", CONFIGFILE);
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
		if(global_svr)
			comm_base_exit(global_svr->base);
		else fatal_exit("killed by signal %d", (int)sig);
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

/** detach from command line */
static void
detach(void)
{
#if defined(HAVE_DAEMON) && !defined(DEPRECATED_DAEMON)
	/* use POSIX daemon(3) function */
	if(daemon(1, 0) != 0)
		fatal_exit("daemon failed: %s", strerror(errno));
#else /* no HAVE_DAEMON */
#ifdef HAVE_FORK
	int fd;
	/* Take off... */
	switch (fork()) {
		case 0:
			break;
		case -1:
			fatal_exit("fork failed: %s", strerror(errno));
		default:
			/* exit interactive session */
			exit(0);
	}
	/* detach */
#ifdef HAVE_SETSID
	if(setsid() == -1)
		fatal_exit("setsid() failed: %s", strerror(errno));
#endif
	if ((fd = open("/dev/null", O_RDWR, 0)) != -1) {
		(void)dup2(fd, STDIN_FILENO);
		(void)dup2(fd, STDOUT_FILENO);
		(void)dup2(fd, STDERR_FILENO);
		if (fd > 2)
			(void)close(fd);
	}
#endif /* HAVE_FORK */
#endif /* HAVE_DAEMON */
}

/** do main work of daemon */
static void
do_main_work(const char* cfgfile, int nodaemonize, int verb)
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
	verbosity += verb;
	if(!cfg) fatal_exit("could not create config");
	svr = svr_create(cfg);
	if(!svr) fatal_exit("could not init server");
	log_init(cfg->logfile, cfg->use_syslog, cfg->chroot);
	if(!nodaemonize)
		detach();
	store_pid(cfg->pidfile);
	log_info("%s start", PACKAGE_STRING);
	svr_service(svr);
	unlink_pid(cfg->pidfile);
	log_info("%s stop", PACKAGE_STRING);
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
	const char* cfgfile = CONFIGFILE;
	int nodaemonize = 0, verb = 0;
#ifdef USE_WINSOCK
	int r;
	WSADATA wsa_data;
#endif
#ifdef USE_WINSOCK
	r = WSAStartup(MAKEWORD(2,2), &wsa_data);
	if(r != 0) {
		fatal_exit("could not init winsock. WSAStartup: %s",
			wsa_strerror(r));
	}
#endif /* USE_WINSOCK */

	log_ident_set("dnssec-triggerd");
	log_init(NULL, 0, NULL);
	while( (c=getopt(argc, argv, "c:dhv")) != -1) {
		switch(c) {
		case 'c':
			cfgfile = optarg;
			break;
		case 'v':
			verbosity++;
			verb++;
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

	ERR_load_crypto_strings();
	ERR_load_SSL_strings();
	OpenSSL_add_all_algorithms();
	(void)SSL_library_init();
	do_main_work(cfgfile, nodaemonize, verb);
	EVP_cleanup();
#ifdef HAVE_OPENSSL_ENGINE_H
	ENGINE_cleanup();
#endif
#ifdef HAVE_OPENSSL_CONF_H
	CONF_modules_free();
#endif
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	RAND_cleanup();

#ifdef USE_WINSOCK
	if(WSACleanup() != 0) {
		log_err("Could not WSACleanup: %s",
			wsa_strerror(WSAGetLastError()));
	}
#endif
	return 0;
}
