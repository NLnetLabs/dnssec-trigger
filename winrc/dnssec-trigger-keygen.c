/*
 * dnssec-trigger-keygen.c - certificate keygen for dnssec-trigger.
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
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * \file
 *
 * The remote control utility contacts the dnssec-trigger server over ssl 
 * This utility creates the keys and certificates used using openssl.
 */

#include "config.h"
#ifdef HAVE_GETOPT_H
#include <getopt.h>
#endif
#ifdef HAVE_OPENSSL_SSL_H
#include <openssl/ssl.h>
#endif
#ifdef HAVE_OPENSSL_ERR_H
#include <openssl/err.h>
#endif
#ifdef HAVE_OPENSSL_RAND_H
#include <openssl/rand.h>
#endif
#include <openssl/x509v3.h>
#include <sys/stat.h>

/** max length of filename */
#define FNAMESIZE 1024

/** Give dnssec-trigger-control usage, and exit (1). */
static void
usage()
{
	printf("Usage:	dnssec-trigger-keygen [options]\n");
	printf("	create keys for dnssec-trigger server.\n");
	printf("Options:\n");
	printf("  -d dir	directory, default is %s\n", KEYDIR);
	printf("  -u		set issuer and subject for unbound use.\n");
	printf("  -h		show this usage help.\n");
	printf("Version %s\n", PACKAGE_VERSION);
	printf("BSD licensed, see LICENSE in source package for details.\n");
	printf("Report bugs to %s\n", PACKAGE_BUGREPORT);
	exit(1);
}

/** exit with error */
static void fatal(const char* s)
{
	fprintf(stderr, "error: %s\n", s);
	exit(1);
}

/** exit with ssl error */
void ssl_err(const char* s)
{
	fprintf(stderr, "error: %s\n", s);
	ERR_print_errors_fp(stderr);
	exit(1);
}

/** setup names of issuer and subject */
static void
setup_mode(int ubmode, char** servername, char** clientname, char** svr_base,
	char** ctl_base)
{
	if(ubmode) {
		*servername = "unbound";
		*clientname = "unbound-control";
		*svr_base = "unbound_server";
		*ctl_base = "unbound_control";
	} else {
		*servername = "dnssec-trigger";
		*clientname = "dnssec-trigger-control";
		*svr_base = "dnssec_trigger_server";
		*ctl_base = "dnssec_trigger_control";
	}
}

/** true if file exists */
static int file_exists(const char* filename)
{
	struct stat buf;
	if(stat(filename, &buf) < 0) {
		if(errno == ENOENT)
			return 0;
		printf("error: stat(%s): %s\n", filename, strerror(errno));
	}
	return 1;
}

/** read pkey from file */
static EVP_PKEY* read_key(char* filename)
{
	EVP_PKEY* pkey;
	BIO* bio = BIO_new(BIO_s_file());
	if(!bio) fatal("cannot BIO_new");
	if(BIO_read_filename(bio, filename) <= 0)
		ssl_err(filename);
	pkey = PEM_read_bio_PrivateKey(bio, NULL, NULL, NULL);
	if(!pkey)
		ssl_err(filename);
	BIO_free(bio);
	return pkey;
}

/** generate key */
static EVP_PKEY* gen_key(int bits)
{
	EVP_PKEY* pkey = NULL;
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
	if(!ctx) ssl_err("cannot create EVP_PKEY_CTX");
	if(EVP_PKEY_keygen_init(ctx) <= 0)
		ssl_err("cannot EVP_PKEY_keygen_init");
	if(EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, bits) <= 0)
		ssl_err("cannot EVP_PKEY_CTX_set_rsa_keygen_bits");
	if(EVP_PKEY_keygen(ctx, &pkey) <= 0)
		ssl_err("cannot EVP_PKEY_keygen");
	EVP_PKEY_CTX_free(ctx);
	return pkey;
}

/** write private key to file */
static void write_key(EVP_PKEY* pkey, char* filename)
{
	BIO* bio = BIO_new(BIO_s_file());
	if(!bio) fatal("cannot BIO_new");
	if(BIO_write_filename(bio, filename) <= 0)
		ssl_err(filename);
	if(PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, NULL, NULL) <= 0)
		ssl_err(filename);
	BIO_free(bio);
}

/** make or read RSA key */
static EVP_PKEY* make_or_read_key(int bits, const char* keydir, const char* nm)
{
	char filename[FNAMESIZE];
	EVP_PKEY* pkey = NULL;
	snprintf(filename, sizeof(filename), "%s/%s.key", keydir, nm);
	if(file_exists(filename)) {
		pkey = read_key(filename);
	} else {
		pkey = gen_key(bits);
		write_key(pkey, filename);
	}
	return pkey;
}

static char* random_64bit_hex(void)
{
	uint16_t r[4];
	static char buf[32];
	RAND_bytes((unsigned char*)r, 8);
	snprintf(buf, sizeof(buf), "0x%4.4x%4.4x%4.4x%4.4x",
		r[0], r[1], r[2], r[3]);
	return buf;
}

/** set issuer and subject to string */
static void set_issuer_and_subject(X509* x, char* str)
{
	X509_NAME* nm = X509_NAME_new();
	if(!nm) fatal("out of memory");
	if(!X509_NAME_add_entry_by_txt(nm, "CN", MBSTRING_ASC,
		(unsigned char*)str, -1, -1, 0))
		ssl_err("cannot X509_NAME_add_entry_by_txt");

	if(!X509_set_issuer_name(x, nm))
		ssl_err("cannot X509_set_issuer_name");
	if(!X509_set_subject_name(x, nm))
		ssl_err("cannot X509_set_subject_name");
	X509_NAME_free(nm);
}

/** set to random serial number */
static void set_random_serial(X509* x)
{
	ASN1_INTEGER* serial;
	serial = s2i_ASN1_INTEGER(NULL, random_64bit_hex());
	if(!serial) ssl_err("cannot s2i_ASN1_INTEGER");
	if(!X509_set_serialNumber(x, serial))
		ssl_err("cannot X509_set_serialNumber");
	ASN1_INTEGER_free(serial);
}

/** set time on cert */
static void set_dates(X509* x, int days)
{
	if(!X509_gmtime_adj(X509_get_notBefore(x), 0))
		ssl_err("cannot X509_gmtime_adj notBefore");
	if(!X509_time_adj_ex(X509_get_notAfter(x), days, 0, NULL))
		ssl_err("cannot X509_time_adj_ex notAfter");
}

/** set attributes on selfsigned x509 */
static void
set_selfsigned_attrs(X509* x, char* servername, int days, EVP_PKEY* skey)
{
	set_issuer_and_subject(x, servername);
	set_dates(x, days);
	if(!X509_set_pubkey(x, skey))
		ssl_err("cannot X509_set_pubkey");
	set_random_serial(x);
}

/** write certificate to file */
static void cert_write(X509* x, const char* keydir, char* nm)
{
	char filename[FNAMESIZE];
	BIO* bio = BIO_new(BIO_s_file());
	if(!bio) fatal("cannot BIO_new");
	snprintf(filename, sizeof(filename), "%s/%s.pem", keydir, nm);
	if(BIO_write_filename(bio, filename) <= 0)
		ssl_err(filename);
	if(PEM_write_bio_X509(bio, x) <= 0)
		ssl_err(filename);
	BIO_free(bio);
}

/** create selfsigned server certificate */
static X509* make_selfsigned(char* hash, char* servername, int days,
	const char* keydir, char* svr_base, EVP_PKEY* skey)
{
	X509* x = X509_new();
	if(!x) fatal("cannot X509_new");
	set_selfsigned_attrs(x, servername, days, skey);
	/* sign */
	if(!X509_sign(x, skey, EVP_get_digestbyname(hash)))
		ssl_err("cannot X509_sign");
	/* write */
	cert_write(x, keydir, svr_base);
	return x;
}

/** set client attributes on the certificate */
static void
set_client_attrs(X509* x, char* clientname, int days, EVP_PKEY* ckey)
{
	set_issuer_and_subject(x, clientname);
	set_dates(x, days);
	if(!X509_set_pubkey(x, ckey))
		ssl_err("cannot X509_set_pubkey");
	set_random_serial(x);
}

/** create signed client certificate */
static void make_clientsigned(char* hash, char* clientname, int days,
	const char* keydir, char* ctl_base, EVP_PKEY* skey, EVP_PKEY* ckey,
	X509* scert)
{
	X509* x = X509_new();
	if(!x) fatal("cannot X509_new");
	/* in script we made trusted_usage(scert) to please the openssl tool */
	set_client_attrs(x, clientname, days, ckey);
	/* sign with ckey */
	if(!X509_sign(x, ckey, EVP_get_digestbyname(hash)))
		ssl_err("cannot X509_sign");
	/* sign with scert */
	if(!X509_set_issuer_name(x, X509_get_subject_name(scert)))
		ssl_err("cannot X509_set_issuer_name");
	if(!X509_sign(x, skey, EVP_get_digestbyname(hash)))
		ssl_err("cannot X509_sign");
	cert_write(x, keydir, ctl_base);
	X509_free(x);
}

/** do the certificate generate */
static void
do_gen(const char* keydir, int ubmode)
{
	/* validity period for certificates */
	int days = 7200;
	/* issuer and subject name for certificates */
	char* servername;
	char* clientname;
	/* size of keys in bits */
	int bits = 3072;
	/* hash algorithm */
	char* hash = "sha256";
	/* base name for files on disk */
	char* svr_base;
	char* ctl_base;
	EVP_PKEY* skey, *ckey;
	X509* scert;

	setup_mode(ubmode, &servername, &clientname, &svr_base, &ctl_base);
	skey = make_or_read_key(bits, keydir, svr_base);
	ckey = make_or_read_key(bits, keydir, ctl_base);
	scert = make_selfsigned(hash, servername, days, keydir, svr_base, skey);
	make_clientsigned(hash, clientname, days, keydir, ctl_base, skey,
		ckey, scert);

	EVP_PKEY_free(skey);
	EVP_PKEY_free(ckey);
	X509_free(scert);
}

/** getopt global, in case header files fail to declare it. */
extern int optind;
/** getopt global, in case header files fail to declare it. */
extern char* optarg;

/** Main routine for dnssec-trigger-keygen */
int main(int argc, char* argv[])
{
	int c;
	const char* keydir = KEYDIR;
	int ubmode = 0;

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	(void)SSL_library_init();

	if(!RAND_status()) {
                /* try to seed it */
                unsigned char buf[256];
                unsigned int v, seed=(unsigned)time(NULL) ^ (unsigned)getpid();
                size_t i;
                for(i=0; i<256/sizeof(v); i++) {
                        memmove(buf+i*sizeof(v), &v, sizeof(v));
                        v = v*seed + (unsigned int)i;
                }
                RAND_seed(buf, 256);
		printf("warning: no entropy, seeding openssl PRNG with time\n");
	}

	/* parse the options */
	while( (c=getopt(argc, argv, "d:hu")) != -1) {
		switch(c) {
		case 'd':
			keydir = optarg;
			break;
		case 'u':
			ubmode = 1;
			break;
		case '?':
		case 'h':
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if(argc != 0)
		usage();
	do_gen(keydir, ubmode);

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	RAND_cleanup();
	return 0;
}
