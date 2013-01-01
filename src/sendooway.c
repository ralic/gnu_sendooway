/**
 * This file is part of
 *   Sendooway - a multi-user and multi-target SMTP proxy
 *   Copyright (C) 2012, 2013 Michael Kammer
 *
 * Sendooway is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.

 * Sendooway is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with Sendooway.  If not, see <http://www.gnu.org/licenses/>.
*/
#include "config.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <getopt.h>
#include "sendooway.h"
#include "proxy.h"
#include "options.h"

static int printHelp() {
	puts(
		"Syntax: sendooway [-h]\n"
		"        sendooway [-V]\n"
		"        sendooway [-s|-S] [-c CONFIG] [-b PORT] [-l LOGFILE]\n"
		"\n"
		"  -h    just display a short help text\n"
#ifdef HAVE_GNUTLS
		"  -s    immediately start the SSL handshake (use for SMTPS)\n"
		"  -S    consider connection safe (disable STARTTLS command)\n"
#endif
		"  -c    load configuration from CONFIG\n"
		"        (default: "SYSCONFDIR"/sendooway.conf)\n"
		"  -b    bind and listen on tcp port PORT\n"
		"  -l    do not use syslog but append log data to LOGFILE\n"
		"  -V    print program version and exit\n"
		"\n"
		"Per default sendooway should be started as root by xinetd or any\n"
		"other super-server daemon.\n"
	);
	return EXIT_SUCCESS;
}

static int printVer() {
	puts(
		PACKAGE_NAME" version "PACKAGE_VERSION"\n"
		"Copyright (C) 2012, 2013 Michael Kammer\n"
		"\n"
		"Licensed under the GPL version 3 or later\n"
		"This is free software: you are free to change and redistribute "
		  "it.\n"
		"It comes with ABSOLUTELY NO WARRANTY!\n"
	);
	return EXIT_SUCCESS;
}

static const struct option longopts[] = {
	{"log", required_argument, NULL, 'l'},
#ifdef HAVE_GNUTLS
	{"ssl", no_argument, NULL, 's'},
#endif
	/* --nossl is silently accepted, because it does not need GnuTLS */
	{"nossl", no_argument, NULL, 'S'},
	{"help", no_argument, NULL, 'h'},
	{"version", no_argument, NULL, 'V'},
	{"bind", required_argument, NULL, 'b'},
	{"config", required_argument, NULL, 'c'},
	{NULL, 0, NULL, 0}
};

#ifdef HAVE_GNUTLS
static const char* shortopts = "+hVb:c:sSl:";
#else
/* -S is silently accepted, because it does not need GnuTLS */
static const char* shortopts = "+hVb:c:Sl:";
#endif

int main(int argc, char** argv) {
	char *configfile = SYSCONFDIR"/sendooway.conf";
	enum {sslOff, sslSession, sslDisable} ssl = sslOff;
	char *bindPort = NULL;

	/* Command line options */
	do {
		int indexptr;
		int c = getopt_long(argc, argv, shortopts, longopts, &indexptr);

		if (c < 0) break;
		if (!c) c = longopts[indexptr].val;

		switch (c) {
			case 's': ssl = sslSession; break;
			case 'S': ssl = sslDisable; break;
			case 'l': util_setLogger(optarg); break;
			case 'h': return printHelp();
			case 'V': return printVer();
			case 'b': bindPort = optarg; break;
			case 'c': configfile = optarg; break;
			default:  return EXIT_FAILURE;
		}
	} while (1);

	/* Parse config file */
	if (!options_parse(configfile, true)) return EXIT_FAILURE;

	/* Update SSL configuration */
#ifndef HAVE_GNUTLS
	ssl = sslDisable;
#endif

	switch (ssl) {
		case sslSession:
		case sslDisable: options.mailerEncryption = meForbidden; break;
		default:         break;
	}

#ifdef HAVE_GNUTLS
	gnutls_global_init();
#endif

	proxy_connection_t *pc = proxy_newConnection(bindPort != NULL);

	/* Prepare to daemonize? */
	if (bindPort) {
		if (!daemon_bind(bindPort)) return EXIT_FAILURE;
		/* Forked, client connected to stdin/stdout! */
	}

	/* Start the proxy */
#ifdef HAVE_GNUTLS
	proxy_handle(pc, ssl == sslSession, STDIN_FILENO, STDOUT_FILENO);
	gnutls_global_deinit();
#else
	proxy_handle(pc, false, STDIN_FILENO, STDOUT_FILENO);
#endif

	proxy_freeConnection(pc);

	return EXIT_SUCCESS;
}
