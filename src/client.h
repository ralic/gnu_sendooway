/**
 * This file is part of
 *   Sendooway - a multi-user and multi-target SMTP proxy
 *   Copyright (C) 2012-2014 Michael Kammer
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
#ifndef _SENDOOWAY_CLIENT_H__
#define _SENDOOWAY_CLIENT_H__

#include "config.h"
#include "smtp.h"
#ifdef HAVE_GNUTLS
	#include <gnutls/gnutls.h>
#endif
#include <stdbool.h>

typedef struct client_data_t {
	int sd;
#ifdef HAVE_GNUTLS
	gnutls_certificate_credentials_t xcred;
	gnutls_session_t session;
#endif

	enum {secNone = 0, secSSL, secTLS} secType;
	bool tlsInitDone;
	bool tlsEnabled;
	bool noCertificateCheck;
	bool authPlain;
	bool authLogin;
	bool authCramMD5;
	bool extSize;
	bool ext8bit;

	char lineBuffer[SMTP_MAXLINE];
	int  lineBufferPos;

	char ehlo[255];
	char *host;
	char *port;
	char *username;
	char *password;
} client_data_t;

#include "util.h"
#include "proxy.h"

void client_write(client_data_t* cd, char* buf, size_t buflen);
ssize_t client_read(void* p, char *buf, size_t buflen);
bool client_connect(client_data_t* cd);
void client_disconnect(client_data_t* cd);

#define client_writes(cd, str) \
	client_write(cd, str, strlen(str))

#define client_readline(cd, buf, buflen) \
	util_readline_DEPR(&client_read, cd, buf, buflen)

#endif
