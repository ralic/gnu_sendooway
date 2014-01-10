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
#ifndef _SENDOOWAY_SERVER_H__
#define _SENDOOWAY_SERVER_H__

#include "config.h"
#include "smtp.h"
#ifdef HAVE_GNUTLS
	#include <gnutls/gnutls.h>
#endif
#include <netinet/in.h>
#include <stdbool.h>

typedef struct server_data_t {
		int out;
		int in;
#ifdef HAVE_GNUTLS
		gnutls_certificate_credentials_t xcred;
		gnutls_session_t session;
#endif

		bool tlsInitDone;
		bool tlsEnabled;

		char lineBuffer[SMTP_MAXCMDLEN];
		int lineBufferPos;

		char peerIp[INET6_ADDRSTRLEN];
		enum {stateUnauthed = 0, stateAuthed,
		  stateConnected, stateZombie} state;
} server_data_t;

#include "proxy.h"

ssize_t server_read(void* p, char *buf, size_t buflen);

#define server_writes(sd, str) server_write(sd, str, strlen(str))
void server_write(struct server_data_t *sd, char* buf, size_t buflen);

bool server_sslPrepare(server_data_t *sd);
bool server_sslHandshake(server_data_t *sd);
void server_handle(server_data_t *sd, void *ptr);

#endif
