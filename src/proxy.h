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
#ifndef _SENDOOWAY_PROXY_H__
#define _SENDOOWAY_PROXY_H__

#include "config.h"
#include <stdbool.h>
#include <stdlib.h>
#include "client.h"
#include "server.h"
#include "smtp.h"

typedef struct proxy_connection_t {
	struct client_data_t client;
	struct server_data_t server;
} proxy_connection_t;

typedef struct proxy_fromData_t {
	char address[255];
	char *domain;
	int size;
	enum {bNone, b8bit, b7bit} body;
} proxy_fromData_t;

bool proxy_doDataCmd(proxy_connection_t* pc);
smtp_reply_t proxy_doOtherCmd(proxy_connection_t* pc, char* cmdline);

typedef enum {pdfeNone, pdfeLookup, pdfeConnect, pdfeEnvironment,
  pdfeRemote} proxy_doFromError_t;
proxy_doFromError_t proxy_doFrom(proxy_connection_t* pc,
  proxy_fromData_t* from);

static inline void proxy_setEhlo(proxy_connection_t* pc,
  char* hostname) {

	util_strcpy(pc->client.ehlo, hostname,
	  sizeofMember(proxy_connection_t, client.ehlo));
}

proxy_connection_t* proxy_newConnection(bool earlySSLprepare);
void proxy_freeConnection(proxy_connection_t* pc);
void proxy_resetConnection(proxy_connection_t* pc);
void proxy_handle(proxy_connection_t* pc, bool ssl, int pin, int pout);

#endif
