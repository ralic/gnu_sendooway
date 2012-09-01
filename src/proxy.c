/**
 * This file is part of
 *   Sendooway - a multi-user and multi-target SMTP proxy
 *   Copyright (C) 2012 Michael Kammer
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
#include <stdlib.h>
#include <time.h>
#include "proxy.h"
#include "client.h"
#include "server.h"
#include "smtp.h"
#include "glue.h"
#include "options.h"

smtp_reply_t proxy_doOtherCmd(proxy_connection_t* pc, char* cmdline) {
	server_data_t* sd = &pc->server;
	client_data_t* cd = &pc->client;

	/* Send command to remote server */
	if (cmdline) client_writes(cd, cmdline);
	client_writes(cd, "\r\n");

	/* Get reply */
	char line[SMTP_MAXLINE + 1];
	do {
		int len = client_readline(cd, line, sizeof(line));
		if (len > 3) {
			server_write(sd, line, len);
			server_writes(sd, "\r\n");
		} else return replyError; /* Protocol error or connection reset */
	} while (line[4] == '-');

	line[4] = '\0';
	return atoi(line);
}

bool proxy_doDataCmd(proxy_connection_t* pc) {
	server_data_t* sd = &pc->server;
	client_data_t* cd = &pc->client;

	/* DATA command */
	switch (proxy_doOtherCmd(pc, "DATA")) {
		case replyError:    return false; /* Protocol error */
		case replySendData: break;        /* Connection ready (go ahed) */
		default:            return true;  /* Failure, but not critical */
	}

	/* Received header */
	if (options.addReceivedField) {
		time_t t = time(NULL);
		struct tm *tmp = localtime(&t);
		char timestamp[40];

		if (strftime(timestamp, sizeof(timestamp), "%a, %d %b %Y "
		  "%H:%M:%S %z (%Z)", tmp)) {

			char *header = NULL;
			int ret = asprintf(&header, "Received: from %s ([%s]) by %s with"
			  " ESMTP ("PACKAGE_NAME" "PACKAGE_VERSION"); %s\r\n",

				cd->ehlo,
				sd->peerIp,
				options.localname,
				timestamp
			);
			if (ret != -1 && header) {
				client_writes(cd, header);
				free(header);
			} else util_logger(LOG_CRIT, "Out of memory while"
			  " adding received header");
		} else util_logger(LOG_CRIT, "strftime() failed while adding"
		  " received header");
	}

	/* Stream */
	for (;;) {
		char line[SMTP_MAXLINE + 1];
		size_t len = sizeof(line);
		int ret = util_readline(&server_read, sd, line, &len);

		if (ret & URL_LINE_TOOLONG) {
			util_logger(LOG_WARNING, "Relaying line that is longer than "
			  "allowed for [%s]", sd->peerIp);

			/* Relay entire line */
			do {
				client_write(cd, line, len);
				len = sizeof(line);
				ret = util_readline(&server_read, sd, line, &len);
			} while (ret & URL_LINE_TOOLONG);

			/* ret, line and len belong to a NEW line now */
		}

		if (ret & URL_ZERO_READ) {
			sd->state = stateZombie;
			return false;
		}

		if ( (len != 1) || (*line != '.') ) {
			client_write(cd, line, len);
			client_writes(cd, "\r\n");
		} else break;
	}

	/* End of data */
	return (proxy_doOtherCmd(pc, ".") != replyError);
}

proxy_doFromError_t proxy_doFrom(proxy_connection_t* pc,
  proxy_fromData_t* from) {

	if ((options.extMsgSize > 0) && (from->size > options.extMsgSize))
	  return pdfeEnvironment;

	if (!glue_lookup(from->address, from->domain, &pc->client))
	  return pdfeLookup;
	if (!client_connect(&pc->client)) return pdfeConnect;

	/* Build command */
	client_writes(&pc->client, "MAIL FROM: <");
	client_writes(&pc->client, from->address);
	client_writes(&pc->client, ">");

	if (pc->client.ext8bit) switch (from->body) {
		case bNone: break;
		case b7bit: client_writes(&pc->client, " BODY=7BIT"); break;
		case b8bit: client_writes(&pc->client, " BODY=8BITMIME"); break;
	}

	if (pc->client.extSize && from->size) {
		char buf[6 + 20 + 1];
		int len = snprintf(buf, sizeof(buf), " SIZE=%u", from->size);
		if (len < sizeof(buf)) {
			client_write(&pc->client, buf, len);
		} else /* FAIL */;
	}

	/* Issue command */
	if (!proxy_doOtherCmd(pc, NULL)) return pdfeRemote;

	/* Success */
	return pdfeNone;
}

void proxy_resetConnection(proxy_connection_t* pc) {
	client_disconnect(&pc->client);
	memset(&pc->client, sizeofMember(proxy_connection_t, client), 0);
}

static void proxy_freeConnection(proxy_connection_t* pc) {
	if (!pc) return;
	client_disconnect(&pc->client);
	free(pc);
}

void proxy_handle(bool ssl, int pin, int pout) {
	proxy_connection_t *pc = proxy_newConnection();
	pc->server.in  = pin;
	pc->server.out = pout;

	/* SSL-Handshake on SMTPS connections */
	if (ssl && server_sslHandshake(&pc->server)) ssl = false;

	if (!ssl) server_handle(&pc->server, pc);

	proxy_freeConnection(pc);
}
