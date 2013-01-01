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
#include <string.h>
#include <arpa/inet.h>
#ifdef HAVE_GNUTLS
	#include <gnutls/gnutls.h>
#endif
#include "server.h"
#include "util.h"
#include "smtp.h"
#include "auth.h"
#include "options.h"

#ifndef HAVE_GNUTLS
ssize_t server_read(void* p, char *buf, size_t buflen) {
	server_data_t *sd = p;
	ssize_t ret = util_readTimeout(sd->in, buf, buflen);

	if (ret <= 0) {
		sd->state = stateZombie;
		return 0;
	} else return ret;
}

static void server_send(struct server_data_t *sd, char* buf,
  size_t buflen) {

	if (sd->state != stateZombie) write(sd->out, buf, buflen);
}


bool server_sslPrepare(server_data_t *sd) {return false;}
bool server_sslHandshake(server_data_t *sd) {return false;}

#else
ssize_t server_read(void* p, char *buf, size_t buflen) {
	server_data_t *sd = p;
	ssize_t ret;

	if (!sd->tlsEnabled) ret = util_readTimeout(sd->in, buf, buflen);
		else ret = gnutls_record_recv(sd->session, buf, buflen);

	if (ret <= 0) {
		/** @todo Handle GNUTLS_E_REHANDSHAKE */
		sd->state = stateZombie;
		return 0;
	} else return ret;
}

static void server_send(struct server_data_t *sd, char* buf,
  size_t buflen) {

	if (sd->state != stateZombie) {
		if (!sd->tlsEnabled) write(sd->out, buf, buflen);
		else gnutls_record_send(sd->session, buf, buflen);
	}
}

bool server_sslPrepare(server_data_t *sd) {
	if (!sd->tlsInitDone) {
		/* These settings are global */
		gnutls_certificate_allocate_credentials(&sd->xcred);
		gnutls_certificate_set_x509_trust_file(sd->xcred,
		  options.sslCa, GNUTLS_X509_FMT_PEM);
		if (gnutls_certificate_set_x509_key_file(sd->xcred, options.sslCert,
		  options.sslKey, GNUTLS_X509_FMT_PEM) < 0) goto failedTemporary;

		/** @todo Globalize */
		gnutls_dh_params_t dh_params;
		gnutls_dh_params_init (&dh_params);
		gnutls_dh_params_generate2 (dh_params, 1024);
		gnutls_certificate_set_dh_params (sd->xcred, dh_params);

		/* Session related stuff */
		gnutls_init(&sd->session, GNUTLS_SERVER);
		if (gnutls_priority_set_direct(sd->session, "NORMAL", NULL) < 0) {
			gnutls_deinit(sd->session);
			goto failedTemporary;
		}

		gnutls_credentials_set(sd->session, GNUTLS_CRD_CERTIFICATE,
		  sd->xcred);
		gnutls_certificate_server_set_request (sd->session,
		  GNUTLS_CERT_IGNORE);

		sd->tlsInitDone = true;
	}

	gnutls_transport_set_ptr2(sd->session,
	  (gnutls_transport_ptr_t) (ssize_t) sd->in,
	  (gnutls_transport_ptr_t) (ssize_t) sd->out);

	/* Since stdin/stdout are used, prefer read/write over recv/send */
	gnutls_transport_set_push_function(sd->session,
	  (gnutls_push_func) &write);
	gnutls_transport_set_pull_function(sd->session,
	  (gnutls_pull_func) &util_readTimeout);

	return true;

failedTemporary:
	gnutls_certificate_free_credentials(sd->xcred);
	util_logger(LOG_DEBUG, "TLS init failed");
	return false;
}

bool server_sslHandshake(server_data_t *sd) {
	if (!server_sslPrepare(sd)) return false;

	if (gnutls_handshake(sd->session) < 0) {
		util_logger(LOG_DEBUG, "gnutls_handshake() failed");
		sd->state = stateZombie;
		return false;
	}

	util_logger(LOG_DEBUG, "gnutls_handshake() succeeded");

	sd->tlsEnabled = true;
	return true;
}
#endif

static void server_flush(server_data_t* sd) {
	if (sd->lineBufferPos > 0) {
		server_send(sd, sd->lineBuffer, sd->lineBufferPos);
		sd->lineBufferPos = 0;
	}
}

void server_write(struct server_data_t *sd, char* buf, size_t buflen) {
	size_t size = sizeof(sd->lineBuffer) - sd->lineBufferPos;

	if (size < buflen) {
		server_flush(sd);
		size = sizeof(sd->lineBuffer);
	}

	if (size > buflen) {
		bool flush = false;
		while (buflen--) {
			sd->lineBuffer[sd->lineBufferPos] = *buf++;
			flush |= (sd->lineBuffer[sd->lineBufferPos++] == '\n');
		}
		if (flush) server_flush(sd);

	} else server_send(sd, buf, buflen);
}

static size_t server_readline(server_data_t *sd, char *buf,
  size_t buflen, bool allowBinary) {

	size_t retval = buflen;
	int status = util_readline(&server_read, sd, buf, &retval);

	if (status & URL_LINE_TOOLONG) {
		/* Line to long --> Catch all */
		do {
			retval = buflen;
			status = util_readline(&server_read, buf, buf, &retval);
		} while (status & URL_LINE_TOOLONG);
		goto fail;
	}

	/* Connection reset --> Update connection state */
	if (status & URL_ZERO_READ) {
		sd->state = stateZombie;
		goto fail;
	}

	/* Invalid input --> Assume empty line */
	if (!allowBinary && (status & URL_READ_GARBAGE)) goto fail;

	/* Well done! */
	return retval;

fail:
	buf[0] = '\0';
	return 0;
}

#define server_reply(sd, reply, ...) \
	do { \
		char *msg[] = {__VA_ARGS__}; \
		server_reply_(sd, reply, sizeof(msg) / sizeof(char*), msg); \
	} while (0)

#define server_replyC(sd, reply) \
	do { \
		char *msg[] = {" "}; \
		server_reply_(sd, reply, 1, msg); \
	} while (0)

static void server_reply_(server_data_t *sd, smtp_reply_t reply,
  int count, char** lines) {

	/** @todo Buffer all lines and send them as one packet */
	while (count--) {
		size_t len = 3 + 1 + strlen(lines[0]) + 2 + 1;
		char   buf[len];

		snprintf(buf, len, "%03u-%s\r\n", reply % 1000, lines[0]);
		if (!count) buf[3] = ' ';

		/* Send everything except of terminating zero */
		server_write(sd, buf, len - 1);

		lines++;
	}
}

static bool server_parseFrom(char *in, proxy_fromData_t *from) {
	/* Trim left (find '<') */
	while (*in == ' ') in++;
	if (*in != '<') return false;

	/* Copy address (find '>', react on '@') */
	from->domain = options.localname;
	char *target = from->address;
	in++;
	while (*in && (*in != '>')) {
		*target++ = *in;
		if (*in == '@') from->domain = target;
		in++;
	}
	*target = '\0';
	if (!*in) return false;

	/* Extensions */
	from->size = 0;
	from->body = bNone;

	in++;
	while (in && *in) {
		/* Trim */
		while (*in && ((*in <= ' ') || (*in > 126))) in++;
		if (!*in) break;

		char *ext = in;
		/* Find end */
		while ((*in > ' ') && (*in <= 126)) in++;
		if (!*in) in = NULL; else *in++ = '\0';

		/* Analyze */
		if (util_strstart(ext, "BODY=")) {
			if (util_strstart(&ext[5], "8BITMIME")) from->body = b8bit;
			else if (util_strstart(&ext[5], "7BIT")) from->body = b7bit;
			else return false;
		} else if (util_strstart(ext, "SIZE=")) {
			from->size = atoi(&ext[5]);
		} else return false;
	}

	return true;
}

static smtp_reply_t server_doAuthPlain(server_data_t* sd,
  char* response, char **username, char **password) {

	int respLen;
	char respBuf[SMTP_MAXLINE + 1];

	if (*response) {
		while (*response && (*response == ' '))
		  response++; /* Remove leading spaces */

		if (!*response) return replyAuthFailed;
		respLen = strlen(response);
	} else {
		server_replyC(sd, replyAuth);
		respLen = server_readline(sd, respBuf, sizeof(respBuf), false);
		if (sd->state != stateZombie) {
			/* Rejects '*' and errors -> base64 has at least 3 characters */
			if (respLen < 3) return replySyntaxArg;
		} else return replyError;

		response = respBuf;
	}

	respLen = util_base64decode(response, respLen, NULL);
	if (!respLen) return replySyntaxArg;

	do {
		if (!--respLen) return replySyntaxArg;
	} while (*response++) ;

	util_strfree(username, false);
	*username = strdup(response);
	if (!*username) {
		util_logger(LOG_CRIT, "Unable to allocate memory for username");
		return replySyntaxArg;
	}

	do {
		if (!--respLen) return replySyntaxArg;
	} while (*response++) ;

	util_strfree(password, true);
	*password = strdup(response);
	if (!*password) {
		util_logger(LOG_CRIT, "Unable to allocate memory for user's"
		  " password");

		util_strfree(username, false);
		return replySyntaxArg;
	}

	return replyAuthOk;
}

static smtp_reply_t server_doAuthLogin(server_data_t* sd,
  char **username, char **password) {

	smtp_reply_t reply = replySyntaxArg;
	int  respLen;
	char respBuf[SMTP_MAXLINE + 1];

	/* Get username */
	server_reply(sd, replyAuth, "VXNlcm5hbWU6");
	respLen = server_readline(sd, respBuf, sizeof(respBuf), false);
	if (sd->state != stateZombie) {
		/* Rejects '*' and errors -> base64 has at least 3 characters */
		if ( respLen >= 3) {
			util_strfree(username, false);
			*username = malloc(UTIL_BASE64SIZE(respLen));
			if (*username) {

				if (!util_base64decode(respBuf, respLen, *username))
				  util_strfree(username, false);

			} else util_logger(LOG_CRIT, "Unable to allocate memory for"
			  " username");
		}

		if (!*username) return reply;
	} else return replyError;

	/* Get password */
	server_reply(sd, replyAuth, "UGFzc3dvcmQ6");
	respLen = server_readline(sd, respBuf, sizeof(respBuf), false);
	if (sd->state != stateZombie) {
		/* Rejects '*' and errors -> base64 has at least 3 characters */
		if (respLen >= 3) {
			util_strfree(password, true);
			*password = malloc(UTIL_BASE64SIZE(respLen));
			if (*password) {

				if (!util_base64decode(respBuf, respLen, *password))
				  util_strfree(password, true);

			} else util_logger(LOG_CRIT, "Unable to allocate memory for "
			  " user's password");
		}
	} else reply = replyError;

	memset(respBuf, sizeof(respBuf), 0);
	return (password) ? replyAuthOk : reply;
}

static void server_doAuth(server_data_t* sd, char *cmdline) {
	smtp_reply_t reply;
	char *username = NULL;
	char *password = NULL;

	/* Get Username/Password */
	if (util_strstart(cmdline, "AUTH PLAIN")) {
		reply = server_doAuthPlain(sd, &cmdline[10], &username, &password);
	} else if (strcasecmp(cmdline, "AUTH LOGIN") == 0) {
		reply = server_doAuthLogin(sd, &username, &password);
	} else reply = replyAuthUnsupported;

	if ((reply == replyAuthOk) && username && password) {
		reply = replyAuthFailed;

		/* Check via PAM */
		if (auth_validate("sendooway", username, password)) {

			/* Drop privileges */
			if (auth_runas(username)) {
				reply = replyAuthOk;
				sd->state = stateAuthed;

				/* Reread configuration */
				options_parseUserInclude();
			}
		}
	}

	/* Free strings */
	util_strfree(&username, false);
	util_strfree(&password, true);

	server_replyC(sd, reply);
}

static bool server_doStarttls(server_data_t *sd) {
	if (sd->tlsEnabled) {
		server_replyC(sd, replyDoubleTLS);
		return false;
	}

	if (!server_sslPrepare(sd)) {
		server_replyC(sd, replyTLSFailed);
		return false;
	}

	server_replyC(sd, replyWelcome);
	return server_sslHandshake(sd);
}

static void server_sendEhlo(server_data_t *sd) {
	char size[4 + 1 + 20 + 1];
	if (options.extMsgSize < 0) *size = '\0';
	else if (options.extMsgSize == 0) strcpy(size, "SIZE");
	else snprintf(size, sizeof(size), "SIZE %i", options.extMsgSize);

	char *lines[8];
	int i = 0;

	lines[i++] = options.localname;
	lines[i++] = "AUTH PLAIN LOGIN";
	lines[i++] = "AUTH=PLAIN LOGIN";
	lines[i++] = "PIPELINING";
	if (options.mailerEncryption != meForbidden) lines[i++] = "STARTTLS";
	if (options.ext8bitmime != e8bDisable) lines[i++] = "8BITMIME";
	if (*size) lines[i++] = size;

	server_reply_(sd, replyOk, i, lines);
}

static bool server_getPeerIp(server_data_t *sd) {
	struct sockaddr addr;
	socklen_t len = sizeof(addr);
	if (getpeername(sd->in, &addr, &len) == 0) {
		if (addr.sa_family == AF_INET) {
			inet_ntop(AF_INET, &((struct sockaddr_in*) &addr)->sin_addr,
			  sd->peerIp, sizeofMember(server_data_t, peerIp));

			return true;
		}

		if (addr.sa_family == AF_INET6) {
			inet_ntop(AF_INET6, &((struct sockaddr_in6*) &addr)->sin6_addr,
			  sd->peerIp, sizeofMember(server_data_t, peerIp));

			return true;
		}
	}

	return false;
}

void server_handle(server_data_t *sd, void *ptr) {
	/* Connection setup */
	if (!server_getPeerIp(sd)) sd->peerIp[0] = '\0';
	server_reply(sd, replyWelcome, options.localname);

	do {
		char cmdline[SMTP_MAXCMDLEN + 1];

		do {
			size_t cmdlineLen = sizeof(cmdline);
			int url = util_readline(&server_read, sd, cmdline, &cmdlineLen);
			if (url & URL_ZERO_READ) {
				/* Connection reset */
				sd->state = stateZombie;
			} else if (url & URL_LINE_TOOLONG) {
				/* Read till end of line */
				do {
					cmdlineLen = sizeof(cmdline);
				} while (util_readline(&server_read, sd, cmdline,
					&cmdlineLen) & URL_LINE_TOOLONG);

				server_reply(sd, replySyntaxCmd, "Line too long");
			} else if (url & URL_READ_GARBAGE) {
				server_reply(sd, replySyntaxCmd, "Invalid input data");
			}

			if (!url) break;
		} while (sd->state != stateZombie);

		smtp_cmd_t cmd = smtp_decodeCmd(cmdline);

		if (sd->state == stateConnected) {
			switch (cmd) {
				case cmdStarttls:
					server_reply(sd, replySyntaxCmd,
					  "STARTTLS must be sent before MAIL command");
					break;

				case cmdAuth:
					server_reply(sd, replyBadSequence,
					  "AUTH must be sent before MAIL command");
					break;

				case cmdFrom:
				case cmdEhlo:
				case cmdHelo:
				case cmdRset:
					proxy_resetConnection(ptr);
					sd->state = stateAuthed; /* Handle below */
					break;

				case cmdData:
					if (!proxy_doDataCmd(ptr)) sd->state = stateZombie;
					break;

				case cmdQuit:
					proxy_doOtherCmd(ptr, cmdline);
					sd->state = stateZombie;
					break;

				default:
					if (!proxy_doOtherCmd(ptr, cmdline)) sd->state = stateZombie;
					break;
			}
		} /* no "else" here */

		if (sd->state == stateZombie) continue;

		if (sd->state != stateConnected) {
			switch (cmd) {
				case cmdHelp:
					server_reply(sd, replyHelp,
					  "See http://tools.ietf.org/rfc/rfc5321.txt");
					break;

				case cmdAuth:
					if (sd->state != stateAuthed) {
						server_doAuth(sd, cmdline);
					} else {
						server_reply(sd, replyBadSequence, "Already authenticated");
					}
					break;

				case cmdFrom:
					if (sd->state != stateAuthed) {
						server_reply(sd, replyAuthNeeded, "AUTH needed");
						break;
					}

					proxy_fromData_t from;
					if (!server_parseFrom(&cmdline[10], &from)) {
						server_reply(sd, replySyntaxArg, "Malformed sender");
						break;
					}

					switch (proxy_doFrom(ptr, &from)) {
						case pdfeNone:
							sd->state = stateConnected;
							break;

						case pdfeLookup:
							server_reply(sd, replyNotTaken,
								"Address lookup failed. Please review your smarthost",
								"definition files and check if those files are linked",
								"within your sendooway configuration.",
								"",
								"Read the manual or see sendooway's homepage for more",
								"information on how to solve this problem"
							);
							break;

						default:
							server_reply(sd, replyNotTaken,
							  "Remote server failed (see log)");
							break;
					}
					break;

				case cmdStarttls:
					server_doStarttls(sd);
					break;

				case cmdRecv:
				case cmdVrfy:
				case cmdData:
					server_reply(sd, replyBadSequence, "Sender address needed");
					break;

				case cmdNoop:
				case cmdRset:
					server_replyC(sd, replyOk);
					break;

				case cmdEhlo:
				case cmdHelo:
					if (cmdline[4] == ' ')
					{
						proxy_setEhlo(ptr, &cmdline[5]);
						if (cmd == cmdEhlo) server_sendEhlo(sd);
						  else server_reply(sd, replyOk, options.localname);
					} else server_reply(sd, replySyntaxArg, "Name required");
					break;

				case cmdQuit:
					server_reply(sd, replyQuit, "Good bye");
					sd->state = stateZombie;
					break;

				default:
					server_reply(sd, replyUnknownCmd, "Unknown SMTP verb");
					break;
			}
		}
	} while (sd->state != stateZombie); /* Connection loop */

#ifdef HAVE_GNUTLS
	if (sd->tlsEnabled) {
		gnutls_bye(sd->session, GNUTLS_SHUT_RDWR);
		sd->tlsEnabled = false;
	}

	if (sd->tlsInitDone) {
		gnutls_deinit(sd->session);
		gnutls_certificate_free_credentials(sd->xcred);
		sd->tlsInitDone = false;
	}
#endif
}
