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
#include <netdb.h>
#include <strings.h>
#ifdef HAVE_GNUTLS
	#include <gnutls/x509.h>
#endif
#include "client.h"
#include "util.h"
#include "smtp.h"
#include "options.h"

#ifndef HAVE_GNUTLS
static void client_send(client_data_t* cd, char* buf, size_t buflen) {
	write(cd->sd, buf, buflen);
}

ssize_t client_read(void* p, char *buf, size_t buflen) {
	client_data_t* cd = p;
	return util_readTimeout(cd->sd, buf, buflen);
}

#define client_sslVerifyCertificate(...) (false)
#define client_sslHandshake(...)         (false)

#else
static void client_send(client_data_t* cd, char* buf, size_t buflen) {
	if (!cd->tlsEnabled) write(cd->sd, buf, buflen);
	else gnutls_record_send(cd->session, buf, buflen);
}

ssize_t client_read(void* p, char *buf, size_t buflen) {
	client_data_t* cd = p;
	if (!cd->tlsEnabled) return util_readTimeout(cd->sd, buf, buflen);
	return gnutls_record_recv(cd->session, buf, buflen);
}

static bool client_sslVerifyCertificate(client_data_t *cd) {
	int err;
	gnutls_x509_crt_t cert = NULL;
	unsigned int status;

	err = gnutls_certificate_verify_peers2(cd->session, &status);
	if (status || err < 0) goto fail;

	const gnutls_datum_t *data;
	unsigned int id = 0;
	data = gnutls_certificate_get_peers(cd->session, &id);
	if (!data) goto fail;

	if (gnutls_x509_crt_init(&cert) != GNUTLS_E_SUCCESS) goto fail;
	if (gnutls_x509_crt_import(cert, data, GNUTLS_X509_FMT_DER)
	  != GNUTLS_E_SUCCESS) goto fail;

	if (gnutls_x509_crt_get_expiration_time(cert) < time(NULL)) goto fail;
	if (gnutls_x509_crt_get_activation_time(cert) > time(NULL)) goto fail;
	if (!cd->host) {
		/* Should never happen */
		util_logger(LOG_CRIT, "BUG: hostname lost during session");
		goto fail;
	}
	if (!gnutls_x509_crt_check_hostname (cert, cd->host)) goto fail;

	/* Verified */
	gnutls_x509_crt_deinit(cert);
	util_logger(LOG_DEBUG,
	  "Verified identity of %s:%s", cd->host, cd->port);
	return true;

fail:
	util_logger(LOG_WARNING,
		"Certificate verification failed for %s:%s", cd->host, cd->port);
	if (cert) gnutls_x509_crt_deinit(cert);

	/* Some people want to live risky... */
	return cd->noCertificateCheck;
}

static bool client_sslHandshake(client_data_t* cd) {
	int ret;

	/* Prepare */
	if (!cd->tlsInitDone) {
		gnutls_init(&cd->session, GNUTLS_CLIENT);

		gnutls_certificate_allocate_credentials(&cd->xcred);
		gnutls_certificate_set_x509_trust_file(cd->xcred, options.sslCa,
		  GNUTLS_X509_FMT_PEM);

		ret = gnutls_priority_set_direct(cd->session, "PERFORMANCE", NULL);
		if (ret < 0) {
			gnutls_certificate_free_credentials(cd->xcred);
			gnutls_deinit(cd->session);
			return false;
		}
		gnutls_credentials_set(cd->session, GNUTLS_CRD_CERTIFICATE,
		  cd->xcred);

		cd->tlsInitDone = true;
	}

	/* readTimeout */
	gnutls_transport_set_pull_function(cd->session,
	  (gnutls_pull_func) &util_readTimeout);

	/* Socket descriptor */
	gnutls_transport_set_ptr(cd->session,
	  (gnutls_transport_ptr_t) (ssize_t) cd->sd);

	/* Init */
	do {
		ret = gnutls_handshake(cd->session);
	} while (ret < 0 && !gnutls_error_is_fatal(ret));
	if (ret < 0) return false;

	cd->tlsEnabled = true;
	return true;
}
#endif

static void client_flush(client_data_t* cd) {
	if (cd->lineBufferPos > 0) {
		client_send(cd, cd->lineBuffer, cd->lineBufferPos);
		cd->lineBufferPos = 0;
	}
}

void client_write(client_data_t* cd, char* buf, size_t buflen) {
	size_t size = sizeof(cd->lineBuffer) - cd->lineBufferPos;

	if (size < buflen) {
		client_flush(cd);
		size = sizeof(cd->lineBuffer);
	}

	if (size > buflen) {
		bool flush = false;
		while (buflen--) {
			cd->lineBuffer[cd->lineBufferPos] = *buf++;
			flush |= (cd->lineBuffer[cd->lineBufferPos++] == '\n');
		}
		if (flush) client_flush(cd);

	} else client_send(cd, buf, buflen);
}

static bool client_getSingleReply(client_data_t* cd,
  smtp_reply_t *reply, char *buffer, size_t maxlen) {

	if (client_readline(cd, buffer, maxlen) >= 4) {
		if ((buffer[3] == ' ') ||
				(buffer[3] == '-')) {

			*reply = atoi(buffer);
			return (buffer[3] == '-');
		}
	}

	*reply = replyError;
	buffer[4] = '\0';
	return false;
}

#define client_await(cd, reply) (client_getReply(cd) == reply)
static smtp_reply_t client_getReply(client_data_t* cd) {
	char line[SMTP_MAXLINE + 1];
	smtp_reply_t retval;

	while (client_getSingleReply(cd, &retval, line, sizeof(line))) ;
	return retval;
}

static bool client_authCramMD5(client_data_t* cd) {
	/* Has server advertised selected AUTH mechanism? */
	if (!cd->authCramMD5) return false;

	char buf[SMTP_MAXLINE + 1];
	smtp_reply_t reply;
	client_writes(cd, "AUTH CRAM-MD5\r\n");
	while (client_getSingleReply(cd, &reply, buf, sizeof(buf))) ;
	if (reply != replyAuth) return false;

	char *challenge = &buf[4];
	util_base64decode(challenge, strlen(challenge), NULL);

	char inner[64];
	char outer[64];
	const int lenP = strlen(cd->password);
	const int lenU = strlen(cd->username);

	/* Key */
	if (lenP > 64) {
		util_md5str(cd->password, lenP, inner);
		memset(&inner[16], 0, 64 - 16);
	} else {
		memcpy(inner, cd->password, lenP);
		memset(&inner[lenP], 0, 64 - lenP);
	}

	/* Padding */
	int i;
	for (i=0;i<64;i++) {
		outer[i] = inner[i] ^ 0x5c;
		inner[i] = inner[i] ^ 0x36;
	}

	/* Hash */
	util_md5state state;
	util_md5init(&state);
	util_md5append(&state, inner, 64);
	util_md5append(&state, challenge, strlen(challenge));
	util_md5finish(&state, inner);

	util_md5init(&state);
	util_md5append(&state, outer, 64);
	util_md5append(&state, inner, 16);
	util_md5finish(&state, outer);

	/* Response */
	char final[lenU + 1 + 32];
	memcpy(final, cd->username, lenU);
	final[lenU] = ' ';

	for (i=0;i<16;i++) {
		const char *hexDigits = "0123456789abcdef";

		final[lenU + 1 + 2*i] = hexDigits[ (outer[i] & 0xF0) >> 4 ];
		final[lenU + 1 + 2*i + 1] = hexDigits[  outer[i] & 0x0F ];
	}

	/* Base64Encode */
	char final64[UTIL_BASE64SIZE( sizeof(final) )];
	util_base64encode(final, sizeof(final), final64);

	/* Authenticate */
	client_write(cd, final64, UTIL_BASE64LEN( sizeof(final) ));
	client_writes(cd, "\r\n");
	return client_await(cd, replyAuthOk);
}

static bool client_authPlain(client_data_t* cd) {
	/* Has server advertised selected AUTH mechanism? */
	if (!cd->authPlain) return false;

	const int lenU = strlen(cd->username);
	const int lenP = strlen(cd->password);

	/* message := "\0" ++ user ++ "\0" ++ pass */
	char message[1 + lenU + 1 + lenP];
	message[0] = '\0';
	memcpy(&message[1], cd->username, lenU);
	message[lenU + 1 ] = '\0';
	memcpy(&message[lenU + 2], cd->password, lenP);

	/* BASE64 encode */
	char response[UTIL_BASE64SIZE(sizeof(message))];
	util_base64encode(&message, sizeof(message), response);

	/* Authenticate */
	client_writes(cd, "AUTH PLAIN ");
	client_write(cd, response, UTIL_BASE64LEN(sizeof(message)));
	client_writes(cd, "\r\n");
	return client_await(cd, replyAuthOk);
}

static bool client_authLogin(client_data_t* cd) {
	/* Has server advertised selected AUTH mechanism? */
	if (!cd->authLogin) return false;

	const int lenU = strlen(cd->username);
	const int lenP = strlen(cd->password);
	char response[UTIL_BASE64SIZE(util_max(lenU, lenP, const int))];

	client_writes(cd, "AUTH LOGIN\r\n");
	if (!client_await(cd, replyAuth)) return false;

	/* Username */
	util_base64encode(cd->username, lenU, response);
	client_write(cd, response, UTIL_BASE64LEN(lenU));
	client_writes(cd, "\r\n");
	if (!client_await(cd, replyAuth)) return false;

	/* Password */
	util_base64encode(cd->password, lenP, response);
	client_write(cd, response, UTIL_BASE64LEN(lenP));
	client_writes(cd, "\r\n");
	return client_await(cd, replyAuthOk);
}

static bool client_sendEhlo(client_data_t* cd) {
	smtp_reply_t reply;
	bool hasNext;

	/* Reset extensions */
	cd->ext8bit      = false;
	cd->extSize      = false;
	cd->authPlain    = (options.smarthostPlain   == spAlwaysTry);
	cd->authLogin    = (options.smarthostLogin   == slAlwaysTry);
	cd->authCramMD5  = (options.smarthostCramMD5 == scAlwaysTry);

	/* Request extensions */
	client_writes(cd, "EHLO ");
	if (options.cloneEhlo && strlen(cd->ehlo)) {
		client_writes(cd, cd->ehlo);
	} else client_writes(cd, options.localname);
	client_writes(cd, "\r\n");

	/* Process answer */
	do {
		char line[SMTP_MAXLINE + 1];

		hasNext = client_getSingleReply(cd, &reply, line, sizeof(line));
		if (reply == replyError) break;

		/* client_getSingleReply() guarantees nulltermination of (line+4) */
		if (strcasecmp(&line[4], "8BITMIME") == 0) cd->ext8bit = true;
		else if (util_strstart(&line[4], "SIZE"))  cd->extSize = true;
		else if (util_strstart(&line[4], "AUTH ")) {
			char *ls = &line[4 + 5];
			char *auth;
			while (*(auth = ls)) {
				util_strparse(&ls, " ");

				if (strcasecmp(auth, "CRAM-MD5") == 0)   cd->authCramMD5 = true;
				else if (strcasecmp(auth, "LOGIN") == 0) cd->authLogin   = true;
				else if (strcasecmp(auth, "PLAIN") == 0) cd->authPlain   = true;
			}
		}
	} while (hasNext);

	/* Override */
	cd->authPlain    &= (options.smarthostPlain   != spNever);
	cd->authLogin    &= (options.smarthostLogin   != slNever);
	cd->authCramMD5  &= (options.smarthostCramMD5 != scNever);

	return (reply == replyOk);
}

static bool client_connectSocket(client_data_t* cd) {
	struct addrinfo hints, *res;
	memset(&hints, 0, sizeof(hints));
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_family = AF_INET;
	if (!cd->host || !cd->port) return false;
	if (getaddrinfo(cd->host, cd->port, &hints, &res) != 0) return false;

	cd->sd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (cd->sd >= 0) {
		if (connect(cd->sd, res->ai_addr, res->ai_addrlen) == 0) {
			freeaddrinfo(res);
			return true;
		}
		close(cd->sd);
	}
	cd->sd = 0;
	freeaddrinfo(res);
	return false;
}

bool client_connect(client_data_t* cd) {
	if (!client_connectSocket(cd)) return false;
	util_logger(LOG_DEBUG, "Connected to %s:%s", cd->host, cd->port);

	switch (cd->secType) {
		case secSSL:
			if (!client_sslHandshake(cd)) goto fail;
			if (!client_sslVerifyCertificate(cd)) goto fail;
			/* Fall through */
		case secNone:
		case secTLS:
			if (!client_await(cd, replyWelcome)) goto fail;
			if (cd->secType != secTLS) break;

			if (!client_sendEhlo(cd)) goto fail;

			/* Don't care if server advertised the STARTTLS-extension. With
			 * secTLS we insist on encryption and would fail otherwise. So
			 * give it a try... */
			client_writes(cd, "STARTTLS\r\n");
			if (!client_await(cd, replyWelcome)) goto fail;
			if (!client_sslHandshake(cd)) goto fail;
			if (!client_sslVerifyCertificate(cd)) goto fail;
			break;

		default:
			return false;
	}

	if (!client_sendEhlo(cd)) goto fail;

	/* Force 8BITMIME? */
	if (!cd->ext8bit) switch (options.ext8bitmime) {
		case e8bDisable:
			break;

		case e8bIgnore:
			util_logger(LOG_WARNING, "Ignoring the fact that server %s does"
			  " not advertise 8BITMIME extension.", cd->host);
			break;

		case e8bForce:
			util_logger(LOG_WARNING, "Unable to guarantee 8BITMIME support"
			  " because server %s has not advertised it.", cd->host);
			goto fail;
	}

	if (cd->username && cd->password) {
		if (client_authCramMD5(cd)) return true;
		if (client_authPlain(cd)) return true;
		if (client_authLogin(cd)) return true;
	} else return true;

fail:
	client_disconnect(cd);
	return false;
}

void client_disconnect(client_data_t* cd) {
#ifdef HAVE_GNUTLS
	if (cd->tlsEnabled) {
		gnutls_bye(cd->session, GNUTLS_SHUT_WR);
//		gnutls_bye(cd->session, GNUTLS_SHUT_RDWR);
		cd->tlsEnabled = false;
	}
#endif

	close(cd->sd);
	cd->sd = 0;

#ifdef HAVE_GNUTLS
	if (cd->tlsInitDone) {
		gnutls_deinit(cd->session);
		gnutls_certificate_free_credentials(cd->xcred);
		cd->tlsInitDone = false;
	}
#endif
}
