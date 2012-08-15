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
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "glue.h"
#include "auth.h"
#include "options.h"

#ifndef USE_DB_GETMAIL
	#define glue_lookupGetmail(address, cd, filename) false
#else
static bool glue_lookupGetmail(char* address, client_data_t* cd,
  char* filename) {

	const char *replacements[] = {auth_session.username,
	  auth_session.home};
	filename = util_strreplace(filename, "uh", replacements);
	if (!filename) return false;

	FILE * f = fopen(filename, "r");
	if (!f) {
		util_logger(LOG_WARNING, "Failed to open %s for %s\n", filename,
		  auth_session.username);
	}
	free(filename);
	if (!f) return false;

	enum {secUnknown, secRetriever, secSender} section = secUnknown;
	bool useDefaultPort     = true;
	bool useRetrieverServer = true;
	bool useRetrieverAcc    = true;
	bool retval = false;

	while (!feof(f)) {
		char key[1024];
		char *value;
		if (!fgets(key, sizeof(key), f)) break;

		if (key[0] == '[') {
			if (util_strstart(key, "[retriever]")) section = secRetriever;
			else if (util_strstart(key, "[sender]")) section = secSender;
			else section = secUnknown;
		} else if (key[0] == '=') continue;

		value = strchr(key, '=');
		if (!value) continue;

		/* Trim right (keyword) and separate value */
		{
			int i = (value-key);
			key[i] = '\0';
			while (i && ((key[i] <= ' ') || (key[i] >= 126))) i--;
			key[i+1] = '\0';
		}

		/* Trim left (value) */
		do {value++;} while ((*value <= ' ') || (*value >= 126));

		/* Trim right (value) */
		{
			int i, last = 0;
			for (i=0;value[i];i++)
				if ((value[i] > ' ') && (value[i] <= 126)) last = i;
			if (!last) continue;
			value[last+1] = '\0';
		}

		switch (section) {
			case secSender:
				if (strcasecmp(key, "server") == 0) {
					util_strcpy(cd->host, value, sizeofMember(client_data_t,
					  host));
					useRetrieverServer = false;
				} else if (strcasecmp(key, "port") == 0) {
					util_strcpy(cd->port, value, sizeofMember(client_data_t,
					  port));
					useRetrieverServer = false;
					useDefaultPort = false;
				} else if (strcasecmp(key, "address") == 0) {
					/* Most interesting thing... */
					retval = retval | (strcasecmp(address, value) == 0);
				} else if (strcasecmp(key, "username") == 0) {
					util_strcpy(cd->username, value, sizeofMember(client_data_t,
					  username));
					useRetrieverAcc = false;
				} else if (strcasecmp(key, "password") == 0) {
					util_strcpy(cd->password, value, sizeofMember(client_data_t,
					  password));
					useRetrieverAcc = false;
				} else if (strcasecmp(key, "type") == 0) {
					if (strcasecmp(value, "SimpleSMTPTLSSender") == 0)
					  cd->secType = secTLS;
					else if (strcasecmp(value, "SimpleSMTPSSLSender") == 0)
					  cd->secType = secSSL;
					else if (strcasecmp(value, "SimpleSMTPSender") == 0)
					  cd->secType = secNone;
				}
				break;

			case secRetriever:
				if (useRetrieverServer) {
					if (strcasecmp(key, "server") == 0) util_strcpy(
					  cd->host, value, sizeofMember(client_data_t, host));
					else if (strcasecmp(key, "port") == 0) util_strcpy(
					  cd->port, value, sizeofMember(client_data_t, port));
				}
				if (useRetrieverAcc) {
					if (strcasecmp(key, "username") == 0) util_strcpy(
					  cd->username, value, sizeofMember(client_data_t, username));
					else if (strcasecmp(key, "password") == 0) util_strcpy(
					  cd->password, value, sizeofMember(client_data_t, password));
				}
				break;

			default:
				break;
		}
	}
	fclose(f);

	if (retval) {
		if (useDefaultPort) switch (cd->secType) {
			/* I guess an unsafe server is so old, that it still listens
			 * on port 25 (Note: 587 is preferred for clients). */
			case secNone: strcpy(cd->port, "25");  break;
			case secTLS:  strcpy(cd->port, "587"); break;
			case secSSL:  strcpy(cd->port, "465"); break;
		}
	} else memset(cd->password, 0, sizeofMember(client_data_t, password));

	return retval;
}
#endif

#ifndef USE_DB_FETCHMAIL
	#define glue_lookupFetchmail(address, cd, filename) false
#else
static bool glue_lookupFetchmail(char* address, client_data_t* cd,
  char* filename) {

	const char *replacements[] = {auth_session.username,
	  auth_session.home};
	filename = util_strreplace(filename, "uh", replacements);
	if (!filename) return false;

	FILE * f = fopen(filename, "r");
	if (!f) {
		util_logger(LOG_WARNING, "Failed to open %s for %s\n", filename,
		  auth_session.username);
	}
	free(filename);
	if (!f) return false;

	bool useDefaultPort  = true;
	bool useRetrieverAcc = true;

	cd->secType = secNone;
	cd->noCertificateCheck = false;

	while (!feof(f)) {
		char buf[1024];
		if (!fgets(buf, sizeof(buf), f)) break;

		char *keyword = buf;
		while (1) {
			/** @todo Adapt and use util_strstep() here */
			/* Trim keyword left */
			while ((*keyword == ' ') || (*keyword == '\t')) keyword++;
			if (!*keyword) break;
			/* Find end of keyword */
			char *value = keyword;
			while ((*value > ' ') && (*value <= 126)) value++;
			if (!*value) break;
			*value = '\0';
			/* Trim value left */
			do {value++;} while ((*value == ' ') || (*value == '\t'));
			if (!*value) break;
			/* Find end of value */
			char *end;
			if (value[0] == '#') {
				/* Empty value */
				value--;
				*value = '\0';
				end = value;
			} else if (value[0] == '"') {
				value++;
				end = strchr(value, '"');
				if (!end) break;
			} else {
				end = value;
				while ((*end > ' ') && (*end <= 126)) end++;
				if (!*end) break;
			}
			*end = '\0';

			/* Analyze */
			if (useRetrieverAcc) {
				if (strcasecmp(keyword, "user") == 0) util_strcpy(cd->username,
				  value, sizeofMember(client_data_t, username));
				else if (strcasecmp(keyword, "pass") == 0) util_strcpy(
				  cd->password, value, sizeofMember(client_data_t, password));
			}

			if (strcasecmp(keyword, "#sendooway:user") == 0) {
				useRetrieverAcc = false;
				util_strcpy(cd->username, value, sizeofMember(client_data_t,
				  username));
			} else if (strcasecmp(keyword, "#sendooway:pass") == 0) {
				useRetrieverAcc = false;
				util_strcpy(cd->password, value, sizeofMember(client_data_t,
				  password));
			} else if (strcasecmp(keyword, "#sendooway:tls") == 0) {
				cd->secType = secTLS;
			} else if (strcasecmp(keyword, "#sendooway:ssl") == 0) {
				cd->secType = secSSL;
			} else if (strcasecmp(keyword, "#sendooway:noCertCheck") == 0) {
				cd->noCertificateCheck = true;
			} else if (strcasecmp(keyword, "#sendooway:server") == 0) {
				util_strcpy(cd->host, value, sizeofMember(client_data_t, host));
			} else if (strcasecmp(keyword, "#sendooway:port") == 0) {
				useDefaultPort = false;
				util_strcpy(cd->port, value, sizeofMember(client_data_t, port));
			} else if (strcasecmp(keyword, "#sendooway:address") == 0) {
				if (strcasecmp(value, address) == 0) {
					fclose(f);
					if (useDefaultPort) switch (cd->secType) {
						/* I guess an unsafe server is so old, that it still listens
						 * on port 25 (Note: 587 is preferred for clients). */
						case secNone: strcpy(cd->port, "25");  break;
						case secTLS:  strcpy(cd->port, "587"); break;
						case secSSL:  strcpy(cd->port, "465"); break;
					}
					return true;
				}
			}

			keyword = end+1;
		}
	}

	fclose(f);
	memset(cd->password, 0, sizeofMember(client_data_t, password));
	return false;
}
#endif

static bool glue_lookupList(char* address, client_data_t* cd,
  options_maplist_t* list) {

	for (;list;list = list->next) {
		switch (list->type) {
			case mapGetmail:
				if (glue_lookupGetmail(address, cd, list->string)) return true;
				break;

			case mapFetchmail:
				if (glue_lookupFetchmail(address, cd, list->string))return true;
				break;

			case mapDirect:
#ifdef USE_DB_SENDOOWAY
				if (util_strstart(list->string, address)) {
					char *linePtr = &list->string[strlen(address)];

					/* Expect space */
					if (*linePtr++ == ' ') {
						util_strstep(&linePtr, cd->host,
						  sizeofMember(client_data_t, host), ' ');
						util_strstep(&linePtr, cd->port,
						  sizeofMember(client_data_t, port), ' ');
						util_strstep(&linePtr, cd->username,
						  sizeofMember(client_data_t, username), ' ');
						util_strstep(&linePtr, cd->password,
						  sizeofMember(client_data_t, password), ' ');

						cd->secType = secNone;
						cd->noCertificateCheck = false;

						char *option;
						while (*linePtr) {
							option = linePtr;
							util_strparse(&linePtr, ",");

							if (strcasecmp(option, "noCertCheck") == 0) {
								cd->noCertificateCheck = true;
							} else if (strcasecmp(option, "tls") == 0) {
								cd->secType = secTLS;
							} else if (strcasecmp(option, "ssl") == 0) {
								cd->secType = secSSL;
							} else {
								util_logger(LOG_WARNING, "User %s uses an unrecognized "
									"configuration option (%s)", auth_session.username,
									option);
							}
						}

						return true;
					}
				}
#endif
				break;
		}
	}

	return false;
}

bool glue_lookup(char* address, client_data_t* cd) {
	/* Search user mappings */
	if (glue_lookupList(address, cd, options.userMappings)) return true;

	/* Search global mappings */
	if (glue_lookupList(address, cd, options.globalMappings)) return true;

	/* Nothing was found */
	return false;
}
