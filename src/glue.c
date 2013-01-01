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
#include <stdio.h>
#include <string.h>
#include "util.h"
#include "glue.h"
#include "auth.h"
#include "options.h"

static bool glue_addrcmp(const char *address, const char *domain,
  const char *match) {

	/* Full match <mailbox@domain> */
	if (strcasecmp(match, address) == 0) return true;

	/* Default address <*> */
	if (strcmp(match, "*") == 0) return true;

	/* Domain address <*@domain> */
	if (util_strstart(match, "*@") &&
	  (strcasecmp(domain, &match[2]) == 0)) return true;

	/* Comparison failed */
	return false;
}

#ifndef USE_DB_GETMAIL
	#define glue_lookupGetmail(address, domain, cd, filename) false
#else
static bool glue_lookupGetmail(char* address, char* domain,
  client_data_t* cd, char* filename) {

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

	struct data_t {
		char *host, *port, *user, *pass;
	} rStruct = {0,0,0,0}, sStruct = {0,0,0,0}, *section = NULL;
	bool retval = false;

	while (!feof(f)) {
		char key[1024];
		char *value;
		if (!fgets(key, sizeof(key), f)) break;

		if (key[0] == '[') {
			if (util_strstart(key, "[retriever]")) section = &rStruct;
			else if (util_strstart(key, "[sender]")) section = &sStruct;
			else section = NULL;
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

		if (section) {
			if (strcasecmp(key, "server") == 0) {
				if (!section->host) section->host = strdup(value); /* NULL ok */
			} else if (strcasecmp(key, "port") == 0) {
				if (!section->port) section->port = strdup(value); /* NULL ok */
			} else if (strcasecmp(key, "username") == 0) {
				if (!section->user) section->user = strdup(value); /* NULL ok */
			} else if (strcasecmp(key, "password") == 0) {
				if (!section->pass) section->pass = strdup(value); /* NULL ok */
			}

			if (section == &sStruct) {
				if (strcasecmp(key, "address") == 0) {
					/* Most interesting thing... */
					retval = retval | glue_addrcmp(address, domain, value);
				} else if (strcasecmp(key, "type") == 0) {
					if (strcasecmp(value, "SimpleSMTPTLSSender") == 0)
						cd->secType = secTLS;
					else if (strcasecmp(value, "SimpleSMTPSSLSender") == 0)
						cd->secType = secSSL;
					else if (strcasecmp(value, "SimpleSMTPSender") == 0)
						cd->secType = secNone;
				} else if (strcasecmp(key, "no_certificate_check") == 0) {
					cd->noCertificateCheck =
						(strcasecmp(value, "true") == 0) ||
						(strcasecmp(value, "on")   == 0) ||
						(strcasecmp(value, "yes")  == 0) ||
						(strcasecmp(value, "1")    == 0);
				}
			}
		}
	}
	fclose(f);

	if (retval) {
		util_strfree(&cd->host, false);
		util_strfree(&cd->port, false);
		util_strfree(&cd->username, false);
		util_strfree(&cd->password, true);

		if (sStruct.host) util_swap(sStruct.host, cd->host, char*);
		  else util_swap(rStruct.host, cd->host, char*);

		if (sStruct.port) util_swap(sStruct.port, cd->port, char*);
		  else util_swap(rStruct.port, cd->port, char*);

		if (sStruct.user) util_swap(sStruct.user, cd->username, char*);
		  else util_swap(rStruct.user, cd->username, char*);

		if (sStruct.pass) util_swap(sStruct.pass, cd->password, char*);
		  else util_swap(rStruct.pass, cd->password, char*);

		if (!cd->port) switch (cd->secType) {
			/* I guess an unsafe server is so old, that it still listens
			 * on port 25 (Note: 587 is preferred for clients). */
			case secNone: cd->port = strdup("25"); break;  /* NULL ok */
			case secTLS:  cd->port = strdup("587"); break; /* NULL ok */
			case secSSL:  cd->port = strdup("465"); break; /* NULL ok */
		}
	}

	util_strfree(&sStruct.host, false);util_strfree(&rStruct.host, false);
	util_strfree(&sStruct.port, false);util_strfree(&rStruct.port, false);
	util_strfree(&sStruct.user, false);util_strfree(&rStruct.user, false);
	util_strfree(&sStruct.pass, true); util_strfree(&rStruct.host, true);

	return retval;
}
#endif

#ifndef USE_DB_FETCHMAIL
	#define glue_lookupFetchmail(address, domain, cd, filename) false
#else
static bool glue_lookupFetchmail(char* address, char *domain,
  client_data_t* cd, char* filename) {

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
	bool optionNoAuth    = false;

	cd->secType = secNone;
	cd->noCertificateCheck = false;

	while (!feof(f)) {
		char buf[1024];
		if (!fgets(buf, sizeof(buf), f)) break;

		char *keyword = buf;
		while (1) {
			/** @todo Adapt and use util_strparse() here */
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
				if (strcasecmp(keyword, "user") == 0) {
					util_strfree(&cd->username, false);
					cd->username = strdup(value); /* NULL okay */
				} else if (strcasecmp(keyword, "pass") == 0) {
					util_strfree(&cd->password, true);
					cd->password = strdup(value); /* NULL okay */
				}
			}

			if (strcasecmp(keyword, "#sendooway:user") == 0) {
				useRetrieverAcc = false;
				util_strfree(&cd->username, false);
				cd->username = strdup(value); /* NULL okay */
			} else if (strcasecmp(keyword, "#sendooway:pass") == 0) {
				useRetrieverAcc = false;
				util_strfree(&cd->password, true);
				cd->password = strdup(value); /* NULL okay */
			} else if (strcasecmp(keyword, "#sendooway:tls") == 0) {
				cd->secType = secTLS;
			} else if (strcasecmp(keyword, "#sendooway:ssl") == 0) {
				cd->secType = secSSL;
			} else if (strcasecmp(keyword, "#sendooway:noCertCheck") == 0) {
				cd->noCertificateCheck = true;
			} else if (strcasecmp(keyword, "#sendooway:noAuth") == 0) {
				optionNoAuth = true;
			} else if (strcasecmp(keyword, "#sendooway:server") == 0) {
				util_strfree(&cd->host, false);
				cd->host = strdup(value); /* NULL okay */
			} else if (strcasecmp(keyword, "#sendooway:port") == 0) {
				useDefaultPort = false;
				util_strfree(&cd->port, false);
				cd->port = strdup(value); /* NULL okay */
			} else if (strcasecmp(keyword, "#sendooway:address") == 0) {
				if (glue_addrcmp(address, domain, value)) {
					fclose(f);
					if (optionNoAuth) {
						util_strfree(&cd->username, false);
						util_strfree(&cd->password, true);
					}
					if (useDefaultPort) util_strfree(&cd->port, false);
					if (useDefaultPort) switch (cd->secType) {
						/* I guess an unsafe server is so old, that it still listens
						 * on port 25 (Note: 587 is preferred for clients). */
						case secNone: cd->port = strdup("25"); break;  /* NULL ok */
						case secTLS:  cd->port = strdup("587"); break; /* NULL ok */
						case secSSL:  cd->port = strdup("465"); break; /* NULL ok */
					}
					return true;
				}
			}

			keyword = end+1;
		}
	}

	fclose(f);
	util_strfree(&cd->password, true);
	return false;
}
#endif

#ifndef USE_DB_SENDOOWAY
	#define glue_lookupDirect(address, domain, cd, string) false
#else
static bool glue_lookupDirect(char* address, char *domain,
  client_data_t* cd, char* string) {

	/** @todo Parse only once, do not rely on malloc() */

	char *tmpStr = strdup(string);
	if (!tmpStr) {
		util_logger(LOG_CRIT, "Out of memory while parsing smarthostMapping"
		  " for user %u", auth_session.username);
		return false;
	}

	char *value, *linePtr = tmpStr;

	if (util_strparse(&linePtr, " ") != ' ') goto failed;
	if (!glue_addrcmp(address, domain, tmpStr)) goto failed;

	value = linePtr;
	if (util_strparse(&linePtr, " ") != ' ') goto failed;
	cd->host = strdup(value); /* NULL okay */

	value = linePtr;
	if (util_strparse(&linePtr, " ") != ' ') goto failed;
	cd->port = strdup(value); /* NULL okay */

	value = linePtr;
	if (util_strparse(&linePtr, " ") != ' ') goto failed;
	cd->username = strdup(value); /* NULL okay */

	value = linePtr;
	if (util_strparse(&linePtr, " ") != ' ') goto failed;
	cd->password = strdup(value); /* NULL okay */

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
		} else if (strcasecmp(option, "noauth") == 0) {
			util_strfree(&cd->username, false);
			util_strfree(&cd->password, true);
		} else {
			util_logger(LOG_WARNING, "User %s uses an unrecognized "
				"configuration option (%s)", auth_session.username,
				option);
		}
	}

	free(tmpStr);
	return true;

failed:
	free(tmpStr);
	return false;
}
#endif

static bool glue_lookupList(char *address, char *domain,
  client_data_t *cd, options_maplist_t *list) {

	for (;list;list = list->next) {
		switch (list->type) {
			case mapGetmail:
				if (glue_lookupGetmail(address, domain, cd, list->string)) {
					return true;
				} else break;

			case mapFetchmail:
				if (glue_lookupFetchmail(address, domain, cd, list->string)) {
					return true;
				} else break;

			case mapDirect:
				if (glue_lookupDirect(address, domain, cd, list->string)) {
					return true;
				} else break;
		}
	}

	return false;
}

bool glue_lookup(char* address, char *domain, client_data_t* cd) {
	/* Search user mappings */
	if (glue_lookupList(address, domain, cd, options.userMappings)) {
		return true;
	}

	/* Search global mappings */
	if (glue_lookupList(address, domain, cd, options.globalMappings)) {
		return true;
	}

	/* Nothing was found */
	return false;
}
