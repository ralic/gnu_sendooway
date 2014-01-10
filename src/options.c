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
#include "config.h"
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <pwd.h>
#include "smtp.h"
#include "options.h"
#include "auth.h"
#include "util.h"

/* Defaults */
struct options_t options = {
	.timeout = SMTP_TIMEOUT,
	.localname = NULL,
	.userInclude = NULL,
	.validUsers = NULL,

	.addReceivedField = true,
	.cloneEhlo = false,

	/* Mappings */
	.globalMappings = NULL,
	.userMappings = NULL,

	/* GnuTLS related */
	.sslCa = NULL,
	.sslCert = NULL,
	.sslKey = NULL,

	/* LDAP related */
	.ldapAuthDN = NULL,
	.ldapUri = NULL,
	.ldapSSLca = NULL,

	/* Auth backends */
#ifdef HAVE_LIBPAM
	.authBackend = abPAM,
#else
	#ifdef HAVE_LIBLDAP
	.authBackend = abLDAP,
	#else
	.authBackend = abNone,
	#endif
#endif
	.mailerEncryption = meAllowed,

	/* Smarthost AUTH */
	.smarthostCramMD5 = scAdvertised,
	.smarthostPlain = spAdvertised,
	.smarthostLogin = spAdvertised,

	/* SMTP Extensions */
	.ext8bitmime = e8bForce,
	.extMsgSize = 0
};

static void options_setString(char **strPtr, char *value) {
	if (*strPtr) free(*strPtr);
	if (value) {
		*strPtr = strdup(value);
		if (!*strPtr) util_logger(LOG_CRIT, "Out of memory");
	} else *strPtr = NULL;
}

static void options_addValidUser(bool isGroup, char *name) {
	options_validUser_t *new = malloc(sizeof(options_validUser_t));
	if (!new) goto oom;

	new->name = strdup(name);
	if (!new->name) goto oom;
	new->isGroup = isGroup;
	new->next    = options.validUsers;

	options.validUsers = new;
	return;

oom:
	if (new) free(new);
	util_logger(LOG_CRIT, "Out of memory");
	return;
}

static void options_addMapping(options_mapping_t type,
  char *value, bool isGlobal) {

	static options_maplist_t* lastGlobalElem = NULL;
	static options_maplist_t* lastUserElem   = NULL;

	options_maplist_t **first, **last;

	if (isGlobal) {
		first = &options.globalMappings;
		last  = &lastGlobalElem;
	} else {
		first = &options.userMappings;
		last  = &lastUserElem;
	}

	options_maplist_t *new = malloc(sizeof(options_maplist_t));
	if (!new) goto oom;

	new->string = strdup(value);
	if (!new->string) goto oom;
	new->type = type;
	new->next = NULL;

	if (!*last) {
		/* First element */
		*first = new;
	} else {
		/* Append at tail */
		(*last)->next = new;
	}

	*last = new;
	return;

oom:
	if (new) free(new);
	util_logger(LOG_CRIT, "Out of memory");
	return;
}

static bool options_getHostname() {
	char hostname[HOST_NAME_MAX];
	if (gethostname(hostname, sizeof(hostname)) < 0) return false;

	options_setString(&options.localname, hostname);
	return true;
}

static bool options_checkLine(char *line, char **keyPtr,
  char **valuePtr, char **errormsgPtr) {

	*keyPtr = line;
	*valuePtr = NULL;
	enum {beforeKey, atKey, afterKey, beforeValue, atValue, atEnd} pos;
	pos = beforeKey;
	int i;
	/* Find key and value */
	for (i=0; pos != atEnd; i++) switch (line[i]) {
		case ' ':
		case '\t':
			switch (pos) {
				case beforeKey:   *keyPtr = &line[i+1]; break;
				case beforeValue: *valuePtr = &line[i+1]; break;
				case atKey:       line[i] = '\0'; pos = afterKey; break;
				default:          break;
			}
			break;

		case '\0': /* Line to long or EOF - assume last */
		case '#':
		case '\r':
		case '\n':
			line[i] = '\0';
			if ((pos == atKey) || (pos == afterKey)) {
				*errormsgPtr = "missing value";
				return false;
			}
			pos = atEnd;
			break;

		case '=':
			if ((pos == atKey) || (pos == afterKey)) {
				line[i] = '\0';
				*valuePtr = &line[i+1];
				pos = beforeValue;
				break;
			}
			/* Fall through */
		default:
			if (pos == beforeKey) pos = atKey;
			else if (pos == beforeValue) pos = atValue;

			if ((line[i] < ' ') || (line[i] > '~')) {
				*errormsgPtr = "unexpected character";
				return false;
			}
	}

	if (*keyPtr   && !**keyPtr)    *keyPtr  = NULL;
	if (*valuePtr && !**valuePtr) *valuePtr = NULL;

	if (!*keyPtr && !*valuePtr) return true;
	if (!*keyPtr) {
		*errormsgPtr = "syntax error";
		return false;
	}

	return true;
}

static enum {pkOk, pkErrKey, pkErrValue} options_parseKeyword(
  char *key, char* value, bool isGlobal) {

	/* Strings */
	if (strcasecmp(key, "localname") == 0) {
		if (value) options_setString(&options.localname, value);
		  else options_getHostname();

		return pkOk;
	}
	if (strcasecmp(key, "userInclude") == 0) {
		if (isGlobal) options_setString(&options.userInclude, value);
		return pkOk;
	}
	if (strcasecmp(key, "sslCA") == 0) {
		options_setString(&options.sslCa, value);
		return pkOk;
	}
	if (strcasecmp(key, "sslCert") == 0) {
		if (isGlobal) options_setString(&options.sslCert, value);
		return pkOk;
	}
	if (strcasecmp(key, "sslKey") == 0) {
		if (isGlobal) options_setString(&options.sslKey, value);
		return pkOk;
	}
	if (strcasecmp(key, "ldapAuthDN") == 0) {
		if (isGlobal) options_setString(&options.ldapAuthDN, value);
		return pkOk;
	}
	if (strcasecmp(key, "ldapUri") == 0) {
		if (isGlobal) options_setString(&options.ldapUri, value);
		return pkOk;
	}
	if (strcasecmp(key, "ldapSSLca") == 0) {
		if (isGlobal) options_setString(&options.ldapSSLca, value);
		return pkOk;
	}

	/* Arrays */
	if (strcasecmp(key, "smarthostMapping") == 0) {
		if (util_strstart(value, "fetchmail:")) {
			if (!value[10]) return pkErrValue;
			options_addMapping(mapFetchmail, &value[10], isGlobal);
		} else if (util_strstart(value, "getmail:")) {
			if (!value[8]) return pkErrValue;
			options_addMapping(mapGetmail, &value[8], isGlobal);
		} else if (util_strstart(value, "direct:")) {
			options_addMapping(mapDirect, &value[7], isGlobal);
		} else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "ValidUser") == 0) {
		bool isGroup = (value[0] == '%');

		if (isGroup && !value[0]) return pkErrValue;

		options_addValidUser(isGroup, &value[isGroup ? 1 : 0]);
		return pkOk;
	}

	/* Bools */
	if (strcasecmp(key, "addReceivedField") == 0) {
		if (strcasecmp(value, "yes") == 0)
		  options.addReceivedField = true;
		else if (strcasecmp(value, "no") == 0)
		  options.addReceivedField = false;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "cloneEhlo") == 0) {
		if (strcasecmp(value, "yes") == 0)
		  options.cloneEhlo = true;
		else if (strcasecmp(value, "no") == 0)
		  options.cloneEhlo = false;
		else return pkErrValue;

		return pkOk;
	}

	/* Integers */
	if (strcasecmp(key, "timeout") == 0) {
		options.timeout = atoi(value);
		if (options.timeout > 0 && options.timeout < 300) return pkOk;
		else return pkErrValue;
	}

	/* Enums */
	if (strcasecmp(key, "authBackend") == 0) {
		if (strcasecmp(value, "none") == 0)
		  if (isGlobal) options.authBackend = abNone;
#ifdef HAVE_LIBPAM
		else if (strcasecmp(value, "PAM") == 0)
		  if (isGlobal) options.authBackend = abPAM;
#endif
#ifdef HAVE_LIBLDAP
		else if (strcasecmp(value, "LDAP") == 0)
		  if (isGlobal) options.authBackend = abLDAP;
#endif
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "mailerEncryption") == 0) {
		if (strcasecmp(value, "forbidden") == 0)
		  options.mailerEncryption = meForbidden;
		else if (strcasecmp(value, "allowed") == 0)
		  options.mailerEncryption = meAllowed;
		else if (strcasecmp(value, "required") == 0)
		  options.mailerEncryption = meRequired;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "smarthostPlain") == 0) {
		if (strcasecmp(value, "never") == 0)
		  options.smarthostPlain = spNever;
		else if (strcasecmp(value, "ifAdvertised") == 0)
		  options.smarthostPlain = spAdvertised;
		else if (strcasecmp(value, "alwaysTry") == 0)
		  options.smarthostPlain = spAlwaysTry;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "smarthostLogin") == 0) {
		if (strcasecmp(value, "never") == 0)
		  options.smarthostLogin = spNever;
		else if (strcasecmp(value, "ifAdvertised") == 0)
		  options.smarthostLogin = spAdvertised;
		else if (strcasecmp(value, "alwaysTry") == 0)
		  options.smarthostLogin = spAlwaysTry;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "smarthostCramMD5") == 0) {
		if (strcasecmp(value, "never") == 0)
		  options.smarthostCramMD5 = spNever;
		else if (strcasecmp(value, "ifAdvertised") == 0)
		  options.smarthostCramMD5 = spAdvertised;
		else if (strcasecmp(value, "alwaysTry") == 0)
		  options.smarthostCramMD5 = spAlwaysTry;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "ext8BitMime") == 0) {
		if (strcasecmp(value, "force") == 0)
		  options.ext8bitmime = e8bForce;
		else if (strcasecmp(value, "ignore") == 0)
		  options.ext8bitmime = e8bIgnore;
		else if (strcasecmp(value, "disable") == 0)
		  options.ext8bitmime = e8bDisable;
		else return pkErrValue;

		return pkOk;
	}
	if (strcasecmp(key, "extMessageSize") == 0) {
		if (strcasecmp(value, "disable") == 0)
		  options.extMsgSize = -1;
		else options.extMsgSize = atoi(value);

		return pkOk;
	}


	return pkErrKey;
}

bool options_parse(char *conffile, bool isGlobal) {
	if (!options_getHostname()) return false;

	FILE *f = fopen(conffile, "r");
	if (!f) {
		util_logger(LOG_CRIT, "Error while reading %s\n", conffile);
		return false;
	}

	char *errormsg = NULL;
	int lineno = 0;
	while (!feof(f)) {
		char *key;
		char *value;
		char buffer[1024];
		lineno++;

		if (!fgets(buffer, sizeof(buffer), f)) break;
		if (!options_checkLine(buffer, &key, &value, &errormsg))
		  goto failWithError;

		/* An empty line? */
		if (!key) continue;

		switch (options_parseKeyword(key, value, isGlobal)) {
			case pkErrKey:   errormsg = "unknown keyword"; break;
			case pkErrValue: errormsg = "unknown value";   break;
			case pkOk:       break;
		}
		if (errormsg) goto failWithError;
	}
	fclose(f);

	/* default, if sslCA is undefined */
	if (!options.sslCa || !*options.sslCa) {
		options_setString(&options.sslCa,
		  SYSCONFDIR"ssl/certs/ca-certificates.crt");
	}

#ifdef HAVE_LIBLDAP
	if (options.authBackend == abLDAP) {
		if ( (!options.ldapAuthDN || !*options.ldapAuthDN)
		  || (!options.ldapUri || !*options.ldapUri) ) {

			util_logger(LOG_CRIT, "The ldapAuthDN and ldapUri configuration "
			  "keys are essential if the LDAP backend is used. Please define "
			  "them or use another backend.");
			return false;
		}

		/* use sslCA, if ldapSSLca is undefined */
		if (!options.ldapSSLca || !*options.ldapSSLca) {
			options_setString(&options.ldapSSLca, options.sslCa);
		}
	}
#endif

	return true;

failWithError:
	util_logger(LOG_CRIT, "Parse of %s failed at line %i (%s)\n",
	  conffile, lineno, errormsg);
	fclose(f);
	return false;
}

bool options_parseUserInclude() {
	const char *replacements[] = {auth_session.username,
	  auth_session.home};
	char *conffile;
	bool ret = false;

	if (options.userInclude) {
		conffile = util_strreplace(options.userInclude, "uh", replacements);
		if (conffile) {
			ret = options_parse(conffile, false);
			free(conffile);
		}
	}

	/* default, if no smarthostMappings where defined */
	if (!options.globalMappings && !options.userMappings) {
		util_logger(LOG_WARNING, "No smarthostMappings defined - "
		  "falling back to defaults");

		options_addMapping(mapGetmail,   "%h/.getmail/.getmailrc", false);
		options_addMapping(mapFetchmail, "%h/.fetchmailrc",        false);
	}
	return ret;
}
