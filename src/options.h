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
#ifndef _SENDOOWAY_OPTIONS_H__
#define _SENDOOWAY_OPTIONS_H__

#include "config.h"
#include <stdbool.h>

typedef enum {mapFetchmail, mapGetmail, mapDirect} options_mapping_t;

typedef struct options_maplist_t {
	options_mapping_t type;
	struct options_maplist_t* next;
	char* string;
} options_maplist_t;

typedef struct options_validUser_t {
	bool isGroup;
	struct options_validUser_t* next;
	char* name;
} options_validUser_t;

extern struct options_t {
	int timeout;
	char *localname, *userInclude;
	char *sslCa, *sslCert, *sslKey;
	char *ldapAuthDN, *ldapUri, *ldapSSLca;
	options_maplist_t *globalMappings, *userMappings;
	options_validUser_t *validUsers;
	enum {abNone, abPAM, abLDAP} authBackend;
	enum {meForbidden, meAllowed, meRequired} mailerEncryption;
	enum {spNever, spAdvertised, spAlwaysTry} smarthostPlain;
	enum {slNever, slAdvertised, slAlwaysTry} smarthostLogin;
	enum {scNever, scAdvertised, scAlwaysTry} smarthostCramMD5;
	enum {e8bForce, e8bIgnore, e8bDisable} ext8bitmime;
	bool addReceivedField, cloneEhlo;
	int extMsgSize;
} options;

bool options_parse(char *conffile, bool isGlobal);
bool options_parseUserInclude();

#endif
