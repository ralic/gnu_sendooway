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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_LIBPAM
	#include <security/pam_appl.h>
#endif
#ifdef HAVE_LIBLDAP
	#include <ldap.h>
#endif
#include "auth.h"
#include "util.h"
#include "options.h"

struct auth_session_t auth_session = {0, 0, NULL, NULL};

#ifdef HAVE_LIBPAM
struct pam_login {
	const char* username;
	const char* password;
};
#endif

static bool auth_dropPrivileges() {
	if ((setgroups(1, &auth_session.gid) != 0)
	  || (setgid(auth_session.gid) != 0)
	  || (setuid(auth_session.uid) != 0)) {

		util_logger(LOG_CRIT, "Unable to drop privileges. Has the user "
		  "running sendooway sufficient rights?");
		return false;
	}

	if (chdir(auth_session.home) != 0) {
		util_logger(LOG_WARNING, "Unable to change to home directory of "
		  "%s (%s)", auth_session.username, auth_session.home);
		return false;
	}

	return true;
}

static bool auth_checkUsername_nss(const char* username) {
	options_validUser_t *item = options.validUsers;
	if (!item) return true;

	/* Find user or fail */
	struct passwd *pw = getpwnam(username);
	if (!pw) return false;

	/* Get grouplist of user */
	bool retval = false;
	gid_t *groups;
	int ngroups = 0;

	getgrouplist(pw->pw_name, pw->pw_gid, NULL, &ngroups);

	groups = malloc(ngroups * sizeof(gid_t));
	if (!groups || (getgrouplist(pw->pw_name,
	  pw->pw_gid, groups, &ngroups) == -1)) return false;

	for (;item;item = item->next) {
		if (item->isGroup) {
			int i;
			struct group *group = getgrnam(item->name);

			if (group) for (i=0;i<ngroups;i++) {
				retval = (group->gr_gid == groups[i]);
				if (retval) break;
			}
		} else {
			retval = (strcasecmp(item->name, username) == 0);
		}
	}

	free(groups);
	return retval;
}

#ifdef HAVE_LIBPAM
static int auth_conv(int num_msg, const struct pam_message **msg,
  struct pam_response **resp, void *appdata_ptr) {

	/* Quickly check for error messages */
	int i;
	for (i=0;i<num_msg;i++) if (msg[i]->msg_style == PAM_ERROR_MSG)
	  return PAM_SUCCESS;

	struct pam_login *login = appdata_ptr;
	struct pam_response *reply;

	if (!(reply = malloc(num_msg * sizeof(struct pam_response)))) {
		/* Out of memory */
		return PAM_CONV_ERR;
	}

	for (i=0;i<num_msg;i++) {
		switch (msg[i]->msg_style) {
			case PAM_PROMPT_ECHO_OFF:
				reply[i].resp_retcode = 0;
				reply[i].resp = strdup(login->password);
				break;
			case PAM_PROMPT_ECHO_ON:
				reply[i].resp_retcode = 0;
				reply[i].resp = strdup(login->username);
				break;
			default:
				break;
		}
	}

	*resp = reply;
	return PAM_SUCCESS;
}
#endif // HAVE_LIBPAM

#ifdef HAVE_LIBLDAP
static bool auth_logon_ldap(const char* username,
  const char* password) {

	/* Format auth DN */
	const char *replacements[] = {username};
	char *user_dn = util_strreplace(options.ldapAuthDN, "u",
	  replacements);
	if (!user_dn) {
		util_logger(LOG_CRIT, "Out of memory");
		return false;
	}

	/* Initialize, setup and bind LDAP */
	LDAP * ldap = NULL;
	const int ver = 3;

	int errval = ldap_initialize(&ldap, options.ldapUri);
	if (errval != LDAP_SUCCESS || !ldap) {
		util_logger(LOG_INFO, "Initialization of LDAP failed: %s",
		  ldap_err2string(errval));
		goto err;
	}

	ldap_set_option(ldap, LDAP_OPT_PROTOCOL_VERSION, &ver);
	ldap_set_option(ldap, LDAP_OPT_X_TLS_CACERTFILE, options.ldapSSLca);

	errval = ldap_simple_bind_s(ldap, user_dn, password);
	if (errval != LDAP_SUCCESS) {
		util_logger(LOG_INFO, "Binding LDAP failed: %s",
		  ldap_err2string(errval));
		goto err;
	}

	/* Search LDAP */
	util_strfree(&auth_session.username, false);
	util_strfree(&auth_session.home, false);

	char *ra[] = {"uidNumber", "gidNumber", "uid", "homeDirectory", NULL};
	int ra_num = 4;

	LDAPMessage *res;

	errval = ldap_search_ext_s(ldap, user_dn, LDAP_SCOPE_BASE,
	  NULL, ra, 0, NULL, NULL, NULL, LDAP_NO_LIMIT, &res);
	if (errval != LDAP_SUCCESS) {
		util_logger(LOG_INFO, "Querying LDAP failed: %s",
		  ldap_err2string(errval));
		goto err;
	}

	LDAPMessage *msg = ldap_first_message(ldap, res);
	for (; msg; msg = ldap_next_message(ldap, msg)) {
		if (ldap_msgtype(msg) != LDAP_RES_SEARCH_ENTRY) continue;

		BerElement *ber = NULL;
		char *a = ldap_first_attribute(ldap, msg, &ber);
		for (; a; a = ldap_next_attribute(ldap, msg, ber)) {
			bool is_gid = !strcasecmp(a, "gidNumber");
			bool is_uid = !strcasecmp(a, "uidNumber");
			bool is_username = !strcasecmp(a, "uid");
			bool is_homedir = !strcasecmp(a, "homeDirectory");

			if (!is_gid && !is_uid && !is_username && !is_homedir) continue;
			ra_num--;

			char **vals = (char**) ldap_get_values(ldap, res, a);
			if (ldap_count_values(vals) > 0) {
				if (is_gid) auth_session.gid = atoi(vals[0]);
				if (is_uid) auth_session.uid = atoi(vals[0]);
				if (is_homedir) auth_session.home = strdup(vals[0]);
				if (is_username) auth_session.username = strdup(vals[0]);
			}

			ldap_value_free(vals);
			ldap_memfree(a);
		}
		if (ber) ber_free(ber, 0);
	}

	ldap_unbind(ldap);
	ldap = NULL;

	if (ra_num > 0) {
		util_logger(LOG_WARNING, "Missing attributes in LDAP entry (%s)."
		  " Check configuration!", user_dn);
		goto err;
	}
	util_strfree(&user_dn, false);

	if (!auth_session.username || !auth_session.home) {
		util_logger(LOG_CRIT,
		  "Out of memory while creating session for %u", username);
		return false;
	}

	/* Finally */
	return auth_dropPrivileges();

err:
	util_strfree(&user_dn, false);
	if (!ldap) ldap_unbind(ldap);
	return false;
}
#endif // HAVE_LIBLDAP

static bool auth_logon_none(const char* username,
  const char* password) {

	if (!auth_checkUsername_nss(username)) return false;

	/* No password validation, allow only effective user */
	struct passwd *passwd = getpwnam(username);
	if (!passwd) return false;
	if (passwd->pw_uid != getuid()) return false;

	util_strfree(&auth_session.username, false);
	util_strfree(&auth_session.home, false);

	auth_session.username = strdup(passwd->pw_name);
	auth_session.home = strdup(passwd->pw_dir);
	auth_session.gid = passwd->pw_gid;
	auth_session.uid = passwd->pw_uid;

	if (!auth_session.username || !auth_session.home) {
		util_logger(LOG_CRIT,
		  "Out of memory while creating session for %u", username);
		return false;
	}

	/* Do not change (e)uid/gid, but change directory */
	if (chdir(auth_session.home) != 0) {
		util_logger(LOG_WARNING, "Unable to change to home directory of "
		  "%s (%s)", auth_session.username, auth_session.home);
		return false;
	}

	return true;
}

#ifdef HAVE_LIBPAM
static bool auth_logon_pam(const char* username,
  const char* password) {

	if (!auth_checkUsername_nss(username)) return false;

	pam_handle_t *pamh;
	struct pam_login login = {username, password};
	struct pam_conv conv = {auth_conv, &login};

	if (pam_start("sendooway", username, &conv, &pamh) != PAM_SUCCESS)
	  return false;

	if ( (pam_authenticate(pamh, 0) != PAM_SUCCESS)
		|| (pam_acct_mgmt(pamh, 0) != PAM_SUCCESS) ) {

		pam_end(pamh, 0);
		return false;
	}
	pam_end(pamh, 0);

	struct passwd *passwd = getpwnam(username);
	if (!passwd) return false;

	util_strfree(&auth_session.username, false);
	util_strfree(&auth_session.home, false);

	auth_session.username = strdup(passwd->pw_name);
	auth_session.home = strdup(passwd->pw_dir);
	auth_session.gid = passwd->pw_gid;
	auth_session.uid = passwd->pw_uid;

	if (!auth_session.username || !auth_session.home) {
		util_logger(LOG_CRIT,
		  "Out of memory while creating session for %u", username);
		return false;
	}

	return auth_dropPrivileges();
}
#endif

bool auth_logon(const char* username, const char* password) {
	switch (options.authBackend) {
		case abNone: return auth_logon_none(username, password);
#ifdef HAVE_LIBPAM
		case abPAM:  return auth_logon_pam(username, password);
#endif
#ifdef HAVE_LIBLDAP
		case abLDAP: return auth_logon_ldap(username, password);
#endif
		default:     return false;
	}
}
