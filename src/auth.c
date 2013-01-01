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
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#ifdef HAVE_LIBPAM
	#include <security/pam_appl.h>
#endif
#include "auth.h"
#include "util.h"
#include "options.h"

struct auth_session_t auth_session = {NULL, NULL};

#ifdef HAVE_LIBPAM
struct pam_login {
	const char* username;
	const char* password;
};
#endif

static bool auth_checkUsername(const char* username) {
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

bool auth_validate(const char* realm, const char* username,
  const char* password) {

	if (!auth_checkUsername(username)) return false;
#ifdef HAVE_LIBPAM
	/* Use PAM */
	pam_handle_t *pamh;
	struct pam_login login = {username, password};
	struct pam_conv conv = {auth_conv, &login};

	if (pam_start(realm, username, &conv, &pamh) != PAM_SUCCESS)
	  return false;

	if ( (pam_authenticate(pamh, 0) != PAM_SUCCESS)
		|| (pam_acct_mgmt(pamh, 0) != PAM_SUCCESS) ) {

		pam_end(pamh, 0);
		return false;
	}

	pam_end(pamh, 0);
	return true;
#else
	/* No password validation, allow only effective user */
	struct passwd *passwd = getpwnam(username);
	if (!passwd) return false;

	return (passwd->pw_uid == geteuid());
#endif
}

bool auth_runas(const char* username) {
	struct passwd *passwd = getpwnam(username);
	if (!passwd) return false;

	util_strfree(&auth_session.username, false);
	util_strfree(&auth_session.home, false);

	auth_session.username = strdup(passwd->pw_name);
	auth_session.home = strdup(passwd->pw_dir);

	if (!auth_session.username || !auth_session.home) {
		util_logger(LOG_CRIT,
		  "Out of memory while creating session for %u", username);
		return false;
	}

	setgroups(1, &passwd->pw_gid);
	if (setgid(passwd->pw_gid) != 0) return false;
	if (setuid(passwd->pw_uid) != 0) return false;
	if (chdir(passwd->pw_dir)  != 0) return false;

	return true;
}
