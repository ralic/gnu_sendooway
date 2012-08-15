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
#ifndef _SENDOOWAY_SMTP_H__
#define _SENDOOWAY_SMTP_H__

#include "config.h"
#include <stdbool.h>

/** @brief Maximum length of command line (RFC 2821) */
#define SMTP_MAXCMDLEN (512)

/** @brief Maximum length of text line (RFC 2821) */
#define SMTP_MAXLINE (1000)

/** @brief Default timeout in seconds (RFC 2821) */
#define SMTP_TIMEOUT (300)

typedef enum {
	cmdUnknown,
	cmdHelp,
	cmdHelo,
	cmdEhlo,
	cmdFrom,
	cmdRecv,
	cmdNoop,
	cmdQuit,
	cmdRset,
	cmdData,
	cmdVrfy,
	cmdStarttls,
	cmdAuth
} smtp_cmd_t;

typedef enum {
	replyError           = false,
	replyHelp            = 214,
	replyWelcome         = 220,
	replyQuit            = 221,
	replyAuthOk          = 235,
	replyOk              = 250,
	replyAuth            = 334,
	replySendData        = 354,
	replyTLSFailed       = 454,
	replySyntaxCmd       = 500,
	replySyntaxArg       = 501,
	replyUnknownCmd      = 502,
	replyBadSequence     = 503,
	replyAuthUnsupported = 504,
	replyAuthNeeded      = 530,
	replyAuthFailed      = 535,
	replyNotTaken        = 553,
	replyDoubleTLS       = 554
} smtp_reply_t;

smtp_cmd_t smtp_decodeCmd(char* cmdline);

#endif
