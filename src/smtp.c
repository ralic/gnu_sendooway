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
#include "smtp.h"
#include "util.h"

smtp_cmd_t smtp_decodeCmd(char* cmdline) {
	if (util_strstart(cmdline, "HELO ")) return cmdHelo;
	if (util_strstart(cmdline, "EHLO ")) return cmdEhlo;
	if (util_strstart(cmdline, "AUTH ")) return cmdAuth;
	if (util_strstart(cmdline, "HELP")) return cmdHelp;
	if (util_strstart(cmdline, "STARTTLS")) return cmdStarttls;
	if (util_strstart(cmdline, "MAIL FROM:")) return cmdFrom;
	if (util_strstart(cmdline, "RCPT TO:")) return cmdRecv;
	if (util_strstart(cmdline, "NOOP")) return cmdNoop;
	if (util_strstart(cmdline, "QUIT")) return cmdQuit;
	if (util_strstart(cmdline, "DATA")) return cmdData;
	if (util_strstart(cmdline, "RSET")) return cmdRset;

	return cmdUnknown;
}
