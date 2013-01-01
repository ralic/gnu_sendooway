#! /bin/sh
#
# This file is part of
#   Sendooway - a multi-user and multi-target SMTP proxy
#   Copyright (C) 2012, 2013 Michael Kammer
#
# Sendooway is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Sendooway is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Sendooway.  If not, see <http://www.gnu.org/licenses/>.
#

# This tests some very simple SMTP keywords.

. "$srcdir/common.sh"

check() {
	# $1 = retval
	# $2 = cmd

	resp="$1"
	shift

	echo "Testing $1..." >&2

	(while [ "$1" ]; do echo "$1"; shift; done) |
	 "$PROG" -l \&2 -c /dev/null | (
		# Welcome message
		read r m
		if ! test x"$r" = x"220"; then
			echo "ERROR: Welcome failed" >&2
			return 1
		fi

		# Command Response
		r=
		while read ir im; do
			r="$ir"
		done
		if ! test x"$r" = x"$resp"; then
			echo "ERROR: Awaited $resp, but received $r" >&2
			return 1
		fi
	)

	return 0
}

check 502 "KUSPBV_IS_NO_VALID_KEYWORD"
check 250 "HELO Foo"
check 250 "EHLO bar"
check 250 "RSET"
check 530 "MAIL FROM: <alice>"
check 503 "RCPT TO: <bob>"
check 503 "DATA"
check 504 "AUTH ME"
check 334 "AUTH LOGIN"
check 501 "AUTH LOGIN" "*"
check 334 "AUTH PLAIN"
check 501 "AUTH PLAIN" "*"
check 250 "NOOP"
check 221 "QUIT"

exit 0
