#! /bin/sh
#
# This file is part of
#   Sendooway - a multi-user and multi-target SMTP proxy
#   Copyright (C) 2012 Michael Kammer
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

# This test sends invalid input to Sendooway

. "$srcdir/common.sh"

await() {
	retval=2
	read welcome_msg
	echo " > $welcome_msg" > "$TMP"
	while read line; do
		echo " > $line" >> "$TMP"
		line=${line/-/ }
		for resp in $line; do
			if ! test x"$resp" = x"$1"; then
				echo "$2 failed (awaited $1, but received $resp)" >&2
				retval=1
			fi
			break
		done

		if test "$retval" -eq 2; then
			retval=0
		fi
	done

	case "$retval" in
		0) echo "$2 passed" >&2;;
		1) ;;
		2) echo "$2 failed (awaited $1, but received nothing)" >&2;;
	esac

	cat "$TMP" >&2
	echo >&2
	rm "$TMP"
	return $retval
}

if test -z "$BASH_VERSION"; then
 test -x "/bin/bash" && exec /bin/bash "$0"
 echo "Bash is needed for this test - Skipping" >&2
 exit 77
fi

# Garbage ident
printf 'HELO \x42\x00\x42\x0D\x0A' | "$PROG" -l \&2 -c "$CONF" | await 500 "Garbage ident"

# Maximum command length (max)
(	printf 'HELO '
	i=$((512-2-5))
	while test "$i" -gt 0; do
		printf 'a'
		i=$(($i - 1))
	done
	printf '\x0D\x0A') | "$PROG" -l \&2 -c "$CONF" | await 250 "Maximum command length"

# Maximum command length (above)
(	printf 'HELO '
	i=$((512-2-5   + 1))
	while test "$i" -gt 0; do
		printf 'a'
		i=$(($i - 1))
	done
	printf '\x0D\x0A') | "$PROG" -l \&2 -c "$CONF" | await 500 "Too long line"

# Garbage mime
printf 'AUTH PLAIN abc[]def\x0A\x0D' | "$PROG" -l \&2 -c "$CONF" | await 501 "Garbage mime"

exit 0
