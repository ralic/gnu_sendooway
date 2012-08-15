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
set -e

PROG="../src/sendooway"
CONF="$srcdir/../etc/sendooway.conf"
TESTDIR="$srcdirs/../test"

TMP="`pwd`/$$.tmp"
