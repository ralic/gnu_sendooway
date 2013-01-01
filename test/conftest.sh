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

# This test checks if the example configuration
# file can be parsed without errors

. "$srcdir/common.sh"

echo QUIT | "$PROG" -l \&2 -c "$CONF"
exit $?
