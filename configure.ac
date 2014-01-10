# Sendooway - a multi-user and multi-target SMTP proxy
#   Copyright (C) 2012-2014 Michael Kammer
#   Published under the GNU GPL version 3 (or later)
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
AC_PREREQ([2.67])
AC_INIT([sendooway], [0.1.0], [KaMichael@gmail.com],, [http://www.kuspbv.de/sendooway/])
AC_CONFIG_SRCDIR([src/sendooway.c])
AC_CONFIG_HEADERS([src/config.h])
AM_INIT_AUTOMAKE([-Wall -Werror parallel-tests])

AC_ARG_ENABLE([db-getmail],
              AS_HELP_STRING([--disable-db-getmail],
                             [disable getmail parser (~/.getmailrc support)]),
              [],
              [enable_db_getmail=yes]
)
AC_ARG_ENABLE([db-fetchmail],
              AS_HELP_STRING([--disable-db-fetchmail],
                             [disable fetchmail parser (~/.fetchmailrc support)]),
              [],
              [enable_db_fetchmail=yes]
)
AC_ARG_ENABLE([db-sendooway],
              AS_HELP_STRING([--disable-db-sendooway],
                             [disable default parser (~/.sendoowayrc support)]),
              [],
              [enable_db_sendooway=yes]
)

AC_ARG_WITH([ldap],
            AS_HELP_STRING([--without-ldap],
                           [disable LDAP support]),
)
AC_ARG_WITH([pam],
            AS_HELP_STRING([--without-pam],
                           [disable PAM support]),
)
AC_ARG_WITH([gnutls],
            AS_HELP_STRING([--without-gnutls],
                           [disable GnuTLS (no SSL support)]),
)

AS_IF([test "x$enable_db_getmail" != "xyes"],   [],
      [AC_DEFINE([USE_DB_GETMAIL], [1], [Define to 1 if you want .getmailrc support])]
)
AS_IF([test "x$enable_db_fetchmail" != "xyes"], [],
      [AC_DEFINE([USE_DB_FETCHMAIL], [1], [Define to 1 if you want .fetchmailrc support])]
)
AS_IF([test "x$enable_db_sendooway" != "xyes"], [],
      [AC_DEFINE([USE_DB_SENDOOWAY], [1], [Define to 1 if you want direct-mapping support])]
)

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AS_IF([test "x$with_gnutls" = "xno"], [],
      [PKG_CHECK_MODULES([GNUTLS], [gnutls])
      AC_DEFINE([HAVE_GNUTLS], [1], [Define to 1 if you have the 'gnutls' library])]
)

AS_IF([test "x$with_pam" = "xno"], [],
      [AC_CHECK_LIB([pam], [pam_start],, AC_MSG_ERROR([libpam missing?]))]
)

AS_IF([test "x$with_ldap" = "xno"], [],
      [AC_CHECK_LIB([ldap], [ldap_initialize],, AC_MSG_ERROR([libldap missing?]))]
)

# Checks for header files.
AC_CHECK_HEADERS([netinet/in.h arpa/inet.h netdb.h stdlib.h string.h unistd.h syslog.h])

# Checks for typedefs, structures, and compiler characteristics.
AC_HEADER_STDBOOL
AC_C_INLINE
AC_TYPE_UID_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([gethostname memset socket strcasecmp strchr strdup select])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 test/Makefile])
AC_OUTPUT
