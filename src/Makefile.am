# Sendooway - a multi-user and multi-target SMTP proxy
#  Copyright (C) 2012 Michael Kammer
#  Published under the GNU GPL version 3 (or later)
#

bin_PROGRAMS = sendooway
sendooway_SOURCES = auth.c auth.h \
	client.c client.h \
	glue.c glue.h \
	md5.c md5.h \
	options.c options.h \
	proxy.c proxy.h \
	sendooway.c sendooway.h \
	server.c server.h \
	smtp.c smtp.h \
	util.c util.h

sendooway_LDADD = $(GNUTLS_LIBS)
AM_CPPFLAGS = $(GNUTLS_CFLAGS) -DSYSCONFDIR='"$(sysconfdir)"'