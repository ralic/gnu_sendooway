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
#include "config.h"
#include "options.h"
#include "util.h"
#include "md5.h"
#include <sys/select.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>

FILE * util_fLogger = 0;

void util_setLogger(char *name) {
	if ( (util_fLogger) &&
	  (util_fLogger != stdout) &&
	  (util_fLogger != stderr)) fclose(util_fLogger);

	if (!name) {
		/* Syslog */
		util_fLogger = 0;
	} else {
		/* Pipe */
		if (strcmp(name, "&1") == 0) util_fLogger = stdout;
		else if (strcmp(name, "&2") == 0) util_fLogger = stderr;
		/* File */
		else util_fLogger = fopen(name, "a");
	}
}

void util_logger(int level, char *fmt, ...) {
	va_list args;
	va_start(args, fmt);
	if (!util_fLogger) {
		/* Log to syslog */
		openlog("sendooway", LOG_PID, LOG_MAIL);
		vsyslog(LOG_MAKEPRI(LOG_MAIL, level), fmt, args);
		closelog();
	} else {
		/* Log to file */
		char buf[20];
		time_t t = time(NULL);
		struct tm *tmp = localtime(&t);
		if (!tmp) *buf = '\0';
		else strftime(buf, sizeof(buf), "%b %d %H:%M:%S", tmp);

		fprintf(util_fLogger, "%s <%u> ", buf, level);
		vfprintf(util_fLogger, fmt, args);
		fputc('\n', util_fLogger);
	}
	va_end(args);
}

ssize_t util_readTimeout(int fd, char *buf, size_t buflen) {
	fd_set fds;
	struct timeval tv = {.tv_sec = options.timeout, .tv_usec = 0};

	FD_ZERO(&fds);
	FD_SET(fd, &fds);
	if (select(fd + 1, &fds, NULL, NULL, &tv) <= 0) return 0;

	return read(fd, buf, buflen);
}

void util_strfree(char **str, bool erase) {
	char *p = *str;
	if (p) {
		if (erase) for (;*p;p++) *p = '\0';
		free(*str);
		*str = NULL;
	}
}

bool util_strstart(const char* str, const char* start) {
	int i = 0;
	while (str[i] && start[i]) {
		char c1 = str[i];
		char c2 = start[i];

		if (c1 >= 'a' && c1 <= 'z') c1 -= ('a' - 'A');
		if (c2 >= 'a' && c2 <= 'z') c2 -= ('a' - 'A');

		if (c1 != c2) return 0;
		i++;
	}
	return (start[i] == 0);
}

char* util_strreplace(char* string, const char* tokens,
  const char** replacements) {

	char *str = string;
	int newlen = strlen(str);

	/* Scan the string */
	do {
		str = strchr(str, '%');
		if (!str) break;

		char token = *++str;
		if (token == '\0') break; /* Malformed str */

		char *tokenP = strchr(tokens, token);
		if (!tokenP) continue;   /* Unknown token */

		int index = (tokenP - tokens);
		newlen = newlen - 2 + strlen(replacements[index]);
	} while (1);

	/* Copy the string */
	char *retval = malloc(newlen + 1);
	if (retval) {
		char *newstr = retval;
		while (*string) {
			if (*string == '%') {
				char *tokenP = strchr(tokens, *++string);
				if (tokenP) {
					int index = (tokenP - tokens);
					int len = strlen(replacements[index]);
					memcpy(newstr, replacements[index], len);
					newstr += len;

					string++;
					continue;
				} else *newstr++ = '%';
			}

			*newstr++ = *string++;
		}
		*newstr = '\0';
	}
	return retval;
}

char util_strparse(char **longstr, const char *delims) {
	while (**longstr && !strchr(delims, **longstr)) *longstr += 1;

	char retval = **longstr;
	if (retval) {
		**longstr = '\0';
		*longstr += 1;
	}
	return retval;
}

int util_readline(ssize_t(*reader)(void*, char*, size_t), void* p,
  char* line, size_t *size) {

	size_t pos = 0;
	size_t max = (*size) - sizeof(char);
	int retval = 0;

	while (pos < max) {
		if (!reader(p, &line[pos], 1)) {
			line[pos] = '\0';
			*size = pos;
			return (retval | URL_ZERO_READ);
		}

		if (line[pos] < 32 || line[pos] > 126) switch (line[pos]) {
			case '\n':
				/* Remove, CR (if any) */
				if (pos && (line[pos-1] == '\r')) pos--;

				/* Return */
				line[pos] = '\0';
				*size = pos;
				return retval;

			case '\r':
				/** @todo CR can also be garbage on missing LF */
				break;

			default:
				retval |= URL_READ_GARBAGE;
		}

		pos++;
	}

	/* Line too long */
	line[pos] = '\0';
	*size = pos;
	return (retval | URL_LINE_TOOLONG);
}

int util_readline_DEPR(ssize_t(*reader)(void*, char*, size_t),
  void* p, char* line, int maxlen) {

	int rem = maxlen;

	while (rem > 0) {
		if (!reader(p, line, 1)) return (-1); // return (maxlen - rem);

		switch (line[0]) {
			case '\n': /* Newline -> done*/
				line[0] = '\0';
				return maxlen - rem;

			case '\0': /* Binary zero -> ignore */
			case '\r': /* Carriage return -> ignore */
				break;

			case '\b': /* Backstep -> step back or ignore */
				if (rem < maxlen) {
					line--;
					rem++;
				}
				break;

			default:
				line++;
				rem--;
				break;
		}
	}

	/* Error */
	return 0;
}

/* GnuTLS offers base64 functionality but "base64_encode" and
 * "base64_decode" are not part of the shared library. Unfortunately
 * "gnutls_pem_base64_encode" and "gnutls_pem_base64_decode" are not
 * useful - so I'm gonna write my own very simple coder.
 *
 * If you know how to use GnuTLS' functionality, please feel free to
 * replace the following two functions.
 */
static const char* util_base64table =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"abcdefghijklmnopqrstuvwxyz"
	"0123456789+/"
;

void util_base64encode(void* input_b, int size, char* output) {
	/* output always needs "size*round_down((size+2)/3) + 1" bytes */
	char* input = input_b;
	while (size >= 3) {
		output[0] = util_base64table[ (input[0] & 0xFC) >> 2 ];
		output[1] = util_base64table[((input[0] & 0x03) << 4) |
		                              (input[1] & 0xF8) >> 4 ];
		output[2] = util_base64table[((input[1] & 0x0F) << 2) |
		                              (input[2] & 0xC0) >> 6 ];
		output[3] = util_base64table[ (input[2] & 0x3F)      ];

		output += 4;
		input  += 3;
		size   -= 3;
	}

	if (size > 0) {
		output[0] = util_base64table[  (input[0] & 0xFC) >> 2 ];
		if (size == 1) {
			output[1] = util_base64table[(input[0] & 0x03) << 4 ];
			output[2] = '=';
		} else {
			output[1] = util_base64table[((input[0] & 0x03) << 4) |
			                              (input[1] & 0xF8) >> 4 ];
			output[2] = util_base64table[((input[1] & 0x0F) << 2) ];
		}
		output[3] = '=';
		output += 4;
	}

	*output = '\0';
}

size_t util_base64decode(char* input, size_t size, char* output) {
	size_t len = 0;
	size_t opos = 0;

	if (!output) output = input; /* Decode in place */

	while (size >= 4) {
		int i;
		int quartet[4];

		len += 3;
		for (i=0;i<4;i++) {
			if (input[i] == '=') {
				quartet[i] = 0;
				if (--len <= 0) goto out; /* Attack? */
			} else {
				char *p = strchr(util_base64table, input[i]);
				if (!p) goto out; /* Error */
				quartet[i] = (p - util_base64table);
			}
		}

		output[opos + 0] = (quartet[0] << 2) | (quartet[1] >> 4);
		output[opos + 1] = (quartet[1] << 4) | (quartet[2] >> 2);
		output[opos + 2] = (quartet[2] << 6) | (quartet[3] >> 0);

		opos   += 3;
		input  += 4;
		size   -= 4;
	}

out:
	if (size) {
		/* Error */
		output[0] = '\0';
		return 0;
	}
	output[opos] = '\0';

	return len;
}

/* Again, GnuTLS offers a MD5 function but I won't use it as long as
 * Debian stable (at the moment: squeeze) comes only with GnuTLS 2.6
 */
void util_md5str(void* input_b, int size, char* output) {
	md5_state_t state;

	md5_init(&state);
	md5_append(&state, input_b, size);
	md5_finish(&state, (md5_byte_t*) output);
}
