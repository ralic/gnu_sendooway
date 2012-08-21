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
#ifndef _SENDOOWAY_UTIL_H__
#define _SENDOOWAY_UTIL_H__

#include "config.h"
#include "md5.h"
#include <stdio.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include <syslog.h>

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX (64)
#endif

#define sizeofMember(type, member) sizeof(((type *)0)->member)

/**
 * @brief Safely return greater value of arbitrary types
 *
 * @param A    : first expression to evaluate
 * @param B    : second expression to evaluate
 * @param TYPE : return type of A and B
 *
 * @return greater return value of both
 */
#define util_max(A, B, TYPE)    \
	({ TYPE a_ = (A);             \
	TYPE b_ = (B);                \
	(a_ > b_) ? a_ : b_; })

/**
 * @brief Sets the destination for logging messages
 *
 * @param *name : NULL for syslog, "&1" for stdout, "&2" for stderr
 *                or a filename
 *
 * @return nothing
 */
void util_setLogger(char *name);

/**
 * @brief Logs a formatted string
 *
 * @param level : urgency of message (see syslog.h)
 * @param *fmt  : format string
 * @param ...   : zero or more arguments
 *
 * @return nothing
 */
void util_logger(int level, char *fmt, ...);

/**
 * @brief Wrapper around read() with timeout
 *
 * @param fd     : file descriptor
 * @param *buf   : points to buffer
 * @param buflen : size of buffer
 *
 * @return return value of read() or zero on timeout
 */
ssize_t util_readTimeout(int fd, char *buf, size_t buflen);

/**
 * @brief Save variant of strcpy that ensures null-termination
 *
 * @param *dst : points to destination buffer
 * @param *src : points to source string
 * @param size : size of the destination buffer
 *
 * @return nothing, but aborts if size is zero
 */
static inline void util_strcpy(char *dst, char *src, size_t size) {
	if (!size) abort();
	strncpy(dst, src, size);
	dst[size - 1] = '\0';
}

/**
 * @brief Overwrite string, free it and null pointer
 *
 * @param **str : points to string pointer
 * @param erase : override memory before freeing
 *
 * @return nothing
 */
void util_strfree(char **str, bool erase);

/**
 * @brief Check if a string is part of another one
 *
 * @param *str   : points to the string to check
 * @param *start : points to the needle
 *
 * @return true, if *str starts with *start (case insensitive)
 */
bool util_strstart(const char *str, const char *start);

/**
 * @brief Replace tokens inside string by replacements
 *
 * @param *string        : points to input string
 * @param *tokens        : points to null-terminated array of tokens
 * @param **replacements : points to array of replacement strings
 *
 * @return Newly allocated string (free() it!) or NULL on failure
 */
char* util_strreplace(char *string, const char *tokens,
  const char **replacements);

/**
 * @brief Parse string upto next delimiter and terminate it
 *
 * @param **longstr : points to input string pointer
 * @param *delims   : null-terminated array of delimiters
 *
 * @return matched delimiter
 */
char util_strparse(char **longstr, const char *delims);

/** @deprecated Use util_strparse() instead (slower, but more robust) */
bool util_strstep(char** longstr, char* next, int maxlen, char delim);

#define URL_READ_GARBAGE (1)
#define URL_LINE_TOOLONG (2)
#define URL_ZERO_READ    (4)
int util_readline(ssize_t(*reader)(void*, char*,
  size_t), void* p, char* line, size_t *size);

/** @deprecated */
int util_readline_DEPR(ssize_t(*reader)(void*, char*, size_t),
  void* p, char* line, int maxlen);

#define UTIL_BASE64LEN(input) (4 * ((input + 2) / 3))
#define UTIL_BASE64SIZE(input) (UTIL_BASE64LEN(input) + 1)
void util_base64encode(void* input_b, int size, char* output);
size_t util_base64decode(char* input, size_t size, char* output);

/* See util.c for an explanation why the following wrappers are used */
#define UTIL_MD5LEN(...) (16)
#define util_md5state md5_state_t
#define util_md5init(state) md5_init(state)
#define util_md5append(state, str, size) \
  md5_append(state, (md5_byte_t*) str, size)
#define util_md5finish(state, output) \
  md5_finish(state, (md5_byte_t*) output)
void util_md5str(void* input_b, int size, char* output);

#endif
