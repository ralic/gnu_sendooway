/**
 * This file is part of
 *   Sendooway - a multi-user and multi-target SMTP proxy
 *   Copyright (C) 2012-2014 Michael Kammer
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
#ifndef _SENDOOWAY_GLUE_H__
#define _SENDOOWAY_GLUE_H__

#include "config.h"
#include <stdbool.h>
#include "client.h"

bool glue_lookup(char* address, char *domain, client_data_t* cd);

#endif
