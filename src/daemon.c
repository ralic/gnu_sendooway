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
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <sys/signal.h>
#include <sys/wait.h>
#include "util.h"
#include "daemon.h"

static void daemon_sigChldHandler(int signal) {
	if (signal != SIGCHLD) return;

	int status;
	waitpid(-1, &status, WNOHANG);
}

static bool daemon_accept(int socket) {
	/* This seems to be the best way to prevent zombie processes */
	signal(SIGCHLD, daemon_sigChldHandler);

	util_logger(LOG_INFO, "Accepting connections");
	int client;
	while ((client = accept(socket, NULL, NULL)) >= 0) {
		pid_t pid = fork();
		if (pid == -1) {
			/* Error */
			util_logger(LOG_CRIT, "Unable to fork client process");
			close(client);
		} else if (pid == 0) {
			/* Forked process */
			close(socket);

			dup2(client, STDIN_FILENO);
			close(client);
			dup2(STDIN_FILENO, STDOUT_FILENO);
			dup2(STDIN_FILENO, STDERR_FILENO);

			return true;
		} else {
			/* Parent process */
			util_logger(LOG_INFO, "Forked client process with pid %i", pid);
			close(client);
		}
	}

	close(socket);
	return false;
}

bool daemon_bind(char *bindPort) {
	struct servent *serv = getservbyname(bindPort, "tcp");
	if (!serv) {
		int p = atoi(bindPort);
		if (p > 0 && p < 65535) serv = getservbyport(htons(p), "tcp");
	}

	if (serv) {
		int s;
		struct sockaddr_in addr;

		memset(&addr, sizeof(addr), 0);
		addr.sin_family = AF_INET;
		addr.sin_addr.s_addr = INADDR_ANY;
		addr.sin_port = serv->s_port;

		if ((s = socket(AF_INET, SOCK_STREAM, 0)) >= 0) {
			int one = 1;
			setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(int));
			if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) == 0) {
				if (listen(s, 5) == 0) {
					return daemon_accept(s);
				} else util_logger(LOG_CRIT, "Unable to listen on socket");
			} else util_logger(LOG_CRIT, "Unable to bind socket");
			close(s);
		} else util_logger(LOG_CRIT, "Unable to create socket");
	} else util_logger(LOG_CRIT, "Unknown port name: %s", bindPort);

	return false;
}
