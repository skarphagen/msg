/**
 *   Copyright (C) 2020 Skarphagen Embedded
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of thee License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <msg_post_office_cmd.h>
#include <msg_cmd_disp.h>
#include <pthread.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int cmd_version_info(int argc, char **argv);
static int cmd_domain_create(int argc, char **argv);
static int cmd_domain_delete(int argc, char **argv);
static int cmd_postbox_info(int argc, char **argv);
static int cmd_domain_info(int argc, char **argv);
static int cmd_hunt_info(int argc, char **argv);
static int cmd_monitor(int argc, char **argv);
static int cmd_unknown(int argc, char **argv);

static struct cmd_disp cmds[] = {
	CMD_DISP(cmd_version_info, "-v,--version", "Version info"),
	CMD_DISP(cmd_domain_create, "-c,--create", "Create a domain"),
	CMD_DISP(cmd_domain_delete, "-d,--delete", "Delete a domain"),
	CMD_DISP(cmd_postbox_info, "-s,--status", "Postbox info"),
	CMD_DISP(cmd_domain_info, "-i,--info", "Domain info"),
	CMD_DISP(cmd_hunt_info, "-h,--hunt", "List unresolved hunt"),
	CMD_DISP(cmd_monitor, "-m,--monitor", "Command monitor"),
	CMD_DISP_END(cmd_unknown)
};

struct args {
	int argc;
	char **argv;
};

static int cmd_unknown(int argc, char **argv)
{
	(void)argc;
	printf("unknown command: %s\n", argv[0]);
	return 1;
}

static int cmd_postbox_info(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}
	post_office_cmd_postbox_info(argv[1]);
	return 2;
}

static int cmd_domain_info(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}
	post_office_cmd_domain_info(argv[1]);
	return 2;
}

static int cmd_domain_create(int argc, char **argv)
{
	uint32_t addresses;
	uint32_t size;
	char *name;

	if (argc < 3) {
		printf("usage: %s <size> <addresses> [name]\n", argv[0]);
		return 0;
	}
	size = atol(argv[1]);
	addresses = atol(argv[2]);
	name = (argc > 3) ? argv[3] : NULL;
	post_office_cmd_domain_create(name, size, addresses);
	return argc > 3 ? 4 : 3;
}

static int cmd_domain_delete(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}
	post_office_cmd_domain_delete(argv[1]);
	return 2;
}

static int cmd_version_info(int argc, char **argv)
{
	(void)argc;
	(void)argv;
	printf("%s version %s\n", PACKAGE_NAME, PACKAGE_VERSION);
	printf("%s %s\n", __DATE__, __TIME__);
	return 1;
}

static int cmd_hunt_info(int argc, char **argv)
{
	if (argc < 2) {
		printf("usage: %s <name>\n", argv[0]);
		return 0;
	}
	post_office_cmd_unresolved_hunt_info(argv[1]);
	return 2;
}

static int cmd_monitor(int argc, char **argv)
{
	static int monitor = 0;
	size_t maxsize = 0;
	int i;

	if (monitor)
		return 1;
	monitor = 1;
	/* count them all */
	while (argv[argc++]);
	if (argc < 3) {
		printf("usage: %s <options...>\n", argv[0]);
		return 0;
	}
	argv--;
	for (i = 0; i < argc; i++) {
		size_t size = strlen(argv[i]) + 1;
		if (size > maxsize)
			maxsize = size;
	}
	char buf[argc][maxsize];
	char *copy[argc + 1];
	for (i = 0; i < argc; i++) {
		copy[i] = &buf[i][0];
	}
	copy[argc] = NULL;
	for (;;) {
		for (i = 0; i < argc; i++) {
			strcpy(&buf[i][0], argv[i]);
		}
		printf("\033c");
		cmd_dispatch(argc, copy, cmds);
		fflush(stdout);
		usleep(100000); /* 100 msec */
	}
	return 0;
}

static void *dispatch(void *arg)
{
	struct args *args = arg;
	cmd_dispatch(args->argc, args->argv, cmds);
	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	struct args args = {.argc = argc, .argv = argv};
	pthread_t tid;
	sigset_t set;

	(void)sigfillset(&set);
	(void)pthread_sigmask(SIG_BLOCK, &set, NULL);
	(void)pthread_create(&tid, NULL, dispatch, &args);
	(void)sigwaitinfo(&set, NULL);
	(void)pthread_cancel(tid);
	(void)pthread_join(tid, NULL);
	exit(EXIT_SUCCESS);
}
