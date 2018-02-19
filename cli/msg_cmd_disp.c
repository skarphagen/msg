/**
 *   Copyright (C) 2020 Skarphagen Embedded
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
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
#include <msg_cmd_disp.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>

/* Short option -a, -ab... */
#define SHORT_OPTION(argv, i)			\
        (argv[(i)][0] == '-' &&			\
         argv[(i)][1] &&			\
         argv[(i)][1] != '-')

/* Long option --a */
#define LONG_OPTION(argv, i)			\
        (argv[(i)][0] == '-' &&			\
         argv[(i)][1] &&			\
         argv[(i)][1] == '-' &&			\
	 argv[(i)][2] &&			\
         argv[(i)][2] != '-')

/**
 *  MAX(len, string)
 *
 * @param len - lenght
 * @param fmt - format
 * @param ... - arguments according to fmt
 *
 * @return max lenght
 */
static int str_max(int len, const char *fmt, ...)
{
        va_list valist;
        int lenght;

        va_start(valist, fmt);
        lenght = vsnprintf(NULL, 0, fmt, valist);
        va_end(valist);
        return lenght > len ? lenght : len;
}

/**
 * Get function from CMD
 *
 * @param cmds - commnad table
 * @param argv - arguments
 * @return msg_cmd_func- command function pointer
 */
static cmd_func *get_cmd_func(const struct cmd_disp *cmds, const char *option)
{
        const char delim[] = ", ";
        char *cmd;
        int i;

        for (i = 0; cmds[i].name; i++) {
                size_t len = strlen(cmds[i].name) + 1;
                char name[len];
                memcpy(name, cmds[i].name, len);
                for (cmd = strtok(name, delim); cmd;
                     cmd = strtok(NULL, delim)) {
                        if (!strcmp(cmd, option))
                                return cmds[i].func;
                }
        }
        return NULL;
}

/**
 * Get the function from CMD_END
 *
 * @param cmds - command table
 * @return msg_cmd_func - command function
 */
static cmd_func *get_end_func(const struct cmd_disp *cmds)
{
        int i;

        for (i = 0; cmds[i].name; i++);
        return cmds[i].func;
}

/**
 * Get number of arguments for a command
 *
 * @param argc - number of arguments
 * @param argv - arguments
 * @param cmds - command table
 * @return Number of arguments for a command
 */
static int get_args(int argc, char **argv, const struct cmd_disp *cmds)
{
	cmd_func *func = NULL;
	int i;

	if (!SHORT_OPTION(argv, 0) && !LONG_OPTION(argv, 0))
		return argc; /* subcommand */
	/* Skip the current command and search for the next one */
        for (i = 1; i < argc; i++) {
                if (SHORT_OPTION(argv, i)) {
			char save = argv[i][2];
                        argv[i][2] = 0;
			func = get_cmd_func(cmds, argv[i]);
			argv[i][2] = save;
                }
		if (LONG_OPTION(argv, i))
			func = get_cmd_func(cmds, argv[i]);
		if (func)
			break;
        }
        return i; /* number of argc for the current command argv[0] */
}

/**
 * Print usage for commands
 *
 * @param name - command name
 * @param cmds - command table
 */
static void print_description(const char *name, const struct cmd_disp *cmds)
{
        int maxName = 0;
        int maxDescription = 0;
        const char indent[] = "   ";
        char format[64];
        int i;

        /* Find the max string lenght */
        for (i = 0; cmds[i].name; i++) {
                maxName = str_max(maxName, "%s", cmds[i].name);
                maxDescription = str_max(maxDescription, "%s",
                                         cmds[i].description);
        }
        snprintf(format, sizeof(format), "%s%%-%ds%s%%-%ds\n",
                 indent, maxName, indent, maxDescription);
        printf("usage: %s <command>\n", name);
        for (i = 0; cmds[i].name; i++) {
                printf(format, cmds[i].name, cmds[i].description ?
                       cmds[i].description : "");
        }
}

/**
 * Dispatch command
 *
 * @param argc[in] - number of arguments
 * @param argv[in] - arguments
 * @param cmds[in] - command table
 *
 * Note!   Command should return with the number of
 *         parsed arguments. If return 0 or less the command
 *         parsing will be aborted
 */
void cmd_dispatch(int argc, char **argv, const struct cmd_disp *cmds)
{
        cmd_func *func;
        int args, i;

        if (argc < 2) {
                print_description(argv[0], cmds);
                return;
        }

        argc--; argv++;
        while (argc > 0 && argv[0]) {
                char next = 0;
                /* Short options -a, -ab...*/
                if (SHORT_OPTION(argv, 0)) {
                        next = argv[0][2];
                        argv[0][2] = 0;
                }
                func = get_cmd_func(cmds, argv[0]);
                if (func) {
                        args = get_args(argc, argv, cmds);
                        args = func(args, argv);
                } else {
                        func = get_end_func(cmds);
                        if (!func) {
                                printf("unknown command '%s'\n", argv[0]);
                                return;
                        }
                        args = func(argc, argv);
                }
                if (args < 1)
                        return;
                if (next) {
                        /* put the next option after '-' and move the
                         * rest of options one step */
                        argv[0][1] = next;
                        for (i = 0; argv[0][3 + i]; i++)
                                argv[0][2 + i] = argv[0][3 + i];
                        argv[0][2 + i] = 0;
                } else {
                        argc = argc - args;
                        argv = argv + args;
                }
        }
}
