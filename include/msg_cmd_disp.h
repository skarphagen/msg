/**
 *   Copyright (C) 2021 Skarphagen Embedded
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

#ifndef MSG_CMD_DISP_H
#define MSG_CMD_DISP_H

#define CMD_DISP(func,name,description) {name,description,func}
#define CMD_DISP_END(func) {NULL,NULL,func}

/*
 * Function type for command handling.
 */
typedef int (cmd_func)(int argc, char **argv);

struct cmd_disp {
	const char *name;
	const char *description;
	cmd_func *func;
};

void cmd_dispatch(int argc, char **argv, const struct cmd_disp *cmds);

#endif
