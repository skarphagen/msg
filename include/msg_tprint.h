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

#ifndef MSG_TPRINT_H
#define MSG_TPRINT_H

#include <stdio.h>
#include <stdarg.h>

struct msg_tprint;

void msg_tprint_init(struct msg_tprint **tprint, char columnsep);

__attribute__((format(printf, 2, 3)))
void msg_tprint_row(struct msg_tprint *tprint, const char *fmt, ...);

__attribute__((format(printf, 2, 3)))
void msg_tprint_str(struct msg_tprint *tprint, const char *fmt, ...);

void msg_tprint_sep(struct msg_tprint *tprint, char rowsep, char columnsep);

void msg_tprint_do(struct msg_tprint *tprint, FILE *stream);

void msg_tprint_cb(struct msg_tprint *tprint,
               void (*func)(void *user, const char *format, va_list ap),
               void *user);

void msg_tprint_exit(struct msg_tprint *tprint);

#endif
