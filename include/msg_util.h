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

#ifndef MSG_UTIL_H
#define MSG_UTIL_H

#define MSG_BIT_SET |=
#define MSG_BIT_CLEAR &=~
#define MSG_BIT_TOGGLE ^=
#define MSG_BIT_CHECK &
#define MSG_BIT_OP(op, n, a) ((a)op(1<<n))

const char *msg_util_file_name(const char *file);

#endif
