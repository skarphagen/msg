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

#ifndef MSG_POST_OFFICE_ALIAS_H
#define MSG_POST_OFFICE_ALIAS_H

#include <stdint.h>

int post_office_alias(const char *name, uint64_t pid,
		      uint64_t bid, uint32_t atmo);

uint64_t post_office_alias_pid(const char *name, uint64_t bid);

void post_office_alias_clear(uint64_t pid);

#endif
