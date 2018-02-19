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

#ifndef MSG_TIME_H
#define MSG_TIME_H

#include <stdint.h>
#include <time.h>

void time_diff(const struct timespec *start, const struct timespec *stop,
               struct timespec *diff);

void time_get(struct timespec *ts);

int time_create_tmo(struct timespec *tmo, uint32_t msec);

void time_set_tmo(struct timespec *start, struct timespec *tmo, uint32_t msec);

void time_delay(uint32_t msec);

#endif
