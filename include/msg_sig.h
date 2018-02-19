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

#ifndef MSG_SIG_H
#define MSG_SIG_H

#include <signal.h>
#include <time.h>

#define SIGMSGEVENT SIGRTMAX
#define SIGMSGTMO  (SIGRTMAX - 1)

void sig_block(void);

void sig_queue(int sig);

int sig_wait(void **reference);

int sig_timer_create(void *reference, long msec, long interval_msec,
		     int signo, timer_t *timerid);

void sig_timer_delete(timer_t timerid);

#endif
