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

#include <msg_time.h>
#include <unistd.h>

#define MSEC_PER_SEC 1000L
#define USEC_PER_SEC 1000000L
#define NSEC_PER_SEC 1000000000L

void time_diff(const struct timespec *start, const struct timespec *stop,
               struct timespec *diff)
{
        long nsec = stop->tv_nsec - start->tv_nsec;
        long sec = stop->tv_sec - start->tv_sec;

        if (nsec < 0) {
                sec -= 1;
                nsec = NSEC_PER_SEC + nsec;
        }
        diff->tv_sec = sec;
        diff->tv_nsec = nsec;
}

void time_get(struct timespec *ts)
{
        clock_gettime(CLOCK_REALTIME, ts);
}

void time_set_tmo(struct timespec *start, struct timespec *tmo, uint32_t msec)
{
        tmo->tv_sec = start->tv_sec + msec / MSEC_PER_SEC;
        tmo->tv_nsec = start->tv_nsec + (msec % MSEC_PER_SEC) * USEC_PER_SEC;
        if (tmo->tv_nsec >= NSEC_PER_SEC) {
                tmo->tv_sec += 1;
                tmo->tv_nsec -= NSEC_PER_SEC;
        }
}

int time_create_tmo(struct timespec *tmo, uint32_t msec)
{
        struct timespec start;

        if (!msec)
                return -1;
        time_get(&start);
        time_set_tmo(&start, tmo, msec);
        return 0;
}

void time_delay(uint32_t msec)
{
        unsigned int usec;
        unsigned int sec;

        sec = msec / MSEC_PER_SEC;
        usec = (msec % MSEC_PER_SEC) * MSEC_PER_SEC;
        if (usec >= USEC_PER_SEC) {
                sec += 1;
                usec -= USEC_PER_SEC;
        }
        if (sec)
                sleep(sec);
        if (usec)
                usleep(usec);
}
