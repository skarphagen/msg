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

#include <msg_thread.h>

int thread_create(void *(*start_routine)(void *), void *arg)
{
        pthread_t pthread;
        int res;

        res = pthread_create(&pthread, NULL, start_routine, arg);
        return res;
}

void thread_cleanup(void (*cleanup_routine)(void *), void *arg)
{
        pthread_key_t key;

        pthread_key_create(&key, cleanup_routine);
        pthread_setspecific(key, arg);
}
