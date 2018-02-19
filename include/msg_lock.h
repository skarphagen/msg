/**
 *   Copyright (C) 2019 Skarphagen Embedded
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
#ifndef MSG_LOCK_H
#define MSG_LOCK_H

#include <pthread.h>
#include <time.h>

struct msg_lock {
        pthread_mutex_t mutex;
        pthread_cond_t cond;
};

#define LOCK_MUTEX_PUSH(mutex)  \
        do {                    \
        lock_mutex_push(mutex); \
        pthread_cleanup_push(lock_mutex_pop, mutex)
#define LOCK_MUTEX_POP()        \
        pthread_cleanup_pop(1); \
        } while (0)

#define LOCK_PUSH(lock)    \
        do {               \
        lock_push(lock);   \
        pthread_cleanup_push(lock_pop, lock)
#define LOCK_POP()              \
        pthread_cleanup_pop(1); \
        } while (0)

void lock_init(struct msg_lock *lock);

void lock_push(void *arg);

void lock_pop(void *arg);

void lock_lock(struct msg_lock *lock);

void lock_unlock(struct msg_lock *lock);

void lock_wait(struct msg_lock *lock);

void lock_signal(struct msg_lock *lock);

void lock_broadcast(struct msg_lock *lock);

int lock_timedwait(struct msg_lock *lock, struct timespec *ts);

void lock_mutex_init(pthread_mutex_t *mutex);

void lock_mutex_lock(pthread_mutex_t *mutex);

void lock_mutex_unlock(pthread_mutex_t *mutex);

void lock_mutex_push(void *arg);

void lock_mutex_pop(void *arg);

#endif
