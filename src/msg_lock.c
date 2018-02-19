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

#include <msg_lock.h>

void lock_init(struct msg_lock *lock)
{
        pthread_condattr_t condattr;

        lock_mutex_init(&lock->mutex);
        pthread_condattr_init(&condattr);
        pthread_condattr_setpshared(&condattr, PTHREAD_PROCESS_SHARED);
        pthread_cond_init(&lock->cond, &condattr);
}

void lock_push(void *arg)
{
        struct msg_lock *lock = arg;
	lock_lock(lock);
}

void lock_pop(void *arg)
{
        struct msg_lock *lock = arg;
        lock_unlock(lock);
}

void lock_lock(struct msg_lock *lock)
{
	lock_mutex_lock(&lock->mutex);
}

void lock_unlock(struct msg_lock *lock)
{
        lock_mutex_unlock(&lock->mutex);
}

void lock_wait(struct msg_lock *lock)
{
        pthread_cond_wait(&lock->cond, &lock->mutex);
}

void lock_signal(struct msg_lock *lock)
{
        pthread_cond_signal(&lock->cond);
}

void lock_broadcast(struct msg_lock *lock)
{
        pthread_cond_broadcast(&lock->cond);
}

int lock_timedwait(struct msg_lock *lock, struct timespec *ts)
{
        return pthread_cond_timedwait(&lock->cond, &lock->mutex, ts);
}

void lock_mutex_init(pthread_mutex_t *mutex)
{
        pthread_mutexattr_t mutexattr;

        pthread_mutexattr_init(&mutexattr);
        pthread_mutexattr_setpshared(&mutexattr, PTHREAD_PROCESS_SHARED);
        pthread_mutex_init(mutex, &mutexattr);
}

void lock_mutex_lock(pthread_mutex_t *mutex)
{
        pthread_mutex_lock(mutex);
}

void lock_mutex_unlock(pthread_mutex_t *mutex)
{
        pthread_mutex_unlock(mutex);
}

void lock_mutex_push(void *arg)
{
        pthread_mutex_t *mutex = arg;
        lock_mutex_lock(mutex);
}

void lock_mutex_pop(void *arg)
{
        pthread_mutex_t *mutex = arg;
        lock_mutex_unlock(mutex);
}
