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
 *   along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <msg_post_office_tmo.h>
#include <msg_post_office.h>
#include <msg_lock.h>
#include <msg_error.h>
#include <msg_heap.h>
#include <msg_sig.h>
#include <string.h>
#include <stdlib.h>
#include <syslog.h>
#include <errno.h>

struct tmo {
        struct msgh *msgh;
        timer_t timerid;
} __attribute__((packed));

struct msgh *post_office_tmo(struct msgh *msgh, timer_t timerid,
			     uint32_t alloc_tmo)
{
        struct post_office *post_office = post_office_get();
        struct tmo *tmo;

        tmo = msg_heap_alloc(post_office->heap, alloc_tmo, sizeof(*tmo), NULL);
        if (!tmo)
                return msgh;
        tmo->msgh = msgh;
        tmo->timerid = timerid;
        lock_mutex_lock(&post_office->lock_tmo);
        msg_heap_append(post_office->heap, &post_office->tmo, tmo);
        lock_mutex_unlock(&post_office->lock_tmo);
        return NULL;
}

struct msgh *post_office_tmo_cancel(uint64_t reference, uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->tmo;
        struct msg_heap *heap = post_office->heap;
        struct msgh *msgh = NULL;
        struct tmo *tmo;

        lock_mutex_lock(&post_office->lock_tmo);
        msg_heap_foreach(heap, queue, tmo) {
                if (tmo->msgh->reference == reference)
                        break;
        }
	/* addressee is the owner of the time out */
        if (tmo && (tmo->msgh->addressee == pid)) {
		msgh = tmo->msgh;
		tmo = msg_heap_linkout(heap, queue, tmo);
		sig_timer_delete(tmo->timerid);
		msg_heap_free(heap, tmo);
        }
        lock_mutex_unlock(&post_office->lock_tmo);
        return msgh;
}

void post_office_tmo_expired(void *reference, uint32_t alloc_tmo)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->tmo;
        struct msg_heap *heap = post_office->heap;
        struct msgh *msgh = reference;
        struct itimerspec curr_value;
        struct tmo *tmo;

        lock_mutex_lock(&post_office->lock_tmo);
        msg_heap_foreach(heap, queue, tmo) {
                if (msgh == tmo->msgh)
                        break;
        }
        if (!tmo)
                goto unlock; /* Timer was cancelled, pending signal */
        if (timer_gettime(tmo->timerid, &curr_value) == -1) {
                error_sig("gettime: %s", strerror(errno));
                goto unlock;
        }
        if (!curr_value.it_interval.tv_sec &&
            !curr_value.it_interval.tv_nsec) {
                tmo = msg_heap_linkout(heap, queue, tmo);
                msg_heap_free(post_office->heap, tmo);
                post_office_send(msgh, msgh->addressee, __FILE__, __LINE__);
                goto unlock;
        }
        struct msgh *copy = msgh_copy(heap, alloc_tmo, msgh);
        if (copy)
		post_office_send(copy, copy->addressee, __FILE__, __LINE__);
        else
                error_sig("%s:%d, heap exhausted", __FILE__, __LINE__);
unlock:
        lock_mutex_unlock(&post_office->lock_tmo);
}

void post_office_tmo_clear(uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->tmo;
        struct msg_heap *heap = post_office->heap;
        struct tmo *tmo, *next;
        struct msgh *msgh;

        lock_mutex_lock(&post_office->lock_tmo);
        msg_heap_foreach_safe(heap, queue, tmo, next) {
                msgh = tmo->msgh;
                if (msgh->addressee == pid) {
                        msg_heap_free(heap, msgh);
                        timer_delete(tmo->timerid);
                        tmo = msg_heap_linkout(heap, queue, tmo);
                        msg_heap_free(heap, tmo);
                }
        }
        lock_mutex_unlock(&post_office->lock_tmo);
}
