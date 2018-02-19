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

#include <msg_post_office_attach.h>
#include <msg_post_office.h>
#include <msg_lock.h>
#include <msg_heap.h>
#include <string.h>
#include <stdlib.h>

struct attach {
        struct msgh *msgh;
};

struct msgh *post_office_attach(struct msgh *msgh, uint32_t atmo)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->attach;
        struct msg_heap *heap = post_office->heap;
        struct attach *attach;

        attach = msg_heap_alloc(heap, atmo, sizeof(*attach), NULL);
        if (attach) {
                attach->msgh = msgh;
                lock_mutex_lock(&post_office->lock_attach);
                msg_heap_append(heap, queue, attach);
                lock_mutex_unlock(&post_office->lock_attach);
                return NULL;
        } else {
                return msgh;
        }
}

void post_office_attach_resolve(uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->attach;
        struct msg_heap *heap = post_office->heap;
        struct attach *attach, *next;
        struct msgh *msgh;

        lock_mutex_lock(&post_office->lock_attach);
        msg_heap_foreach_safe(heap, queue, attach, next) {
                msgh = attach->msgh;
                if (msgh->sender == pid) {
                        attach = msg_heap_linkout(heap, queue, attach);
                        msg_heap_free(heap, attach);
                        post_office_send(msgh, msgh->addressee, __FILE__,
					 __LINE__);
                }
        }
        lock_mutex_unlock(&post_office->lock_attach);
}

struct msgh *post_office_attach_cancel(uint64_t reference, uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->attach;
        struct msg_heap *heap = post_office->heap;
        struct msgh *msgh = NULL;
        struct attach *attach;

        lock_mutex_lock(&post_office->lock_attach);
        msg_heap_foreach(heap, queue, attach) {
                if (attach->msgh->reference == reference)
                        break;
        }
	/* addressee is the owner of the attach */
	if (attach && (attach->msgh->addressee == pid)) {
		msgh = attach->msgh;
                attach = msg_heap_linkout(heap, queue, attach);
                msg_heap_free(heap, attach);
        }
        lock_mutex_unlock(&post_office->lock_attach);
        return msgh;
}

void post_office_attach_clear(uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->attach;
        struct msg_heap *heap = post_office->heap;
        struct attach *attach, *next;
        struct msgh *msgh;

        lock_mutex_lock(&post_office->lock_attach);
        msg_heap_foreach_safe(heap, queue, attach, next) {
                msgh = attach->msgh;
		/* addressee is the owner of the attach */
                if (msgh->addressee == pid) {
                        msg_heap_free(heap, msgh);
                        attach = msg_heap_linkout(heap, queue, attach);
                        msg_heap_free(heap, attach);
                }
        }
        lock_mutex_unlock(&post_office->lock_attach);
}
