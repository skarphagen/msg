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

#include <msg_post_office_hunt.h>
#include <msg_lock.h>
#include <msg_heap.h>
#include <msg_error.h>
#include <msgh.h>
#include <msg.h>
#include <string.h>

struct hunt {
        struct msgh *msgh;
        char name[1];
} __attribute__((packed));

static void send_msg_snoop_hunt(const struct post_office_snoop *snoop,
                                const struct hunt *hunt,
				uint32_t atmo)
{
        struct post_office *post_office = post_office_get();
	struct msg_heap *heap = post_office->heap;
        struct msg_snoop_unresolved_hunt *msg;
        struct msgh *msgh;
        size_t size, len;

        len = strlen(hunt->name);
	size = sizeof(*msg) + len;
        msgh = msgh_alloc(heap, atmo, size, MSG_SNOOP_UNRESOLVED_HUNT);
        if (!msgh) {
                error_sig("%s", "heap exhausted");
                return;
        }
        msgh->sender = hunt->msgh->addressee;
        msgh->addressee = snoop->pid;
        msg = MSG_PAYLOAD(msgh);
        memcpy(msg->name, hunt->name, len + 1);
        post_office_send(msgh, msgh->addressee, __FILE__, __LINE__);
}

struct msgh *post_office_hunt(struct msgh *msgh, const char *name,
			      uint32_t atmo)
{
        struct post_office *post_office = post_office_get();
	struct msg_heap *heap = post_office->heap;
        struct post_office_snoop *snoop;
        struct hunt *hunt;
        uint8_t event;
        size_t len;

        len = strlen(name);
        hunt = msg_heap_alloc(heap, atmo, sizeof(*hunt) + len, NULL);
        if (!hunt)
                return msgh;
        hunt->msgh = msgh;
        memcpy(hunt->name, name, len + 1);
        lock_mutex_lock(&post_office->lock_hunt);
        lock_mutex_lock(&post_office->lock_snoop);
        msg_heap_append(heap, &post_office->hunt, hunt);
        msg_heap_foreach(heap, &post_office->snoop, snoop) {
                event = POST_OFFICE_SNOOP_UNRESOLVED_HUNT;
                if (POST_OFFICE_SNOOP_EVENT(event, snoop->event))
                        send_msg_snoop_hunt(snoop, hunt, atmo);
        }
        lock_mutex_unlock(&post_office->lock_snoop);
        lock_mutex_unlock(&post_office->lock_hunt);
        return NULL;
}

void post_office_hunt_resolve(uint64_t pid, const char *name)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->hunt;
        struct msg_heap *heap = post_office->heap;
        struct hunt *hunt, *next;
        struct msgh *msgh;

        lock_mutex_lock(&post_office->lock_hunt);
        msg_heap_foreach_safe(heap, queue, hunt, next) {
                if (!strcmp(hunt->name, name)) {
                        msgh = hunt->msgh;
                        msgh->sender = pid;
                        hunt = msg_heap_linkout(heap, queue, hunt);
                        msg_heap_free(heap, hunt);
                        post_office_send(msgh, msgh->addressee,
					 __FILE__, __LINE__);
                }
        }
        lock_mutex_unlock(&post_office->lock_hunt);
}

struct msgh *post_office_hunt_cancel(uint64_t reference, uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->hunt;
        struct msg_heap *heap = post_office->heap;
        struct msgh *msgh = NULL;
        struct hunt *hunt;

        lock_mutex_lock(&post_office->lock_hunt);
        msg_heap_foreach(heap, queue, hunt) {
                if (hunt->msgh->reference == reference)
                        break;
        }
        if (hunt && (hunt->msgh->addressee == pid)) {
		msgh = hunt->msgh;
		hunt = msg_heap_linkout(heap, queue, hunt);
		msg_heap_free(heap, hunt);
        }
        lock_mutex_unlock(&post_office->lock_hunt);
        return msgh;
}

void post_office_hunt_clear(uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->hunt;
        struct msg_heap *heap = post_office->heap;
        struct hunt *hunt, *next;

        lock_mutex_lock(&post_office->lock_hunt);
        msg_heap_foreach_safe(heap, queue, hunt, next) {
                if (hunt->msgh->addressee == pid) {
                        msg_heap_free(heap, hunt->msgh);
                        hunt = msg_heap_linkout(heap, queue, hunt);
                        msg_heap_free(heap, hunt);
                }
        }
        lock_mutex_unlock(&post_office->lock_hunt);
}

void post_office_hunt_foreach(post_office_hunt_func *func, void *user)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->hunt;
        struct msg_heap *heap = post_office->heap;
        struct post_office_hunt_info info;
        struct hunt *hunt;

        LOCK_MUTEX_PUSH(&post_office->lock_hunt);
        msg_heap_foreach(heap, queue, hunt) {
                info.msgh = hunt->msgh;
                info.name = hunt->name;
                if (func(&info, user))
                        break;
        }
        LOCK_MUTEX_POP();
}

void post_office_hunt_snoop(uint64_t pid, uint32_t atmo)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->hunt;
        struct msg_heap *heap = post_office->heap;
        struct post_office_snoop *snoop;
        struct hunt *hunt;

        lock_mutex_lock(&post_office->lock_hunt);
        lock_mutex_lock(&post_office->lock_snoop);
        msg_heap_foreach(heap, queue, snoop) {
                if (snoop->pid == pid)
                        break;
        }
        if (!snoop) {
		snoop = msg_heap_alloc(heap, atmo, sizeof(*snoop), NULL);
                if (!snoop) {
                        error_sig("%s", "heap exhausted");
                        lock_mutex_unlock(&post_office->lock_hunt);
                        lock_mutex_unlock(&post_office->lock_snoop);
                        return;
                }
                snoop->pid = pid;
                snoop->event = 0;
                msg_heap_append(heap, queue, snoop);
        }
        MSG_BIT_OP(MSG_BIT_SET, POST_OFFICE_SNOOP_UNRESOLVED_HUNT,
                   snoop->event);
        msg_heap_foreach(heap, queue, hunt) {
                send_msg_snoop_hunt(snoop, hunt, atmo);
        }
        lock_mutex_unlock(&post_office->lock_hunt);
        lock_mutex_unlock(&post_office->lock_snoop);
}
