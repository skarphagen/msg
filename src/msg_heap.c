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

#include <msg_heap.h>
#include <msg_lock.h>
#include <msg_time.h>
#include <sys/param.h>
#include <unistd.h>
#include <string.h>

#define QLINK_PAYLOAD(q) ((struct qlink *)(q) + 1)
#define PAYLOAD_QLINK(p) ((struct qlink *)(p) - 1)
#define QLINK(p,i) ((struct qlink *)(p))[i]

#define QLINK_FOREACH(p,s,c,q)			\
        for (c = s, q = &QLINK(p,c);		\
             q->adjacent;			\
             c = q->adjacent, q = &QLINK(p,c))

#define QLINK_FOREACH_FREE(p,s,c,q)		\
        for (c = s, q = &QLINK(p,c);		\
             q->next_free;			\
             c = q->next_free, q = &QLINK(p,c))

struct msg_heap {
        struct msg_lock lock;
        uint64_t reference;
        uint64_t allocation;
        uint64_t deallocation;
        uint64_t tmo_counter;
        uint32_t tmo;
        uint32_t start;
        uint32_t end;
        uint32_t free;
        uint32_t size;
        uint32_t used;
        uint32_t peak;
};

struct qlink {
        uint32_t next_free;
        uint32_t adjacent;
        uint32_t next;
        uint32_t prev;
};

static void heap_info_update(struct msg_heap *heap, struct qlink *qlink)
{
        heap->allocation++;
        heap->used += qlink->adjacent - qlink->next_free;
        heap->peak = MAX(heap->peak, heap->used);
}

static uint32_t next_free(struct msg_heap *heap, uint32_t start)
{
        struct qlink *qlink;
        uint32_t cursor;

        QLINK_FOREACH(heap, start, cursor, qlink) {
                if (qlink->next_free != cursor)
                        return cursor;
        }
        return cursor;
}

static uint32_t next_used(struct msg_heap *heap, uint32_t start)
{
        struct qlink *qlink;
        uint32_t cursor;

        QLINK_FOREACH(heap, start, cursor, qlink) {
                if (qlink->next_free == cursor)
                        return cursor;
        }
        return cursor;
}

static uint32_t heap_quanta(uint32_t size)
{
        size = (size + (sizeof(struct qlink) - 1)) &
		(~(sizeof(struct qlink) - 1));
        size = size / sizeof(struct qlink);
        return size > 0 ? size : 1;
}

static struct qlink *heap_qlink(struct msg_heap *heap, uint32_t quanta)
{
        struct qlink *qlink;
        uint32_t avail_quanta;
        uint32_t offset;
        uint32_t cursor;

        QLINK_FOREACH_FREE(heap, heap->free, cursor, qlink) {
                avail_quanta = qlink->adjacent - cursor - 1;
                if (quanta > avail_quanta)
                        continue;
                /* Insert a qlink */
                if (quanta + 2 <= avail_quanta) {
                        offset = quanta + 1;
                        qlink[offset].adjacent = qlink->adjacent;
                        qlink[offset].next_free = qlink->next_free;
                        qlink[offset].next = 0;
                        qlink[offset].prev = 0;
                        qlink->adjacent = cursor + offset;
                        heap->free = qlink->adjacent;
                } else {
                        heap->free = qlink->next_free;
                }
		qlink->next_free = cursor; /* used qlink */
		return qlink;
        }
        return NULL;
}

static void heap_merge(struct msg_heap *heap)
{
        struct qlink *qlink;
        uint32_t next;
	
        next = next_free(heap, heap->start);
        heap->free = next;
        qlink = &QLINK(heap, next);
        while (qlink->adjacent) {
                qlink->adjacent = next_used(heap, next);
                qlink->next_free = next_free(heap, qlink->adjacent);
                next = qlink->next_free;
                qlink = &QLINK(heap, next);
        }
}

struct msg_heap *msg_heap_create(uint32_t size, void *address)
{
        struct msg_heap *heap;

	heap = memset(address, 0, size);
        lock_init(&heap->lock);
        heap->reference = 1;
        heap->tmo = 0;
        heap->tmo_counter = 0;
        heap->start = heap_quanta(sizeof(*heap));
        heap->end = heap_quanta(size) - 1;
        heap->size = size;
        heap->free = heap->start;
        heap->allocation = 0;
        heap->deallocation = 0;
        heap->used = 0;
        heap->peak = 0;
        QLINK(heap, heap->start).adjacent = heap->end;
        QLINK(heap, heap->start).next_free = heap->end;
        QLINK(heap, heap->start).next = 0;
        QLINK(heap, heap->start).prev = 0;
        QLINK(heap, heap->end).adjacent = 0;
        QLINK(heap, heap->end).next_free = 0;
        QLINK(heap, heap->end).next = 0;
        QLINK(heap, heap->end).prev = 0;
        return heap;
}

static void heap_alloc_cleanup(void *arg)
{
        struct msg_heap *heap = arg;

        heap->tmo--;
        lock_unlock(&heap->lock);
}

static struct qlink *heap_alloc_tmo(struct msg_heap *heap, uint32_t tmo,
				    uint32_t quanta)
{
        struct qlink *qlink;

	heap->tmo++;
	heap->tmo_counter++;
	pthread_cleanup_push(heap_alloc_cleanup, heap);
	int timedout = 0;
	struct timespec spec;
	time_create_tmo(&spec, tmo);
	while (!(qlink = heap_qlink(heap, quanta)) && !timedout) {
		timedout = lock_timedwait(&heap->lock, &spec);
	}
	if (qlink) 
		heap_info_update(heap, qlink);
	pthread_cleanup_pop(1);
	return qlink;
}

void *msg_heap_alloc(struct msg_heap *heap, uint32_t tmo, uint32_t size,
		     uint64_t *reference)
{
        struct qlink *qlink;
        uint32_t quanta;

        quanta = heap_quanta(size);
        lock_lock(&heap->lock);
	if (reference)
		*reference = heap->reference++;
        qlink = heap_qlink(heap, quanta);
        if (qlink) {
                heap_info_update(heap, qlink);		
                lock_unlock(&heap->lock);
                return QLINK_PAYLOAD(qlink);
        }
	if (tmo)
		qlink = heap_alloc_tmo(heap, tmo, quanta);
	else
		lock_unlock(&heap->lock);
        return qlink ? QLINK_PAYLOAD(qlink) : NULL;
}

int msg_heap_verify(struct msg_heap *heap, void *ptr)
{
        struct qlink *qlink = PAYLOAD_QLINK(ptr);
	return !(&QLINK(heap, qlink->next_free) == qlink);
}

void msg_heap_free(struct msg_heap *heap, void *ptr)
{
        struct qlink *qlink = PAYLOAD_QLINK(ptr);
        uint32_t cursor = qlink->next_free;

        lock_lock(&heap->lock);
	heap->deallocation++;
        heap->used -= qlink->adjacent - cursor;
	qlink->next_free = heap->free;
        heap->free = cursor;
	heap_merge(heap);
        if (heap->tmo)
                lock_broadcast(&heap->lock);
        lock_unlock(&heap->lock);
}

void msg_heap_append(struct msg_heap *heap, struct msg_queue *queue, void *ptr)
{
        struct qlink *qlink = PAYLOAD_QLINK(ptr);
        uint32_t cursor = qlink->next_free;

        if (!queue->first) {
                queue->first = cursor;
                queue->last = cursor;
        } else {
                qlink->prev = queue->last;
                QLINK(heap, queue->last).next = cursor;
                queue->last = cursor;
        }
}

void *msg_heap_first(struct msg_heap *heap, struct msg_queue *queue)
{
        return queue->first ? QLINK_PAYLOAD(&QLINK(heap, queue->first)) : NULL;
}

void *msg_heap_next(struct msg_heap *heap, void *ptr)
{
        struct qlink *qlink = PAYLOAD_QLINK(ptr);

        return qlink->next ? QLINK_PAYLOAD(&QLINK(heap, qlink->next)) : NULL;
}

void *msg_heap_linkout(struct msg_heap *heap, struct msg_queue *queue,
		       void *ptr)
{
        struct qlink *qlink = PAYLOAD_QLINK(ptr);
        uint32_t cursor;

        cursor = qlink->next_free;
        if (queue->first == cursor)
                queue->first = qlink->next;
        if (queue->last == cursor)
                queue->last = qlink->prev;
        if (qlink->prev)
                QLINK(heap, qlink->prev).next = qlink->next;
        if (qlink->next)
                QLINK(heap, qlink->next).prev = qlink->prev;
        qlink->next = 0;
        qlink->prev = 0;
        return ptr;
}

void msg_heap_queue(struct msg_heap *heap, struct msg_queue *queue)
{
        queue->heap = heap;
        queue->first = 0;
        queue->last = 0;
}

void msg_heap_queue_clear(struct msg_heap *heap, struct msg_queue *queue)
{
        void *ptr, *next;

        msg_heap_foreach_safe(heap, queue, ptr, next) {
                ptr = msg_heap_linkout(heap, queue, ptr);
                msg_heap_free(heap, ptr);
        }
}

void msg_heap_get_info(struct msg_heap *heap, struct msg_heap_info *info)
{
        lock_lock(&heap->lock);
        info->allocation = heap->allocation;
        info->deallocation = heap->deallocation;
        info->tmo_counter = heap->tmo_counter;
        info->size = heap->size;
        info->used = heap->used * sizeof(struct qlink);
        info->peak = heap->peak * sizeof(struct qlink);
        lock_unlock(&heap->lock);
}

uint64_t msg_heap_reference(struct msg_heap *heap)
{
	uint64_t reference;

	lock_lock(&heap->lock);
	reference = heap->reference++;
	lock_unlock(&heap->lock);
	return reference;
}
