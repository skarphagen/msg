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

#ifndef MSG_HEAP_H
#define MSG_HEAP_H

#include <stdint.h>

struct msg_heap;

struct msg_queue {
	struct msg_heap *heap;
        uint32_t first;
        uint32_t last;
};

struct msg_heap_info {
        uint64_t allocation;
        uint64_t deallocation;
        uint64_t tmo_counter;
        uint32_t size;
        uint32_t used;
        uint32_t peak;
};

#define msg_heap_foreach(heap, queue, ptr)		\
        for ((ptr) = msg_heap_first((heap), (queue));	\
             (ptr);					\
             (ptr) = msg_heap_next((heap), (ptr)))

#define msg_heap_foreach_safe(heap, queue, ptr, next)			\
        for ((ptr) = msg_heap_first((heap), (queue));			\
             (ptr) && ((next) = msg_heap_next((heap), (ptr)), 1);	\
             (ptr) = (next))

struct msg_heap *msg_heap_create(uint32_t size, void *address);

void *msg_heap_alloc(struct msg_heap *heap, uint32_t tmo, uint32_t size,
		     uint64_t *reference);

void msg_heap_free(struct msg_heap *heap, void *ptr);

void msg_heap_queue(struct msg_heap *heap, struct msg_queue *queue);

void *msg_heap_linkout(struct msg_heap *heap, struct msg_queue *queue,
		       void *ptr);

void msg_heap_append(struct msg_heap *heap, struct msg_queue *queue, void *ptr);

void *msg_heap_first(struct msg_heap *heap, struct msg_queue *queue);

void *msg_heap_next(struct msg_heap *heap, void *ptr);

void msg_heap_queue_clear(struct msg_heap *heap, struct msg_queue *queue);

void msg_heap_get_info(struct msg_heap *heap, struct msg_heap_info *info);

int msg_heap_verify(struct msg_heap *heap, void *ptr);

uint64_t msg_heap_reference(struct msg_heap *heap);

#endif
