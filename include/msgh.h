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

#ifndef MSGH_H
#define MSGH_H

#include <stddef.h>
#include <msg_heap.h>

#define MSG_VALID         0 /* Valid message */
#define MSG_INVALID_PTR   1 /* Invalid pointer */
#define MSG_INVALID_OWNER 2 /* Not the message owner */
#define MSG_CORRUPTED     3 /* Corrupted message */

#define MSG_HEADER(m) &((struct msgh *)(m))[-1]
#define MSG_PAYLOAD(h) (void *)(&(h)[1])

struct msgh {
        uint64_t reference; /* message reference */
        uint64_t type;      /* message type */
        uint64_t addressee; /* original receiver of the message */
        uint64_t sender;    /* sender of the message */
        uint64_t owner;     /* message owner */
        uint64_t size;      /* size of payload */
};

struct msgh *msgh_alloc(struct msg_heap *heap, uint32_t tmo, uint64_t size,
			uint64_t type);

struct msgh *msgh_copy(struct msg_heap *heap, uint32_t tmo, struct msgh *msgh);

int msgh_verify(struct msg_heap *heap, uint64_t owner, struct msgh *msgh);

void msgh_free(struct msg_heap *heap, struct msgh *msgh);

void msgh_new_reference(struct msg_heap *heap, struct msgh *msgh);

#endif
