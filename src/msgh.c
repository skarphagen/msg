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
#include <msgh.h>
#include <string.h>

#define MSG_PAYLOAD_OFFSET sizeof(struct msgh)

#define MSGH_END_MARK(msgh)						\
	(uint64_t *)((uint8_t *)MSG_PAYLOAD(msgh) + msgh->size)

static void set_endmark(struct msgh *msgh)
{
	uint64_t *endmark = MSGH_END_MARK(msgh);
	*endmark = msgh->reference ^ msgh->size;
}

static int verify_endmark(struct msgh *msgh)
{
	uint64_t *endmark = MSGH_END_MARK(msgh);
	return !(*endmark == (msgh->reference ^ msgh->size));
}

struct msgh *msgh_alloc(struct msg_heap *heap, uint32_t tmo, uint64_t size,
			uint64_t type)
{
        uint64_t reference;
        uint64_t msg_size;
        struct msgh *msgh;

        msg_size = sizeof(struct msgh) + size + sizeof(uint64_t);
        msgh = msg_heap_alloc(heap, tmo, msg_size, &reference);
        if (msgh) {
                msgh->reference = reference;
                msgh->type = type;
                msgh->addressee = 0;
                msgh->sender = 0;
                msgh->owner = 0;
                msgh->size = size;
		set_endmark(msgh);
        }
        return msgh;
}

void msgh_free(struct msg_heap *heap, struct msgh *msgh)
{
	msg_heap_free(heap, msgh);
}

struct msgh *msgh_copy(struct msg_heap *heap, uint32_t tmo, struct msgh *msgh)
{
        struct msgh *copy;
        uint64_t size;

        size = sizeof(struct msgh) + msgh->size + sizeof(uint64_t);
        copy = msg_heap_alloc(heap, tmo, size, NULL);
        return copy ? memcpy(copy, msgh, size) : NULL;
}

int msgh_verify(struct msg_heap *heap, uint64_t owner, struct msgh *msgh)
{
	if (!msg_heap_verify(heap, msgh)) {
		if (!verify_endmark(msgh)) {
			return (msgh->owner == owner) ? MSG_VALID :
				MSG_INVALID_OWNER;
		} else {
			return MSG_CORRUPTED;
		}
	}
	return MSG_INVALID_PTR;
}

void msgh_new_reference(struct msg_heap *heap, struct msgh *msgh)
{
	msgh->reference = msg_heap_reference(heap);
	set_endmark(msgh);
}
