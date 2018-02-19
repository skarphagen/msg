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

#include <msg_post_office_alias.h>
#include <msg_post_office.h>
#include <msg_lock.h>
#include <msg_heap.h>
#include <string.h>
#include <stdlib.h>

struct alias {
        uint64_t pid;
        uint64_t bid;
        char name[1];
} __attribute__((packed));

int post_office_alias(const char *name, uint64_t pid,
		      uint64_t bid, uint32_t atmo)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->alias;
        struct msg_heap *heap = post_office->heap;
        struct alias *alias;
        size_t len;

        lock_mutex_lock(&post_office->lock_alias);
        msg_heap_foreach(heap, queue, alias) {
                if (alias->bid == bid && alias->pid == pid &&
                    !strcmp(alias->name, name))
                        break;
        }
        if (!alias) {
                len = strlen(name);
                alias = msg_heap_alloc(heap, atmo, sizeof(*alias) + len, NULL);
                if (alias) {
                        alias->pid = pid;
                        alias->bid = bid;
                        memcpy(alias->name, name, len + 1);
                        msg_heap_append(heap, queue, alias);
                }
        }
        lock_mutex_unlock(&post_office->lock_alias);
        return alias ? 0 : -1;
}

uint64_t post_office_alias_pid(const char *name, uint64_t bid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->alias;
        struct msg_heap *heap = post_office->heap;
        struct alias *alias;
        uint64_t pid = 0;

        lock_mutex_lock(&post_office->lock_alias);
        msg_heap_foreach(heap, queue, alias) {
                if (!strcmp(alias->name, name)) {
                        pid = alias->pid;
                        if (alias->bid == bid)
                                break;
                }
        }
        lock_mutex_unlock(&post_office->lock_alias);
        return pid;
}

void post_office_alias_clear(uint64_t pid)
{
        struct post_office *post_office = post_office_get();
        struct msg_queue *queue = &post_office->alias;
        struct msg_heap *heap = post_office->heap;
        struct alias *alias, *next;

        lock_mutex_lock(&post_office->lock_alias);
        msg_heap_foreach_safe(heap, queue, alias, next) {
                if (alias->pid == pid) {
                        alias = msg_heap_linkout(heap, queue, alias);
                        msg_heap_free(heap, alias);
                }
        }
        lock_mutex_unlock(&post_office->lock_alias);
}
