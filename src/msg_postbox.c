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

#include <msg_postbox.h>
#include <msg_thread.h>
#include <msg_time.h>
#include <msg_sig.h>
#include <msgh.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static struct msgh *postbox_select(struct msg_heap *heap,
				   struct msg_queue *rx_queue,
                                   const uint64_t *rx_filter)
{
        struct msgh *msgh;
        uint64_t i;

        if (rx_filter[0] == 0) {
                msgh = msg_heap_first(heap, rx_queue);
                return msgh;
        }
        msg_heap_foreach(heap, rx_queue, msgh) {
                for (i = 0; i < rx_filter[0]; i++) {
                        if (msgh->type == rx_filter[i + 1])
                                return msgh;
                }
        }
        return NULL;
}

static struct msgh *postbox_select_from(struct msg_heap *heap,
                                        struct msg_queue *rx_queue,
                                        const uint64_t *rx_filter,
                                        uint64_t from)
{
        struct msgh *msgh;
        uint64_t i;

        if (rx_filter[0] == 0) {
                msg_heap_foreach(heap, rx_queue, msgh) {
                        if (msgh->sender == from)
                                return msgh;
                }
                return NULL;
        }
        msg_heap_foreach(heap, rx_queue, msgh) {
                if (msgh->sender != from)
                        continue;
                for (i = 0; i < rx_filter[0]; i++) {
                        if (msgh->type == rx_filter[i + 1])
                                return msgh;
                }
        }
        return NULL;
}

static void free_redirect_table(struct msg_heap *heap, union postbox *postbox)
{
        if (postbox->box.redirection) {
                msg_heap_free(heap, postbox->box.redirection);
                postbox->box.redirection = NULL;
        }
}

union postbox *postbox_create(struct msg_heap *heap, uint32_t tmo,
			      const char *name, uint8_t state,
			      const uint64_t *rdr, void (*entry)(void))
{
        union postbox *postbox;
	size_t size;
        size_t len;

        len = name ? strlen(name) : 0;
	size = sizeof(struct postbox_thread) + len;
        postbox = msg_heap_alloc(heap, tmo, size, NULL);
        if (!postbox)
		goto out;
	postbox->box.type = POSTBOX_TYPE_THREAD;
	postbox->box.redirection = NULL;
	postbox->thread.entry = entry;
	postbox->thread.state = state;
	postbox->thread.pid = getpid();
	postbox->thread.id = pthread_self();
	postbox->thread.fd = -1;
	postbox->thread.line = 0;
	postbox->thread.name[len] = 0;
	postbox->thread.rx_count = 0;
	postbox->thread.tx_count = 0;
	postbox->thread.rx_bytes = 0;
	postbox->thread.tx_bytes = 0;
	postbox->thread.file[0] = 0;
	postbox->thread.name[len] = 0;
	msg_heap_queue(heap, &postbox->thread.rx);
	msg_heap_queue(heap, &postbox->thread.own);
	memcpy(postbox->thread.name, name, len);
	if (postbox_redirect(heap, tmo, postbox, rdr)) {
		postbox_free(heap, postbox);
                goto out;
        }		
	return postbox;
out:
        return NULL;
}

union postbox *postbox_phantom(struct msg_heap *heap, uint32_t tmo,
			       const char *name, const uint64_t *rdr)
{
        union postbox *postbox;
	size_t size;
        size_t len;

        len = name ? strlen(name) : 0;
	size = sizeof(struct postbox_phantom) + len;
        postbox = msg_heap_alloc(heap, tmo, size, NULL);
        if (!postbox )
                goto out;
        postbox->box.type = POSTBOX_TYPE_PHANTOM;
        postbox->box.redirection = NULL;
        postbox->phantom.name[len] = 0;
        memcpy(postbox->phantom.name, name, len);
        if (postbox_redirect(heap, tmo, postbox, rdr)) {
                postbox_free(heap, postbox);
                goto out;
        }
        return postbox;
out:
        return NULL;
}

struct msgh *postbox_recv(struct msg_heap *heap,
			  struct postbox_address *address,
                          const uint64_t *rx_filer)
{
        union postbox *postbox = address->postbox;
        struct msg_lock *lock = &address->lock;
        struct msg_queue *rx = &postbox->thread.rx;
        struct msgh *msgh;

        LOCK_PUSH(lock);
        while (!(msgh = postbox_select(heap, rx, rx_filer))) {
                lock_wait(lock);
        }
        msgh = msg_heap_linkout(heap, rx, msgh);
        msg_heap_append(heap, &postbox->thread.own, msgh);
        msgh->owner = address->pid;
	postbox->thread.rx_count++;
        postbox->thread.rx_bytes += msgh->size;
        LOCK_POP();
        return msgh;
}

struct msgh *postbox_recv_tmo(struct msg_heap *heap,
                              struct postbox_address *address,
                              const uint64_t *rx_filter, uint32_t tmo)
{
        union postbox *postbox = address->postbox;
        struct msg_lock *lock = &address->lock;
        struct msg_queue *rx_queue = &postbox->thread.rx;
        struct timespec ts;
        struct msgh *msgh;
        int timeout;
	
        timeout = time_create_tmo(&ts, tmo);
        do {
                LOCK_PUSH(lock);
                while (!(msgh = postbox_select(heap, rx_queue, rx_filter)) &&
                       !timeout) {
                        timeout = lock_timedwait(lock, &ts);
                }
                if (msgh) {
                        msgh = msg_heap_linkout(heap, rx_queue, msgh);
                        msg_heap_append(heap, &postbox->thread.own, msgh);
                        msgh->owner = address->pid;
			postbox->thread.rx_count++;
                        postbox->thread.rx_bytes += msgh->size;
                }
                LOCK_POP();
        } while (!msgh && !timeout);
        return msgh;
}

struct msgh *postbox_recv_from(struct msg_heap *heap,
                               struct postbox_address *address,
                               const uint64_t *rx_filter, uint64_t from,
                               uint32_t tmo)
{
        union postbox *postbox = address->postbox;
        struct msg_lock *lock = &address->lock;
        struct msg_queue *rx_queue = &postbox->thread.rx;
        struct timespec ts;
        struct msgh *msgh;
        int timeout;
	
        timeout = time_create_tmo(&ts, tmo);
        do {
                LOCK_PUSH(lock);
                while (!(msgh = postbox_select_from(heap, rx_queue,
                                                    rx_filter, from)) &&
                       !timeout) {
                        timeout = lock_timedwait(lock, &ts);
                }
                if (msgh) {
                        msgh = msg_heap_linkout(heap, rx_queue, msgh);
                        msg_heap_append(heap, &postbox->thread.own, msgh);
                        msgh->owner = address->pid;
			postbox->thread.rx_count++;
                        postbox->thread.rx_bytes += msgh->size;
                }
                LOCK_POP();
        } while (!msgh && !timeout);
        return msgh;
}

void postbox_lock(struct postbox_address *address)
{
	lock_lock(&address->lock);
}

void postbox_unlock(struct postbox_address *address)
{
	lock_unlock(&address->lock);
}

void postbox_signal(struct postbox_address *address)
{
	lock_signal(&address->lock);
	if (address->postbox->thread.fd != -1) {
		union sigval value;
		value.sival_ptr = NULL;
		sigqueue(address->postbox->thread.pid, SIGMSGEVENT, value);
	}
}

union postbox *postbox_get(const struct postbox_address *address, uint64_t pid)
{
        union postbox *postbox;

        postbox = address->postbox;
        return postbox && address->pid == pid ? postbox : NULL;
}

void postbox_free(struct msg_heap *heap, union postbox *postbox)
{
        if (postbox->box.type == POSTBOX_TYPE_THREAD) {
                msg_heap_queue_clear(heap, &postbox->thread.rx);
                msg_heap_queue_clear(heap, &postbox->thread.own);
        }
        free_redirect_table(heap, postbox);
        msg_heap_free(heap, postbox);
}

int postbox_redirect(struct msg_heap *heap, uint32_t tmo,
		     union postbox *postbox, const uint64_t *rdr)
{
        free_redirect_table(heap, postbox);
        if (rdr[0]) {
                size_t size = POSTBOX_RDR_LEN(rdr) * sizeof(rdr[0]);
                postbox->box.redirection = msg_heap_alloc(heap, tmo, size,
							  NULL);
                if (!postbox->box.redirection)
                        return -1;
                memcpy(postbox->box.redirection, rdr, size);
        }
        return 0;
}

uint64_t postbox_redirect_pid(union postbox *postbox, uint64_t type)
{
        uint64_t *rdr = postbox->box.redirection;
        uint64_t i, t;

        if (!rdr)
		return 0;
	for (i = 0, t = 1; i < rdr[0]; i++, t += 2) {
		if ((rdr[t] == 0) || (rdr[t] == type)) {
			return rdr[t + 1];  /* PID */
		}
	}
        return 0;
}

void postbox_state_file_line(struct postbox_thread *postbox, uint8_t state,
                             const char *file, uint32_t line)
{
        static __thread const char *filep = NULL;
        const char *name;
        size_t offset;
        size_t size;

        postbox->state = state;
        postbox->line = line;
        if (filep != file) {
                filep = file; 
                name = msg_util_file_name(file);
                size = strlen(name) + 1;
                /* If needed, truncate from left */
                offset = (size <= sizeof(postbox->file)) ? 0 :
			(size - sizeof(postbox->file));
                size -= offset;
                memcpy(postbox->file, &name[offset], size);
        }
}

union postbox_info *postbox_get_info(struct postbox_address *address)
{
        union postbox *postbox = address->postbox;
        struct postbox_phantom *phantom;
        struct postbox_thread *thread;
        union postbox_info *info;
        size_t nlen, flen;

        if (postbox->box.type == POSTBOX_TYPE_THREAD) {
                thread = &postbox->thread;
                nlen = strlen(thread->name);
                flen = strlen(thread->file);
                info = malloc(sizeof(info->thread) + nlen + flen + 1);
                if (info) {
                        info->type = postbox->box.type;
                        info->thread.pid = address->pid;
                        info->thread.ppid = address->ppid;
                        info->thread.bid = address->bid;
                        info->thread.state = thread->state;
                        info->thread.line = thread->line;
			info->thread.tx_count = thread->tx_count;
                        info->thread.rx_count = thread->rx_count;
                        info->thread.tx_bytes = thread->tx_bytes;
                        info->thread.rx_bytes = thread->rx_bytes;
                        info->thread.name = memcpy(&info->thread.buf[0],
                                                   thread->name, nlen);
                        info->thread.buf[nlen++] = 0;
                        info->thread.file = memcpy(&info->thread.buf[nlen],
                                                   thread->file, flen);
                        info->thread.buf[nlen + flen] = 0;
                }
        } else {
                phantom = &postbox->phantom;
                nlen = strlen(phantom->name);
                info = malloc(sizeof(info->phantom) + nlen);
                if (info) {
                        info->type = postbox->box.type;
                        info->phantom.pid = address->pid;
                        info->phantom.ppid = address->ppid;
                        info->phantom.bid = address->bid;
                        memcpy(&info->phantom.name[0], phantom->name, nlen);
                        info->phantom.name[nlen] = 0;
                }
        }
        return info;
}
