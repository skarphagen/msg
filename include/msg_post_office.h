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

#ifndef MSG_POST_OFFICE_H
#define MSG_POST_OFFICE_H

#include <msg_postbox.h>
#include <msg_thread.h>
#include <msg_heap.h>
#include <msg_util.h>
#include <msgh.h>
#include <limits.h>
#include <stdatomic.h>

#define POST_OFFICE_MAGIC 0x0000046702796924U
#define POST_OFFICE_PID_INVALID 0
#define POST_OFFICE_PID_VALID   1
#define POST_OFFICE_PID_ZOOMBIE 2

struct post_office_mem {
	uint64_t magic;
	size_t size;
	void *addr;
};

struct post_office {
	struct post_office_mem mem;
        char name[NAME_MAX];   /* post office name */
        struct msg_heap *heap; /* message heap */
        uint64_t index_mask;   /* bitmask to lock up address index */
        uint32_t addresses;    /* number of available addresses */
        uint32_t rank;         /* used to extract the pid sequence number */
	uint32_t alloc_tmo;
        atomic_uint_least32_t postboxes[2]; /* in use [0] and peak value [1] */
        atomic_uint_least32_t index; /* latest used address index */
        atomic_uint_least64_t bid;
        pthread_mutex_t lock_attach;
        pthread_mutex_t lock_hunt;
        pthread_mutex_t lock_alias;
        pthread_mutex_t lock_tmo;
        pthread_mutex_t lock_snoop;
        struct msg_queue attach;
        struct msg_queue hunt;
        struct msg_queue alias;
        struct msg_queue tmo;
        struct msg_queue snoop;
        struct postbox_address postbox_map[1]; /* postbox address map */
};

#define POST_OFFICE_SNOOP_EVENT(snoop, event) \
        MSG_BIT_OP(MSG_BIT_CHECK, snoop, event)

#define POST_OFFICE_SNOOP_UNRESOLVED_HUNT 0
#define POST_OFFICE_SNOOP_POSTBOX         1

struct post_office_snoop {
        uint64_t pid;
        uint8_t event;
} __attribute__((packed));

typedef int (postbox_func)(const union postbox_info *, void *);

struct post_office *post_office_get(void);

int post_office_create(const char *domain, uint32_t size, uint32_t addresses);

int post_office_delete(const char *name);

int post_office_open(const char *name);

int post_office_close(struct post_office *post_office);

int post_office_connect(const char *domain);

struct postbox_address *post_office_assign_address(union postbox *postbox,
                                                   uint64_t ppid, uint64_t bid);

struct postbox_address *post_office_lock(uint64_t pid);

union postbox *post_office_deassign_address(struct postbox_address *address);

void post_office_send(struct msgh *msgh, uint64_t addressee, const char *file,
		      int line);

void post_office_unlock_address(struct postbox_address *address);

void post_office_foreach_postbox(postbox_func *func, void *user);

void post_office_exit(void (*exit_func)(struct msg_heap *heap,
					struct postbox_address *),
		      uint64_t bid);

void post_office_snoop_clear(uint64_t pid);

void post_office_snoop_exit_resolve(struct postbox_address *address,
				    uint32_t tmo);

void post_office_snoop_create_resolve(struct postbox_address *address,
				      uint32_t tmo);

void post_office_snoop_postbox(uint64_t pid, uint32_t tmo);

uint64_t post_office_new_bid(void);

uint64_t post_office_get_pid(const char *name, uint64_t bid);

uint8_t post_office_pid_status(struct postbox_address *address, uint64_t pid);

struct msgh *post_office_reference_rx_cancel(uint64_t reference, uint64_t pid);

void post_office_msg_rx_clear(uint64_t type, uint64_t pid);

#endif
