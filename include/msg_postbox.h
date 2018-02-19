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

#ifndef MSG_POSTBOX_H
#define MSG_POSTBOX_H

#include <msg_heap.h>
#include <msg_lock.h>
#include <msg_util.h>
#include <limits.h>

#define POSTBOX_TYPE_THREAD  0U
#define POSTBOX_TYPE_PHANTOM 1U
#define POSTBOX_RDR_LEN(r) (((r)[0]) ? (((r)[0] * 2) + 1) : 0)

struct postbox_box {
        uint64_t *redirection; /* redirection table */
        uint8_t type;          /* POSTBOX_TYPE_XXX */
};

struct postbox_thread {
        struct postbox_box box;
        uint8_t state;
        pid_t pid;            /* process identity */
        pthread_t id;         /* thread identity */
	int fd;               /* event file descriptoy */
        int line;             /* file line */
        struct msg_queue rx;  /* receive queue */
        struct msg_queue own; /* own queue */
	uint64_t tx_count;
	uint64_t rx_count;
        uint64_t rx_bytes;   /* received bytes (message payload) */
        uint64_t tx_bytes;   /* transmitted bytes (message payload) */
        void (*entry)(void); /* postbox entry point */
        char file[32];       /* short file name */
        char name[1];        /* postbox name */
};

struct postbox_phantom {
        struct postbox_box box;
        char name[1]; /* postbox name */
};

union postbox {
        struct postbox_box box;
        struct postbox_thread thread;
        struct postbox_phantom phantom;
};

struct postbox_address {
        union postbox *postbox; /* postbox (allocated in the message heap) */
        struct msg_lock lock;   /* address lock */
        uint64_t bid;           /* postbox block ID */
        uint64_t ppid;          /* parent postbox ID */
        uint64_t pid;           /* postbox ID */
};

struct postbox_thread_info {
        uint8_t type;
        uint8_t state; /* postbox type MSG_STAT_XXX, see msg.h */
        int line;
        uint64_t bid;
        uint64_t ppid;
        uint64_t pid;
	uint64_t tx_count;
	uint64_t rx_count;
        uint64_t tx_bytes; /* transmitted bytes (message payload) */
        uint64_t rx_bytes; /* received bytes (message payload) */
        char *name;
        char *file;
        char buf[1];
};

struct postbox_phantom_info {
        uint8_t type;
        uint64_t bid;
        uint64_t ppid;
        uint64_t pid;
        char name[1];
};

union postbox_info {
        uint8_t type;
        struct postbox_thread_info thread;
        struct postbox_phantom_info phantom;
};

union postbox *postbox_create(struct msg_heap *heap, uint32_t tmo,
			      const char *name, uint8_t state,
			      const uint64_t *rdr, void (*entry)(void));

union postbox *postbox_phantom(struct msg_heap *heap, uint32_t tmo,
			       const char *name, const uint64_t *rdr);

struct msgh *postbox_recv(struct msg_heap *heap,
			  struct postbox_address *address,
                          const uint64_t *rx_filter);

struct msgh *postbox_recv_tmo(struct msg_heap *heap,
                              struct postbox_address *address,
                              const uint64_t *rx_filter, uint32_t tmo);

struct msgh *postbox_recv_from(struct msg_heap *heap,
                               struct postbox_address *address,
                               const uint64_t *rx_filter, uint64_t from,
                               uint32_t tmo);

void postbox_lock(struct postbox_address *address);

void postbox_unlock(struct postbox_address *address);

void postbox_signal(struct postbox_address *address);

union postbox *postbox_get(const struct postbox_address *address, uint64_t pid);

int postbox_redirect(struct msg_heap *heap, uint32_t tmo,
		     union postbox *postbox, const uint64_t *rdr);

uint64_t postbox_redirect_pid(union postbox *postbox, uint64_t type);

void postbox_free(struct msg_heap *heap, union postbox *postbox);

void postbox_state_file_line(struct postbox_thread *postbox, uint8_t state,
                             const char *file, uint32_t line);

union postbox_info *postbox_get_info(struct postbox_address *address);

#endif
