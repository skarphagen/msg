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

#ifndef MSG_H
#define MSG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/**
 * Postbox type
 */
#define MSG_POSTBOX_INVALID 0
#define MSG_POSTBOX_STATIC  1
#define MSG_POSTBOX_DYNAMIC 2
#define MSG_POSTBOX_PHANTOM 3
#define MSG_POSTBOX_ZOOMBIE 4

/**
 * Postbox state
 */
#define MSG_STATE_CREATED 0
#define MSG_STATE_RUNNING 1
#define MSG_STATE_RECV    2
#define MSG_STATE_DELAY   3

/**
 * Snoop events
 */
#define MSG_EVENT_SNOOP_OFF             0
#define MSG_EVENT_SNOOP_UNRESOLVED_HUNT 1
#define MSG_EVENT_SNOOP_POSTBOX         2

/**
 * Note! 0 - 999 are reserved message types
 */
#define MSG_BASE 1000

/**
 * Default attach message type
 */
#define MSG_ATTACH 1

/**
 * Default asynchronous hunt message type
 */
#define MSG_HUNT 2

/**
 * Default timeout message type
 */
#define MSG_TMO 3

/**
 * Unresolved hunt snoop message
 * The hunting PID of name is the sender of the message.
 */
#define MSG_SNOOP_UNRESOLVED_HUNT 4
struct msg_snoop_unresolved_hunt {
	char name[1];
} __attribute__((packed));

/**
 * Postbox snoop message
 */
#define MSG_SNOOP_POSTBOX 5
struct msg_snoop_postbox {
	uint64_t ppid;  /* parent postbox ID */
	uint64_t pid;   /* postbox ID */
	uint64_t bid;   /* postbox block ID */
	uint8_t type;   /* MSG_POSTBOX_XXX */
	char name[1];   /* postbox name */
} __attribute__((packed));

/**
 * Send and receive hook function prototype
 */
typedef void (msg_hook)(void *msg, void *user);

/**
 * Postbox information
 */
struct msgpbi {
	uint64_t ppid;  /* parent postbox ID */
	uint64_t pid;   /* postbox ID */
	uint64_t bid;   /* postbox block ID */
	uint8_t type;   /* MSG_POSTBOX_XXX */
	char name[1];   /* postbox name */
};

/**
 * Message redirection entry
 */
struct msgrdr {
	uint64_t type; /* message type */
	uint64_t pid;  /* redirection postbox */
};

/**
 * Create a static postbox, called once per block (process).
 */
#define msg_init(name, domain)				\
	msg_init_zz(name, domain, __FILE__, __LINE__)

/**
 * Register a function to be called when a postbox is terminated.
 * Functions are called at reversed order of there registration.
 */
#define msg_atexit(func, user)				\
	msg_atexit_zz(func, user, __FILE__, __LINE__)

/**
 * Create a dynamic postbox
 */
#define msg_postbox(name, entry, rdr)				\
	msg_postbox_zz(name, entry, rdr, __FILE__, __LINE__)

/**
 * Create a phantom postbox
 */
#define msg_phantom(name, rdr)				\
	msg_phantom_zz(name, rdr, __FILE__, __LINE__)

/**
 * Assign an alias to own postbox
 */
#define msg_alias(name)				\
	msg_alias_zz(name, __FILE__, __LINE__)

/**
 * Kill a postbox
 */
#define msg_kill(pid)				\
	msg_kill_zz(pid, __FILE__, __LINE__)

/**
 * Hunt for a postbox
 */
#define msg_hunt(name)				\
	msg_hunt_zz(name, __FILE__, __LINE__)

/**
 * Hunt for a postbox asynchronously
 */
#define msg_hunt_async(name, msg, reference)				\
	msg_hunt_async_zz(name, msg, reference, __FILE__, __LINE__)

/**
 * Attach to a postbox
 */
#define msg_attach(pid, msg, reference)				\
	msg_attach_zz(pid, msg, reference, __FILE__, __LINE__)

/**
 * Allocate a message
 */
#define msg_alloc(size, type)				\
	msg_alloc_zz(size, type, __FILE__, __LINE__)

/**
 * Send a message
 */
#define msg_send(msg, to)				\
	msg_send_zz(msg, to, __FILE__, __LINE__)

/**
 * Send a message from
 */
#define msg_sends(msg, to, from)			\
	msg_sends_zz(msg, to, from, __FILE__, __LINE__)

/**
 * Receive a message
 */
#define msg_recv(rx)				\
	msg_recv_zz(rx, __FILE__, __LINE__)

/**
 * Receive a message with timeout
 */
#define msg_recv_tmo(rx, tmo)				\
	msg_recv_tmo_zz(rx, tmo, __FILE__, __LINE__)

/**
 * Receive a message from a specific postbox
 */
#define msg_recv_from(rx, from, tmo)				\
	msg_recv_from_zz(rx, from, tmo, __FILE__, __LINE__)

/**
 * Reference of a message
 */
#define msg_reference(msg)				\
	msg_reference_zz(msg, __FILE__, __LINE__)

/**
 * Message type
 */
#define msg_type(msg)				\
	msg_type_zz(msg, __FILE__, __LINE__)

/**
 * Set message type
 */
#define msg_type_set(msg, type)				\
	msg_type_set_zz(msg, type, __FILE__, __LINE__)

/**
 * The postbox identity (PID) of the message sender
 */
#define msg_sender(msg)				\
	msg_sender_zz(msg, __FILE__, __LINE__)

/**
 * The addressee of a message, i.e. the PID 'to' in msg_send and
 * msg_sends. This makes it possible for a receiver to determine if the
 * message was redirected or not (addressee != own PID).
 */
#define msg_addressee(msg)				\
	msg_addressee_zz(msg, __FILE__, __LINE__)

/**
 * Size of a message
 */
#define msg_size(msg)				\
	msg_size_zz(msg, __FILE__, __LINE__)

/**
 * Cancel an ongoing operation with the associated reference.
 * - msg_attach
 * - msg_hunt_async
 * - msg_tmo
 *
 * Note, the rx queue is also checked for this reference, i.e. all messages
 * with this reference are removed from the callers rx queue.
 *
 * return message pointer if the reference is found, else NULL.
 */
#define msg_cancel(reference)				\
	msg_cancel_zz(reference, __FILE__, __LINE__)

/**
 * Free a message
 */
#define msg_free(msg)				\
	msg_free_zz(msg, __FILE__, __LINE__)

/**
 * Set the redirection table for a postbox
 */
#define msg_redirect(pid, rdr)				\
	msg_redirect_zz(pid, rdr, __FILE__, __LINE__)

/**
 * Own postbox identity
 */
#define msg_pid()				\
	msg_pid_zz(__FILE__, __LINE__)

/**
 * Parent postbox identity, pid = ppid for a static postbox.
 */
#define msg_ppid()				\
	msg_ppid_zz(__FILE__, __LINE__)

/**
 * Block identity for a postbox
 */
#define msg_bid(pid)				\
	msg_bid_zz(pid, __FILE__, __LINE__)

/**
 * Postbox information
 */
#define msg_pbi(pid)				\
	msg_pbi_zz(pid, __FILE__, __LINE__)

/**
 * Event file descriptor for own postbox
 */
#define msg_open_fd()				\
	msg_open_fd_zz(__FILE__, __LINE__)
	
#define msg_close_fd()				\
	msg_close_fd_zz(__FILE__, __LINE__)
/**
 * Set msg_alloc timeout.
 */
#define msg_atmo_set(msec)				\
	msg_atmo_set_zz(msec, __FILE__, __LINE__)

#define msg_tmo(msg, msec, interval_msec, reference)			\
	msg_tmo_zz(msg, msec, interval_msec, reference, __FILE__, __LINE__)

#define msg_delay(msec)				\
	msg_delay_zz(msec, __FILE__, __LINE__)

#define msg_snoop(event)			\
	msg_snoop_zz(event, __FILE__, __LINE__)

#define msg_hook_recv(hook, user)				\
	msg_hook_recv_zz(hook, user, __FILE__, __LINE__)

#define msg_hook_send(hook, user)				\
	msg_hook_send_zz(hook, user, __FILE__, __LINE__)

#define msg_exit(fmt, ...)					\
	msg_exit_zz(__FILE__, __LINE__, fmt, __VA_ARGS__)

#define msg_error(fmt, ...)					\
	msg_error_zz(__FILE__, __LINE__, fmt, __VA_ARGS__)

void msg_init_zz(const char *name, const char *domain, const char *file, int line);

void msg_atexit_zz(void (*func)(void *), void *user, const char *file, int line);

uint64_t msg_postbox_zz(const char *name, void (*entry)(void),
			const struct msgrdr *rdr, const char *file, int line);

uint64_t msg_phantom_zz(const char *name, const struct msgrdr *rdr,
			const char *file, int line);

void msg_alias_zz(const char *name, const char *file, int line);

void msg_kill_zz(uint64_t pid, const char *file, int line);

uint64_t msg_hunt_zz(const char *name, const char *file, int line);

uint64_t msg_hunt_async_zz(const char *name, void *msg, uint64_t *reference,
			   const char *file, int line);

void msg_attach_zz(uint64_t pid, void *msg, uint64_t *reference,
		   const char *file, int line);

void *msg_alloc_zz(uint64_t size, uint64_t type, const char *file, int line);

void msg_send_zz(void *msg, uint64_t to, const char *file, int line);

void msg_sends_zz(void *msg, uint64_t to, uint64_t from, const char *file, int line);

void *msg_recv_zz(const uint64_t *rx, const char *file, int line);

void *msg_recv_tmo_zz(const uint64_t *rx, uint32_t tmo,
		      const char *file, int line);

void *msg_recv_from_zz(const uint64_t *rx, uint64_t from,
		       uint32_t tmo, const char *file, int line);

void msg_redirect_zz(uint64_t pid, const struct msgrdr *rdr,
		     const char *file, int line);

void msg_free_zz(void *msg, const char *file, int line);

uint64_t msg_sender_zz(void *msg, const char *file, int line);

uint64_t msg_addressee_zz(void *msg, const char *file, int line);

uint64_t msg_size_zz(void *msg, const char *file, int line);

uint64_t msg_reference_zz(void *msg, const char *file, int line);

uint64_t msg_type_zz(void *msg, const char *file, int line);

void msg_type_set_zz(void *msg, uint64_t type, const char *file, int line);

void *msg_cancel_zz(uint64_t reference, const char *file, int line);

uint64_t msg_pid_zz(const char *file,  int line);

uint64_t msg_ppid_zz(const char *file,  int line);

uint64_t msg_bid_zz(uint64_t pid, const char *file, int line);

struct msgpbi *msg_pbi_zz(uint64_t pid, const char *file, int line);

int msg_open_fd_zz(const char *file, int line);

void msg_close_fd_zz(const char *file, int line);

void msg_atmo_set_zz(uint32_t msec, const char *file, int line);

void msg_tmo_zz(void *msg, long msec, long interval_msec, uint64_t *reference,
		const char *file, int line);

void msg_delay_zz(uint32_t msec, const char *file, int line);

void msg_snoop_zz(uint32_t event, const char *file, int line);

void msg_hook_recv_zz(msg_hook *hook, void *user, const char *file, int line);

void msg_hook_send_zz(msg_hook *hook, void *user, const char *file, int line);

void msg_exit_zz(const char *file, int line, const char *fmt, ...)
	__attribute__((format(printf, 3, 4), noreturn));

void msg_error_zz(const char *file, int line, const char *fmt, ...)
	__attribute__((format(printf, 3, 4), noreturn));

#ifdef __cplusplus
}
#endif
#endif
