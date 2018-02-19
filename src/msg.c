/**
 * Copyright (C) 2021 Skarphagen Embedded
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <msg.h>
#include <msgh.h>
#include <msg_sig.h>
#include <msg_heap.h>
#include <msg_time.h>
#include <msg_trace.h>
#include <msg_error.h>
#include <msg_thread.h>
#include <msg_postbox.h>
#include <msg_post_office.h>
#include <msg_post_office_tmo.h>
#include <msg_post_office_hunt.h>
#include <msg_post_office_alias.h>
#include <msg_post_office_attach.h>
#include <sys/eventfd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>

struct msg_ops {
	msg_hook *send_hook;
	msg_hook *recv_hook;
	void *send_user;
	void *recv_user;
};

struct thread_args {
	struct postbox_address *address;
	uint32_t atmo;
};

struct thread_exit {
	void (*func)(void *);
	void *user;
};

static __thread struct own {
	struct msg_ops ops;
	struct msg_trace trace;
	struct post_office *post_office;
	struct postbox_address *address;
	struct postbox_thread *postbox;
	struct msg_heap *heap;
	char *name;
	uint64_t bid;
	uint64_t pid;
	uint64_t ppid;
	uint32_t atmo;
	int exists;
	struct thread_exit *thread_exit;
} own = {
	.ops = {0},
	.trace = {0},
	.post_office = NULL,
	.address = NULL,
	.postbox = NULL,
	.heap = NULL,
	.name = NULL,
	.bid = 0,
	.pid = 0,
	.ppid = 0,
	.atmo = 0,
	.exists = 0,
	.thread_exit = NULL
};

static pthread_t main_tid;

static void msg_evenfd_read(const char *file, int line)
{
	eventfd_t data;
	
	if (own.postbox->fd == -1)
		return;
	if (eventfd_read(own.postbox->fd, &data)) {
		if (errno != EAGAIN)
			msg_error_zz(file, line, "%s", strerror(errno));
	}
}

static void __attribute__((noreturn))
msg_heap_exhausted(const char *file, int line)
{
	msg_error_zz(file, line, "%s", "heap exhausted");
}

static uint8_t msg_pid_type(struct postbox_address *address, uint64_t pid)
{
	uint8_t status;

	status = post_office_pid_status(address, pid);
	if (status == POST_OFFICE_PID_VALID) {
		if (address->postbox->box.type == POSTBOX_TYPE_THREAD)
			return (address->ppid != pid) ? MSG_POSTBOX_DYNAMIC :
				MSG_POSTBOX_STATIC;
		return MSG_POSTBOX_PHANTOM;
	}
	return (status == POST_OFFICE_PID_ZOOMBIE) ? MSG_POSTBOX_ZOOMBIE :
		MSG_POSTBOX_INVALID;
}

static struct msgh *msg_linkout_own_queue(struct msgh *msgh)
{
	msgh = msg_heap_linkout(own.heap, &own.postbox->own, msgh);
	msgh->owner = 0;
	return msgh;
}

static struct msgh *msg_append_own_queue(struct msgh *msgh)
{
	msg_heap_append(own.heap, &own.postbox->own, msgh);
	msgh->owner = own.pid;
	return msgh;
}

static struct msgh *msg_alloc_own(uint64_t size, uint64_t type,
				  const char *file, int line)
{
	struct msgh *msgh;

	msgh = msgh_alloc(own.heap, own.atmo, size, type);
	if (msgh)
		return msg_append_own_queue(msgh);
	msg_heap_exhausted(file, line);
}

static void msg_linkout_send(struct msgh *msgh, const char *file, int line)
{
	msgh = msg_linkout_own_queue(msgh);
	own.postbox->tx_count++;
	own.postbox->tx_bytes += msgh->size;
	post_office_send(msgh, msgh->addressee, file, line);
}

static struct msgh *msg_verify(void *msg, const char *file, int line)
{
	static const char fmt[] = "%s detected (msg = %p)";
	struct msgh *msgh;
	char *faulty;
	int res;

	msgh = MSG_HEADER(msg);
	res = msgh_verify(own.heap, own.pid, msgh);
	switch (res) {
	case MSG_VALID:
		return msgh;
	case MSG_INVALID_PTR:
		faulty = "invalid pointer";
		break;
	case MSG_INVALID_OWNER:
		faulty = "invalid ownership";
		break;
	default: /* MSG_CORRUPTED */
		faulty = "corrupted message";
		break;
	}
	msg_error_zz(file, line, fmt, faulty, msg);
	return msgh;
}

static void msg_exit_pid(struct msg_heap *heap, struct postbox_address *address)
{
	uint64_t pid = address->pid;
	union postbox *postbox;

	post_office_attach_clear(pid);
	post_office_hunt_clear(pid);
	post_office_tmo_clear(pid);
	post_office_alias_clear(pid);
	post_office_snoop_clear(pid);
	post_office_snoop_exit_resolve(address, own.atmo);
	post_office_attach_resolve(pid);
	postbox_lock(address);
	postbox = post_office_deassign_address(address);
	postbox_free(heap, postbox);
	postbox_unlock(address);
}

static void msg_cleanup_thread(void *arg)
{
	struct own *own = arg;
	int i;

	/* reversed execution order */
	for (i = own->exists - 1; i >= 0; i--) {
		own->thread_exit[i].func(own->thread_exit[i].user);
	}
	free(own->thread_exit);
	own->exists = 0;
	msg_exit_pid(own->heap, own->address);
}

static void *msg_thread(void *arg)
{
	struct thread_args *args = arg;
	struct postbox_address *address = args->address;

	own.post_office = post_office_get();
	own.heap = own.post_office->heap;
	own.address = address;
	own.postbox = &address->postbox->thread;
	own.postbox->id = pthread_self();
	own.pid = address->pid;
	own.ppid = address->ppid;
	own.bid = address->bid;
	own.name = own.postbox->name;
	own.trace.post_office_name = own.post_office->name;
	own.trace.postbox_name = own.postbox->name;
	own.trace.file = NULL;
	own.trace.line = 0;
	own.trace.ppid = own.ppid;
	own.trace.pid = own.pid;
	own.trace.bid = own.bid;
	own.atmo = args->atmo;
	postbox_unlock(address);
	pthread_cleanup_push(msg_cleanup_thread, &own);
	post_office_snoop_create_resolve(address, own.atmo);
	post_office_hunt_resolve(own.pid, own.name);
	own.postbox->state = MSG_STATE_RUNNING;
	own.postbox->entry();
	pthread_cleanup_pop(1);
	return NULL;
}

static struct msgh *msg_recv_hook(struct msgh *msgh, const char *file, int line)
{
	void *msg = MSG_PAYLOAD(msgh);
	msg_hook *recv_hook = own.ops.recv_hook;
	void *user = own.ops.recv_user;

	/* prevent recursive loop */
	own.ops.recv_hook = NULL;
	recv_hook(msg, user);
	own.ops.recv_hook = recv_hook;
	return msg_verify(msg, file, line);
}

static struct msgh *msg_send_hook(struct msgh *msgh, const char *file, int line)
{
	void *msg = MSG_PAYLOAD(msgh);
	msg_hook *send_hook = own.ops.send_hook;
	void *user = own.ops.send_user;

	/* prevent a recursive loop */
	own.ops.send_hook = NULL;
	send_hook(msg, user);
	own.ops.send_hook = send_hook;
	return msg_verify(msg, file, line);
}
	
static void *msg_monitor(void *arg)
{
	struct own *own = arg;
	void *reference;
	int sig;

	for (;;) {
		sig = sig_wait(&reference);
		if (sig == SIGMSGEVENT) {
			eventfd_t data = 1;
			eventfd_write(own->postbox->fd, data);
		} else if (sig == SIGMSGTMO) {
			post_office_tmo_expired(reference, own->atmo);
		} else {
			/* main thread will call exit when ready */
			pthread_detach(main_tid);
			if (pthread_cancel(main_tid))
				exit(0);
		}
	}
	return NULL;
}

static struct msg_trace *msg_get_own_trace(const char *file, int line)
{
	own.trace.file = msg_util_file_name(file);
	own.trace.line = line;
	return &own.trace;
}

static uint64_t msg_get_pid(const char *name)
{
	uint64_t pid;

	pid = post_office_get_pid(name, own.bid);
	if (!pid)
		pid = post_office_alias_pid(name, own.bid);
	return pid;
}

static void msg_kill_dynamic(struct postbox_address *address, const char *file,
			     int line)
{
	union postbox *postbox = address->postbox;
	uint64_t pid = address->pid;
	uint64_t bid = address->bid;
	pthread_t tid = postbox->thread.id;

	if (bid != own.bid)
		msg_error_zz(file, line, "invalid bid %zu", bid);
	if (own.pid != pid) {
		if (!pthread_cancel(main_tid))
			pthread_join(main_tid, NULL);
	} else {
		pthread_detach(tid);
		pthread_cancel(tid);
		pause();
	}
}

static void msg_kill_phantom(struct postbox_address *address, const char *file,
			     int line)
{
	uint64_t bid = address->bid;

	if (bid == own.bid)
		msg_exit_pid(own.heap, address);
	else
		msg_error_zz(file, line, "invalid bid %zu", bid);
}

static void msg_exit_main(void *arg)
{
	union postbox *postbox;
	struct own *own = arg;
	uint64_t pid;
	int i;

	if (!own->address)
		exit(0);
	pid = own->address->pid;
	for (i = own->exists - 1; i >= 0; i--) {
		own->thread_exit[i].func(own->thread_exit[i].user);
	}
	free(own->thread_exit);
	own->exists = 0;
	post_office_attach_clear(pid);
	post_office_hunt_clear(pid);
	post_office_tmo_clear(pid);
	post_office_alias_clear(pid);
	post_office_snoop_clear(pid);
	post_office_snoop_exit_resolve(own->address, own->atmo);
	post_office_attach_resolve(pid);
	postbox_lock(own->address);
	postbox = post_office_deassign_address(own->address);
	postbox_free(own->heap, postbox);
	postbox_unlock(own->address);
	post_office_exit(msg_exit_pid, own->bid);
	own->address = NULL;
	exit(0);
}

static void msg_main_exit(void)
{
	if (own.address) {
		error_sig("%s", __func__);
		pause();
	}
}

void msg_init_zz(const char *name, const char *domain,
		 const char *file, int line)
{
	uint8_t state = MSG_STATE_CREATED;
	union postbox *postbox;
	uint64_t rdr[1] = {0};
	int res;

	main_tid = pthread_self();
	res = post_office_connect(domain);
	if (res)
		error_err("%s:%u, %s\n", file, line, strerror(-res));
	sig_block();
	own.post_office = post_office_get();
	own.heap = own.post_office->heap;
	own.bid = post_office_new_bid();
	own.address = NULL;
	own.atmo = own.post_office->alloc_tmo;
	thread_create(msg_monitor, &own);
	thread_cleanup(msg_exit_main, &own);
	if (atexit(msg_main_exit))
		error_err("%s:%u, atexit call fails\n", file, line);
	postbox = postbox_create(own.heap, own.atmo, name, state, rdr, NULL);
	if (!postbox)
		msg_heap_exhausted(file, line);
	own.address = post_office_assign_address(postbox, 0, own.bid);
	if (!own.address) {
		postbox_free(own.post_office->heap, postbox);
		error_err("%s:%u, max number (%u) of addresses exceeded",
			  file, line, own.post_office->addresses);
	}
	own.address->ppid = own.address->pid;
	own.pid = own.address->pid;
	own.ppid = own.pid;
	own.postbox = &postbox->thread;
	own.postbox->id = pthread_self();
	own.name = own.postbox->name;
	own.trace.post_office_name = own.post_office->name;
	own.trace.postbox_name = own.postbox->name;
	own.trace.file = file;
	own.trace.line = line;
	own.trace.ppid = own.ppid;
	own.trace.pid = own.pid;
	own.trace.bid = own.bid;
	own.postbox->state = MSG_STATE_RUNNING;
	msg_trace(msg_init, msg_get_own_trace(file, line));
	post_office_snoop_create_resolve(own.address, own.atmo);
	post_office_hunt_resolve(own.pid, own.name);
	postbox_unlock(own.address);
}

void msg_atexit_zz(void (*func)(void *), void *user,
		   const char *file, int line)
{
	struct thread_exit *thread_exit;
	int i = own.exists;
	size_t size;

	size = sizeof(*thread_exit) * (i + 1);
	thread_exit = realloc(own.thread_exit, size);
	if (!thread_exit)
		msg_error_zz(file, line, "%s", strerror(errno));
	own.thread_exit = thread_exit;
	own.thread_exit[i].func = func;
	own.thread_exit[i].user = user;
	own.exists++;
}

static int verify_rdr(const struct msgrdr *rdr,
		      const char *file, int line)
{
	struct postbox_address *address;
	int i;

	for (i = 0; rdr && rdr[i].pid; i++) {
		address = post_office_lock(rdr[i].pid);
		uint8_t stat = msg_pid_type(address, rdr[i].pid);
		postbox_unlock(address);
		if (stat == MSG_POSTBOX_INVALID)
			msg_error_zz(file, line, "invalid pid %zu", rdr[i].pid);
	}
	return (2 * i) + 1;
}

static void fill_redirection(const struct msgrdr *rdr, uint64_t *redirection)
{
	int i, j;

	redirection[0] = 0;
	for (i = 0, j = 1; rdr && rdr[i].pid; i++, j += 2) {
		redirection[0]++;
		redirection[j] = rdr[i].type;
		redirection[j + 1] = rdr[i].pid;
	}
}

uint64_t msg_postbox_zz(const char *name, void (*entry)(void),
			const struct msgrdr *rdr, const char *file, int line)
{
	struct postbox_address *address;
	union postbox *postbox;
	uint64_t pid;
	int size;

	size = verify_rdr(rdr, file, line);
	uint64_t redirection[size];
	fill_redirection(rdr, redirection);
	postbox = postbox_create(own.heap, own.atmo, name,
				 MSG_STATE_CREATED, redirection, entry);
	if (!postbox)
		msg_heap_exhausted(file, line);
	address = post_office_assign_address(postbox, own.pid, own.bid);
	if (!address) {
		postbox_free(own.post_office->heap, postbox);
		error_err("%s:%u, max number (%u) of addresses exceeded",
			  file, line, own.post_office->addresses);
	}
	pid = address->pid;
	struct thread_args args = {
		.address = address,
		.atmo = own.atmo
	};
	int res = thread_create(msg_thread, &args);
	if (res) {
		postbox = post_office_deassign_address(address);
		postbox_free(own.heap, postbox);
		postbox_unlock(address);
		msg_error_zz(file, line, "%s", strerror(res));
	}
	/* Wait for the thread to release it's postbox lock */
	postbox_lock(address);
	postbox_unlock(address);
	msg_trace(msg_postbox, name, pid, redirection,
		  msg_get_own_trace(file, line));
	return pid;
}

uint64_t msg_phantom_zz(const char *name, const struct msgrdr *rdr,
			const char *file, int line)
{
	struct postbox_address *address;
	union postbox *postbox;
	uint64_t pid;
	int size;

	size = verify_rdr(rdr, file, line);
	uint64_t redirection[size];
	fill_redirection(rdr, redirection);
	postbox = postbox_phantom(own.heap, own.atmo, name, redirection);
	if (!postbox)
		msg_heap_exhausted(file, line);
	address = post_office_assign_address(postbox, own.pid, own.bid);
	if (!address) {
		postbox_free(own.post_office->heap, postbox);
		error_err("%s:%u, max number (%u) of addresses exceeded",
			  file, line, own.post_office->addresses);
	}
	pid = address->pid;
	post_office_snoop_create_resolve(address, own.atmo);
	post_office_hunt_resolve(address->pid, postbox->phantom.name);
	postbox_unlock(address);
	msg_trace(msg_phantom, name, pid, redirection,
		  msg_get_own_trace(file, line));
	return pid;
}

void msg_alias_zz(const char *name, const char *file, int line)
{
	int res;

	msg_trace(msg_alias, name, msg_get_own_trace(file, line));
	res = post_office_alias(name, own.pid, own.bid, own.atmo);
	if (!res)
		post_office_hunt_resolve(own.pid, name);
	else
		msg_heap_exhausted(file, line);
}

uint64_t msg_hunt_zz(const char *name, const char *file, int line)
{
	uint64_t pid;

	pid = msg_get_pid(name);
	msg_trace(msg_hunt, name, pid, msg_get_own_trace(file, line));
	return pid;
}

uint64_t msg_hunt_async_zz(const char *name, void *msg, uint64_t *reference,
			   const char *file, int line)
{
	struct msgh *msgh;
	uint64_t pid;

	if (msg) {
		msgh = msg_verify(msg, file, line);
		msgh_new_reference(own.heap, msgh);
	} else {
		msgh = msg_alloc_own(0, MSG_HUNT, file, line);
	}
	pid = msg_get_pid(name);
	msgh->sender = pid;
	msgh->addressee = own.pid;
	msg_trace(msg_hunt_async, msgh, name, msg_get_own_trace(file, line));
	if (reference)
		*reference = msgh->reference;
	if (msgh->sender) {
		msg_linkout_send(msgh, file, line);
	} else {
		msgh = msg_linkout_own_queue(msgh);
		msgh = post_office_hunt(msgh, name, own.atmo);
		if (msgh) {
			msgh_free(own.heap, msgh);
			msg_heap_exhausted(file, line);
		}
		pid = msg_get_pid(name);
		if (pid)
			post_office_hunt_resolve(pid, name);
	}
	pthread_testcancel();
	return pid;
}

void msg_redirect_zz(uint64_t pid, const struct msgrdr *rdr,
		     const char *file, int line)
{
	struct postbox_address *address;
	union postbox *postbox;
	int size;

	size = verify_rdr(rdr, file, line);
	uint64_t redirection[size];
	fill_redirection(rdr, redirection);
	msg_trace(msg_redirect, pid, redirection, msg_get_own_trace(file, line));
	address = post_office_lock(pid);
	uint8_t type = msg_pid_type(address, pid);
	switch (type) {
	case MSG_POSTBOX_STATIC:
	case MSG_POSTBOX_DYNAMIC:
	case MSG_POSTBOX_PHANTOM:
		postbox = address->postbox;
		if (postbox_redirect(own.heap, own.atmo, postbox, redirection)) {
			postbox_unlock(address);
			msg_heap_exhausted(file, line);
		}
		break;
	case MSG_POSTBOX_ZOOMBIE:
		break;
	default: /* MSG_POSTBOX_INVALID */
		postbox_unlock(address);
		msg_error_zz(file, line, "invalid pid %zu", pid);
		break;
	}
	if ((type == MSG_POSTBOX_PHANTOM) ||
	    (type == MSG_POSTBOX_ZOOMBIE)) {
		postbox_unlock(address);
		return;
	}
	/* check the rx queue for any redirected messages */
	struct msg_queue *rx = &postbox->thread.rx;
	struct msgh *msgh;
	int count = 0;
	msg_heap_foreach(own.heap, rx, msgh) {
		for (uint8_t i = 0; rdr[i].pid; i++) {
			if (((msgh->type == rdr[i].type) ||
			     (rdr[i].type == 0)) &&
			    (address->pid != rdr[i].pid))
				count++;
		}
	}
	if (!count) {
		postbox_unlock(address);
		return;
	}
	uint64_t rpid[count];
	struct msgh *rmsg[count];
	struct msgh *next;
	msg_heap_foreach_safe(own.heap, rx, msgh, next) {
		for (uint8_t i = 0; rdr[i].pid; i++) {
			if (((msgh->type == rdr[i].type) ||
			     (rdr[i].type == 0)) &&
			    (address->pid != rdr[i].pid)) {
				rmsg[i] = msg_heap_linkout(own.heap, rx, msgh);
				rpid[i] = rdr[i].pid;
			}
		}
	}
	/* We dont know if any message is comming back, unlock
	 * to avoid dead lock.
	 */
	postbox_unlock(address);
	for (int i = 0; i < count; i++) {
		post_office_send(rmsg[i], rpid[i], file, line);
	}
	pthread_testcancel();
}

void msg_attach_zz(uint64_t pid, void *msg, uint64_t *reference,
		   const char *file, int line)
{
	struct postbox_address *address;
	struct msgh *msgh;
	uint8_t type;

	if (msg) {
		msgh = msg_verify(msg, file, line);
		msgh_new_reference(own.heap, msgh);
	} else {
		msgh = msg_alloc_own(0, MSG_ATTACH, file, line);
	}
	msgh->sender = pid; /* attach to */
	msgh->addressee = own.pid;
	msg_trace(msg_attach, msgh, pid, msg_get_own_trace(file, line));
	if (reference)
		*reference = msgh->reference;
	msgh = msg_linkout_own_queue(msgh);
	msgh = post_office_attach(msgh, own.atmo);
	if (msgh) {
		msgh_free(own.heap, msgh);
		msg_heap_exhausted(file, line);
	}
	address = post_office_lock(pid);
	type = msg_pid_type(address, pid);
	postbox_unlock(address);
	switch (type) {
	case MSG_POSTBOX_STATIC:
	case MSG_POSTBOX_DYNAMIC:
	case MSG_POSTBOX_PHANTOM:
		break;
	case MSG_POSTBOX_ZOOMBIE:
		post_office_attach_resolve(pid);
		break;
	default: /* MSG_POSTBOX_INVALID */
		msg_error_zz(file, line, "invalid pid %zu", pid);
		break;
	}
	pthread_testcancel();
}

void msg_kill_zz(uint64_t pid, const char *file, int line)
{
	struct postbox_address *address;
	uint8_t type;

	msg_trace(msg_kill, pid, msg_get_own_trace(file, line));
	address = post_office_lock(pid);
	type = msg_pid_type(address, pid);
	postbox_unlock(address);
	switch (type) {
	case MSG_POSTBOX_DYNAMIC:
		msg_kill_dynamic(address, file, line);
		break;
	case MSG_POSTBOX_PHANTOM:
		msg_kill_phantom(address, file, line);
		break;
	case MSG_POSTBOX_ZOOMBIE:
		break;
	case MSG_POSTBOX_STATIC:
		msg_error_zz(file, line, "static postbox %zu", pid);
		break;
	default: /* MSG_POSTBOX_INVALID */
		msg_error_zz(file, line, "invalid pid %zu", pid);
		break;
	}
}

void *msg_recv_zz(const uint64_t *rx, const char *file, int line)
{
	struct msgh *msgh;
      
	msg_evenfd_read(file, line);
	postbox_state_file_line(own.postbox, MSG_STATE_RECV, file, line);
	msgh = postbox_recv(own.heap, own.address, rx);
	msg_trace(msg_recv, msgh, msg_get_own_trace(file, line));
	if (own.ops.recv_hook)
		msgh = msg_recv_hook(msgh, file, line);
	own.postbox->state = MSG_STATE_RUNNING;
	return MSG_PAYLOAD(msgh);
}

void *msg_recv_tmo_zz(const uint64_t *rx, uint32_t tmo,
		      const char *file, int line)

{
	struct msgh *msgh;
    
	msg_evenfd_read(file, line);
	postbox_state_file_line(own.postbox, MSG_STATE_RECV, file, line);
	msgh = postbox_recv_tmo(own.heap, own.address, rx, tmo);
	if (msgh) {
		msg_trace(msg_recv_tmo, msgh, tmo,
			  msg_get_own_trace(file, line));
		if (own.ops.recv_hook)
			msgh = msg_recv_hook(msgh, file, line);
		own.postbox->state = MSG_STATE_RUNNING;
		return MSG_PAYLOAD(msgh);
	}
	own.postbox->state = MSG_STATE_RUNNING;
	return NULL;
}

void *msg_recv_from_zz(const uint64_t *rx, uint64_t from,
		       uint32_t tmo, const char *file, int line)
{
	struct msgh *msgh;
      
	msg_evenfd_read(file, line);
	postbox_state_file_line(own.postbox, MSG_STATE_RECV, file, line);
	msgh = postbox_recv_from(own.heap, own.address, rx, from, tmo);
	if (msgh) {
		msg_trace(msg_recv_from, msgh, tmo, from,
			  msg_get_own_trace(file, line));
		if (own.ops.recv_hook)
			msgh = msg_recv_hook(msgh, file, line);
		own.postbox->state = MSG_STATE_RUNNING;
		return MSG_PAYLOAD(msgh);
	}
	own.postbox->state = MSG_STATE_RUNNING;
	return NULL;
}

void *msg_alloc_zz(uint64_t size, uint64_t type, const char *file, int line)
{
	struct msgh *msgh;

	msgh = msg_alloc_own(size, type, file, line);
	msg_trace(msg_alloc, msgh, msg_get_own_trace(file, line));
	return MSG_PAYLOAD(msgh);
}

void msg_send_zz(void *msg, uint64_t addressee, const char *file, int line)
{
	struct msgh *msgh;

	msgh = msg_verify(msg, file, line);
	msgh->sender = own.pid;
	msgh->addressee = addressee;
	msg_trace(msg_send, msgh, msg_get_own_trace(file, line));
	if (own.ops.send_hook)
		msgh = msg_send_hook(msgh, file, line);
	msg_linkout_send(msgh, file, line);
	pthread_testcancel();
}

void msg_sends_zz(void *msg, uint64_t to, uint64_t from,
		  const char *file, int line)
{
	struct postbox_address *address;
	struct msgh *msgh;
	uint8_t type;

	msgh = msg_verify(msg, file, line);
	msgh->sender = from;
	msgh->addressee = to;
	msg_trace(msg_sends, msgh, msg_get_own_trace(file, line));
	address = post_office_lock(from);
	type = msg_pid_type(address, from);
	postbox_unlock(address);
	if (type == MSG_POSTBOX_INVALID)
		msg_error_zz(file, line, "invalid pid from %zu", from);
	if (own.ops.send_hook)
		msgh = msg_send_hook(msgh, file, line);
	msg_linkout_send(msgh, file, line);
	pthread_testcancel();
}

void msg_free_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh;

	msgh = msg_verify(msg, file, line);
	msg_trace(msg_free, msgh, msg_get_own_trace(file, line));
	msgh = msg_linkout_own_queue(msgh);
	msgh_free(own.heap, msgh);
}

uint64_t msg_sender_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh = MSG_HEADER(msg);

	msg_trace(msg_sender, msgh, msg_get_own_trace(file, line));
	return msgh->sender;
}

uint64_t msg_addressee_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh = MSG_HEADER(msg);

	msg_trace(msg_addressee, msgh, msg_get_own_trace(file, line));
	return msgh->addressee;
}

uint64_t msg_size_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh = MSG_HEADER(msg);

	msg_trace(msg_reference, msgh, msg_get_own_trace(file, line));
	return msgh->size;
}

uint64_t msg_reference_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh = MSG_HEADER(msg);

	msg_trace(msg_reference, msgh, msg_get_own_trace(file, line));
	return msgh->reference;
}

uint64_t msg_type_zz(void *msg, const char *file, int line)
{
	struct msgh *msgh = MSG_HEADER(msg);

	msg_trace(msg_type, msgh, msg_get_own_trace(file, line));
	return msgh->type;
}

void msg_type_set_zz(void *msg, uint64_t type, const char *file, int line)
{
	struct msgh *msgh;

	msgh = msg_verify(msg, file, line);
	msg_trace(msg_type_set, msgh, type, msg_get_own_trace(file, line));
	msgh->type = type;
}

void *msg_cancel_zz(uint64_t reference, const char *file, int line)
{
	struct msgh *msgh;

	msg_trace(msg_cancel, reference, msg_get_own_trace(file, line));
	msgh = post_office_attach_cancel(reference, own.pid);
	if (msgh)
		goto out;
	msgh = post_office_hunt_cancel(reference, own.pid);
	if (msgh)
		goto out;
	/**
	 * Note! msg_tmo with interval produce messages with same reference,
	 * i.e. it's possible that the rx queue contains multiple messages
	 * with the same reference.
	 */
	msgh = post_office_tmo_cancel(reference, own.pid);
	struct msgh *rx = post_office_reference_rx_cancel(reference, own.pid);
	if (msgh) {
		if (rx)
			msgh_free(own.heap, rx);
		goto out;
	}
	if (rx) {
		msgh = rx;
		goto out;
	}
	return NULL;
out:
	return MSG_PAYLOAD(msg_append_own_queue(msgh));
}

uint64_t msg_pid_zz(const char *file, int line)
{
	msg_trace(msg_pid, msg_get_own_trace(file, line));
	return own.pid;
}

uint64_t msg_ppid_zz(const char *file, int line)
{
	msg_trace(msg_ppid, msg_get_own_trace(file, line));
	return own.ppid;
}

uint64_t msg_bid_zz(uint64_t pid, const char *file, int line)
{
	struct postbox_address *address;
	uint8_t type;
	uint64_t bid;

	msg_trace(msg_pid, msg_get_own_trace(file, line));
	if (own.pid == pid)
		return own.bid;
	address = post_office_lock(pid);
	type = msg_pid_type(address, pid);
	bid = address->bid;
	postbox_unlock(address);
	switch (type) {
	case MSG_POSTBOX_STATIC:
	case MSG_POSTBOX_DYNAMIC:
	case MSG_POSTBOX_PHANTOM:
		break;
	case MSG_POSTBOX_ZOOMBIE:
		bid = 0;
		break;
	default: /* MSG_POSTBOX_INVALID */
		msg_error_zz(file, line, "invalid pid %zu", pid);
		break;
	}
	return bid;
}

struct msgpbi *msg_pbi_zz(uint64_t pid, const char *file, int line)
{
	struct postbox_address *address;
	uint64_t bid = 0;
	uint64_t ppid = 0;
	char *name = NULL;

	msg_trace(msg_pbi, pid, msg_get_own_trace(file, line));
	address = post_office_lock(pid);
	uint8_t type = msg_pid_type(address, pid);
	switch (type) {
	case MSG_POSTBOX_STATIC:
	case MSG_POSTBOX_DYNAMIC:
		name = address->postbox->thread.name;
		ppid = address->ppid;
		bid = address->bid;
		break;
	case MSG_POSTBOX_PHANTOM:
		name = address->postbox->phantom.name;
		ppid = address->ppid;
		bid = address->bid;
		break;
	case MSG_POSTBOX_ZOOMBIE:
		break;
	default: /* MSG_POSTBOX_INVALID */
		break;
	}
	size_t len = name ? strlen(name) : 0;
	struct msgpbi *pbi = malloc(sizeof(*pbi) + len);
	if (pbi) {
		pbi->type = type;
		pbi->ppid = ppid;
		pbi->pid = pid;
		pbi->bid = bid;
		name = memcpy(pbi->name, name, len + 1);
		postbox_unlock(address);
	} else {
		postbox_unlock(address);
		msg_error_zz(file, line, "%s", strerror(errno));
	}
	return pbi;
}

int msg_open_fd_zz(const char *file, int line)
{
	msg_trace(msg_open_fd, msg_get_own_trace(file, line));
	own.postbox->fd = eventfd(0, EFD_NONBLOCK | EFD_SEMAPHORE);
	if (own.postbox->fd == -1)
		msg_error_zz(file, line, "%s", strerror(errno));
	return own.postbox->fd;
}

void msg_close_fd_zz(const char *file, int line)
{
	msg_trace(msg_close_fd, msg_get_own_trace(file, line));
	if ((own.postbox->fd != -1) && close(own.postbox->fd))
		msg_error_zz(file, line, "%s", strerror(errno));
	own.postbox->fd = -1;
}

void msg_atmo_set_zz(uint32_t msec, const char *file, int line)
{
	msg_trace(msg_atmo_set, msec, msg_get_own_trace(file, line));
	own.atmo = msec;
}

void msg_tmo_zz(void *msg, long msec, long interval_msec,
		uint64_t *reference, const char *file, int line)
{
	struct msgh *msgh;
	timer_t timerid;
	int res;

	if (msg) {
		msgh = msg_verify(msg, file, line);
		msgh_new_reference(own.heap, msgh);
	} else {
		msgh = msg_alloc_own(0, MSG_TMO, file, line);
	}
	msgh->sender = own.pid;
	msgh->addressee = own.pid;
	if (reference)
		*reference = msgh->reference;
	msg_trace(msg_tmo, msgh, msec, interval_msec,
		  msg_get_own_trace(file, line));
	res = sig_timer_create(msgh, msec, interval_msec, SIGMSGTMO, &timerid);
	if (res)
		msg_error_zz(file, line, "%s", strerror(-res));
	msgh = msg_linkout_own_queue(msgh);
	msgh = post_office_tmo(msgh, timerid, own.atmo);
	if (msgh) {
		msgh_free(own.heap, msgh);
		msg_heap_exhausted(file, line);
	}
}

void msg_delay_zz(uint32_t msec, const char *file, int line)
{
	msg_trace(msg_delay, msec, msg_get_own_trace(file, line));
	postbox_state_file_line(own.postbox, MSG_STATE_DELAY, file, line);
	time_delay(msec);
	own.postbox->state = MSG_STATE_RUNNING;
}

void msg_exit_zz(const char *file, int line, const char *fmt, ...)
{
	char reason[256];
	va_list args;
	const char *name;

	name = msg_util_file_name(file);
	va_start(args, fmt);
	vsnprintf(reason, sizeof(reason), fmt, args);
	va_end(args);
	error_exit("msg_exit, %s:%u, %s", name, line, reason);
}

void msg_error_zz(const char *file, int line, const char *fmt, ...)
{
	char reason[256];
	va_list args;
	const char *name;

	name = msg_util_file_name(file);
	va_start(args, fmt);
	vsnprintf(reason, sizeof(reason), fmt, args);
	va_end(args);
	error_err("msg_error, %s:%u, %s", name, line, reason);
}

void msg_hook_recv_zz(msg_hook *hook, void *user, const char *file, int line)
{
	msg_trace(msg_hook_recv, msg_get_own_trace(file, line));
	own.ops.recv_hook = hook;
	own.ops.recv_user = user;
}

void msg_hook_send_zz(msg_hook *hook, void *user, const char *file, int line)
{
	msg_trace(msg_hook_send, msg_get_own_trace(file, line));
	own.ops.send_hook = hook;
	own.ops.send_user = user;
}

void msg_snoop_zz(uint32_t event, const char *file, int line)
{
	uint64_t pid = own.pid;

	msg_trace(msg_snoop, event, msg_get_own_trace(file, line));
	switch (event) {
	case MSG_EVENT_SNOOP_UNRESOLVED_HUNT:
		post_office_hunt_snoop(pid, own.atmo);
		break;
	case MSG_EVENT_SNOOP_POSTBOX:
		post_office_snoop_postbox(pid, own.atmo);
		break;
	case MSG_EVENT_SNOOP_OFF:
		post_office_snoop_clear(pid);
		post_office_msg_rx_clear(MSG_EVENT_SNOOP_UNRESOLVED_HUNT, pid);
		post_office_msg_rx_clear(MSG_EVENT_SNOOP_POSTBOX, pid);
		break;
	default:
		msg_error_zz(file, line, "invalid snoop event %u", event);
		break;
	}
}
