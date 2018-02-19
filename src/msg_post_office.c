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

#include <msg_post_office.h>
#include <msg_error.h>
#include <msg_sig.h>
#include <msgh.h>
#include <msg.h>
#include <sys/param.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>

#define MSG_BITSIZEOF(x) (CHAR_BIT * sizeof(x))
#define MSG_ADDR_INDEX(p,pid) (p->index_mask & (pid))
#define MSG_ADDRESS(p,i) (&p->postbox_map[(i)])
#define MSG_PID_SEQ(pid) (pid >> post_office->rank)

static struct post_office *post_office = MAP_FAILED;

static struct msg_snoop_postbox *
post_office_postbox_info(struct postbox_address *address)
{
	struct msg_snoop_postbox *pbi;
	uint8_t type;
	char *name;
	size_t len;

	if (address->postbox->box.type == POSTBOX_TYPE_THREAD) {
		name = address->postbox->thread.name;
		type = (address->ppid != address->pid) ?
			MSG_POSTBOX_DYNAMIC : MSG_POSTBOX_STATIC;
	} else {
		name = address->postbox->phantom.name;
		type = MSG_POSTBOX_PHANTOM;
	}
	len = name ? strlen(name) : 0;
	pbi = malloc(sizeof(*pbi) + len);
	if (pbi) {
		pbi->type = type;
		pbi->ppid = address->ppid;
		pbi->pid = address->pid;
		pbi->bid = address->bid;
		memcpy(pbi->name, name, len + 1);
	} else {
		error_sig("%s", strerror(errno));
	}
	return pbi;
}

static void send_msg_snoop_address(const struct post_office_snoop *snoop,
				   const struct msg_snoop_postbox *info,
				   uint32_t tmo)
{
	struct msgh *msgh;
	size_t size;
 
	size = sizeof(*info) + strlen(info->name);
	msgh = msgh_alloc(post_office->heap, tmo, size, MSG_SNOOP_POSTBOX);
	if (msgh) {		
		msgh->sender = info->pid;
		msgh->addressee = snoop->pid;
		memcpy(MSG_PAYLOAD(msgh), info, size);
		post_office_send(msgh, msgh->addressee, __FILE__, __LINE__);
	} else {
		error_sig("%s:%d, %s", __FILE__, __LINE__, "heap exhausted");
	}
}

static int create_post_office_name(char *name, int size, const char *domain)
{
	char buf[size];
	int res = 0;

	if (domain) {
		int bytes = snprintf(buf, size, "%s", domain);
		if (bytes >= size)
			res = EINVAL;
	} else {
		res = gethostname(buf, size);
	}
	memcpy(name, buf, size);
	return -res;
}

static int create_shm_name(char *name, int size, const char *domain)
{
	char buf[size];
	int bytes;
	int res;

	res = create_post_office_name(buf, size, domain);
	if (res)
		return res;
	bytes = snprintf(name, size, "/msg-%s", buf);
	if (bytes >= size)
		res = -EINVAL;
	return res;
}

static uint32_t most_significant_bit_pos(uint32_t addresses)
{
	uint32_t bits = MSG_BITSIZEOF(addresses);
	uint32_t pos;

	for (pos = 0; pos < bits; pos++) {
		if (!(addresses >> pos))
			break;
	}
	return pos;
}

static uint64_t post_office_new_pid(uint64_t pid)
{
	uint64_t seq = MSG_PID_SEQ(pid);
	uint64_t index = MSG_ADDR_INDEX(post_office, pid);
	return ((seq + 1) << post_office->rank) | index;
}

static uint32_t align_addresses(uint32_t addresses)
{
	uint32_t i = 0;
	
	for (--addresses; addresses > 0; addresses >>= 1) {
		i++;
	}
	return 1 << i;
}

static struct postbox_address *lock_free_address(uint32_t index)
{
	struct postbox_address *address;

	address = MSG_ADDRESS(post_office, index);
	if (!address->postbox) {
		postbox_lock(address);
		if (!address->postbox)
			return address;  /* locked */
		postbox_unlock(address);
	}
	return NULL;
}

static struct postbox_address *lock_used_address(uint32_t index)
{
	struct postbox_address *address;

	address = MSG_ADDRESS(post_office, index);
	if (address->postbox) {
		postbox_lock(address);
		if (address->postbox)
			return address;  /* locked */
		postbox_unlock(address);
	}
	return NULL;
}

struct postbox_address *post_office_lock(uint64_t pid)
{
	struct postbox_address *address;

	address = MSG_ADDRESS(post_office, MSG_ADDR_INDEX(post_office, pid));
	postbox_lock(address);
	return address;
}

static void post_office_mutex_init(struct post_office *post_office)
{
#define mutex_init(mutex)			\
	lock_mutex_init(&post_office->mutex)
	mutex_init(lock_attach);
	mutex_init(lock_hunt);
	mutex_init(lock_alias);
	mutex_init(lock_tmo);
	mutex_init(lock_snoop);
}

int post_office_open(const char *domain)
{
	struct post_office_mem mem;
	char name[NAME_MAX];
	int res = 0;
	int fd = -1;
	
	res = create_shm_name(name, sizeof(name), domain);
	if (res)
		goto out;
	do { /* wait for post office to open */
		fd = shm_open(name, O_RDWR, 0);
	} while ((fd == -1) && (errno == EACCES) && !usleep(100000));
	if (fd == -1) {
		res = -errno;
		goto out;
	}
	if (read(fd, &mem, sizeof(mem)) == -1) {
		res = -errno;
		goto out;
	}
	if (mem.magic != POST_OFFICE_MAGIC) {
	  	res = -EFAULT;
		goto out;
	}
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_SHARED | MAP_FIXED;
	post_office = mmap(mem.addr, mem.size, prot, flags, fd, 0);
	if (post_office == MAP_FAILED)
		res = -errno;
out:
	if (fd != -1)
		close(fd);
	return res;
}

int post_office_close(struct post_office *post_office)
{
	int res;

	res = munmap(post_office->mem.addr, post_office->mem.size);
	return res ? -errno : 0;
}

int post_office_create(const char *domain, uint32_t size, uint32_t addresses)
{
	struct postbox_address *address;
	char name[NAME_MAX];
	uint32_t rank;
	uint32_t i;
	void *heap;
	size_t length;
	int res;
	int fd = -1;

	addresses = align_addresses(addresses);
	rank = most_significant_bit_pos(addresses);
	res = create_shm_name(name, sizeof(name), domain);
	if (res)
		goto create_failure;
	int oflags = O_RDWR | O_CREAT | O_EXCL;
	fd = shm_open(name, oflags, 0); /* give access when ready */
	if (fd == -1) {
		res = -errno;
		/* post office is open or is about to open */
		if ((res == -EEXIST) || (res == -EACCES))
			goto already_exists;
		else
			goto create_failure;
	}
	length = sizeof(*post_office);
	length += sizeof(post_office->postbox_map[0]) *
		(addresses ? addresses - 1 : 0);
	length += (size_t)size;
	res = ftruncate(fd, (off_t)length);
	if (res == -1) {
		res = -errno;
		goto create_failure;
	}	
	int prot = PROT_READ | PROT_WRITE;
	int flags = MAP_SHARED;
	post_office = mmap(NULL, length, prot, flags, fd, 0);
	if (post_office == MAP_FAILED) {
		res = -errno;
		goto create_failure;
	}
	res = create_post_office_name(post_office->name,
				      sizeof(post_office->name), domain);
	if (res)
		goto create_failure;
	heap = &post_office->postbox_map[addresses];
	post_office->heap = msg_heap_create(size, heap);
	post_office->mem.magic = POST_OFFICE_MAGIC;
	post_office->mem.addr = post_office;
	post_office->mem.size = length;
	post_office->addresses = addresses;
	post_office->alloc_tmo = 1000;
	atomic_init(&post_office->bid, 1);
	atomic_init(&post_office->index, 0);
	atomic_init(&post_office->postboxes[0], 0); /* current */
	atomic_init(&post_office->postboxes[1], 0); /* peak */
	post_office->rank = rank;
	post_office->index_mask = ~(UINT64_MAX << (rank - 1));
	for (i = 0; i < post_office->addresses; i++) {
		address = &post_office->postbox_map[i];
		lock_init(&address->lock);
		address->pid = post_office_new_pid(i);
		address->bid = 0;
		address->postbox = NULL;
	}
	msg_heap_queue(heap, &post_office->attach);
	msg_heap_queue(heap, &post_office->hunt);
        msg_heap_queue(heap, &post_office->alias);
        msg_heap_queue(heap, &post_office->tmo);
        msg_heap_queue(heap, &post_office->snoop);
	post_office_mutex_init(post_office);
	/* Open the post office */
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	res = fchmod(fd, mode);
	if (res) {
		res = -errno;
		goto create_failure;
	}
	close(fd);
	return 0;
already_exists:
	return -EEXIST;
create_failure:
	if (fd) {
		close(fd);
		shm_unlink(name);
	}
	return res;
}

int post_office_connect(const char *domain)
{
	static char name[NAME_MAX];
	int res;

	if (post_office != MAP_FAILED)
		return -EEXIST;
	res = create_post_office_name(name, sizeof(name), domain);
	if (res)
		return res;
	openlog(name, LOG_PID, LOG_USER);
	res = post_office_open(name);
	return res;
}

int post_office_delete(const char *domain)
{
	struct postbox_address *address;
	char name[NAME_MAX];
	uint32_t i;
	int res;

	res = create_shm_name(name, sizeof(name), domain);
	if (res)
		return res;
	for (i = 0; i < post_office->addresses; i++) {
		address = lock_used_address(i);
		if (address) {
			postbox_unlock(address);
			return -EBUSY;
		}
	}
	if (shm_unlink(name))
		return -errno;
	return 0;
}

struct post_office *post_office_get(void)
{
	return post_office;
}

void post_office_send(struct msgh *msgh, uint64_t addressee,
		      const char *file, int line)
{
  	static const char fmt[] = "%s:%d, invalid pid %zu";
	struct msg_heap *heap = post_office->heap;

	for (;; ) {
		struct postbox_address *address;
		union postbox *postbox;
		address = post_office_lock(addressee);
		postbox = address->postbox;
		if (!postbox) {
			uint8_t status;
			status = post_office_pid_status(address, addressee);
			postbox_unlock(address);
			msgh_free(heap, msgh);
			if (status == POST_OFFICE_PID_INVALID)
				error_sig(fmt, file, line, addressee);
			break;
		}
		uint64_t pid = postbox_redirect_pid(postbox, msgh->type);
		if ((pid == 0) || /* no redirection */
		    (pid == address->pid)) { /* own redirection */
			if (postbox->box.type == POSTBOX_TYPE_THREAD) {
				msg_heap_append(heap, &postbox->thread.rx,
						msgh);
				postbox_signal(address);	
			} else { /* phantom without redirection */
				msgh_free(heap, msgh);
			}
			postbox_unlock(address);
			break;
		}
		if (pid == msgh->addressee) { /* circular redirection */
		  	postbox_unlock(address);
			msgh_free(heap, msgh);
			break;
		}
		/* we have a new addressee */
		addressee = pid;
		postbox_unlock(address);
	}
}

static void set_current_peak_postboxes(void)
{
	atomic_uint_least32_t *postboxes = post_office->postboxes;
	memory_order order = memory_order_relaxed;
	uint32_t current;
	uint32_t peak;

	current = atomic_fetch_add_explicit(&postboxes[0], 1, order) + 1;
	peak = atomic_load_explicit(&postboxes[1], order);
	if (current > peak)
		atomic_store_explicit(&postboxes[1], current, order);

}

static struct postbox_address *try_assign_address(union postbox *postbox,
						  uint64_t ppid, uint64_t bid,
						  uint32_t index)
{
	struct postbox_address *address;

	address = lock_free_address(index);
	if (address) {
		address->postbox = postbox;
		address->ppid = ppid;
		address->bid = bid;
		atomic_store(&post_office->index, index + 1);
		set_current_peak_postboxes();
	}
	return address;
}

struct postbox_address *post_office_assign_address(union postbox *postbox,
						   uint64_t ppid, uint64_t bid)
{
	struct postbox_address *address = NULL;
	uint32_t index;
	uint32_t i;

	lock_mutex_lock(&post_office->lock_snoop);
	index = atomic_load(&post_office->index);
	for (i = index; i < post_office->addresses; i++) {
		address = try_assign_address(postbox, ppid, bid, i);
		if (address)
			goto out;
	}
	/* wrap around */
	for (i = 0; i < index; i++) {
		address = try_assign_address(postbox, ppid, bid, i);
		if (address)
			goto out;
	}
out:
	lock_mutex_unlock(&post_office->lock_snoop);
	return address;
}

union postbox *post_office_deassign_address(struct postbox_address *address)
{
	union postbox *postbox = address->postbox;
	memory_order order = memory_order_relaxed;

	address->pid = post_office_new_pid(address->pid);
	address->bid = 0;
	address->ppid = 0;
	address->postbox = NULL;
	atomic_fetch_sub_explicit(&post_office->postboxes[0], 1, order);
	return postbox;
}

uint64_t post_office_new_bid(void)
{
	memory_order order = memory_order_relaxed;

	return atomic_fetch_add_explicit(&post_office->bid, 1, order);
}

uint64_t post_office_get_pid(const char *name, uint64_t bid)
{
	struct postbox_address *address;
	union postbox *postbox;
	char *postbox_name;
	uint64_t pid = 0;
	uint32_t i;

	for (i = 0; i < post_office->addresses; i++) {
		address = lock_used_address(i);
		if (!address)
			continue;
		postbox = address->postbox;
		postbox_name = (postbox->box.type == POSTBOX_TYPE_THREAD) ?
			postbox->thread.name : postbox->phantom.name;
		if (!strcmp(postbox_name, name)) {
			pid = address->pid;
			if (address->bid == bid) {
				postbox_unlock(address);
				break;
			}
		}
		postbox_unlock(address);
	}
	return pid;
}

void post_office_exit(void (*exit_func)(struct msg_heap *heap,
					struct postbox_address *),
		      uint64_t bid)
{
	struct postbox_address *address;
	uint32_t count;
	uint32_t i;

	do {
		count = 0;
		for (i = 0; i < post_office->addresses; i++) {
			address = lock_used_address(i);
			if (!address)
				continue;
			if (address->bid != bid) {
				postbox_unlock(address);
				continue;
			}
			if (address->postbox->box.type == POSTBOX_TYPE_THREAD) {
				pthread_t id = address->postbox->thread.id;
				postbox_unlock(address);
				if (!pthread_cancel(id))
					pthread_join(id, NULL);
			} else {
				postbox_unlock(address);
				exit_func(post_office->heap, address);
			}
			count++;
		}
	} while (count);
}

void post_office_foreach_postbox(postbox_func *func, void *user)
{
	struct postbox_address *address;
	union postbox_info *info;
	volatile uint32_t i;
	int res;

	for (i = 0; i < post_office->addresses; i++) {
		address = lock_used_address(i);
		if (address) {
			info = postbox_get_info(address);
			postbox_unlock(address);
			if (info) {
				pthread_cleanup_push(free, info);
				res = func(info, user);
				pthread_cleanup_pop(1);
				if (res)
					break;
			}
		}
	}
}

uint8_t post_office_pid_status(struct postbox_address *address, uint64_t pid)
{
	if (address->pid == pid)
		return POST_OFFICE_PID_VALID;
	if (MSG_PID_SEQ(pid) < MSG_PID_SEQ(address->pid) &&
	    MSG_PID_SEQ(pid) > 0)
		return POST_OFFICE_PID_ZOOMBIE;
	return POST_OFFICE_PID_INVALID;
}

struct msgh *post_office_reference_rx_cancel(uint64_t reference, uint64_t pid)
{
	struct msg_heap *heap = post_office->heap;
	struct postbox_address *address;
	union postbox *postbox;
	struct msgh *msgh = NULL;

	/**
	 * Note! msg_tmo with interval produce messages with same reference,
	 * i.e. it's possible that the rx queue contains multiple messages
	 * with the same reference.
	 */
	address = post_office_lock(pid);
	postbox = address->postbox;
	if (postbox && (postbox->box.type == POSTBOX_TYPE_THREAD)) {
		struct msg_queue *rx  = &postbox->thread.rx;
		struct msgh *iter;
		struct msgh *next;
		msg_heap_foreach_safe(heap, rx, iter, next) {
			if (iter->reference == reference) {
				iter = msg_heap_linkout(heap, rx, iter);
				if (!msgh)
					msgh = iter; /* keep one of them */
				else
					msgh_free(heap, iter);
			}
		}
	}
	postbox_unlock(address);
	return msgh;
}

void post_office_msg_rx_clear(uint64_t type, uint64_t pid)
{
	struct msg_heap *heap = post_office->heap;
	struct postbox_address *address;
	union postbox *postbox;
	struct msgh *msgh;
	struct msgh *next;

	address = post_office_lock(pid);
	postbox = address->postbox;
	if (postbox && (postbox->box.type == POSTBOX_TYPE_THREAD)) {
		struct msg_queue *rx = &postbox->thread.rx;
		msg_heap_foreach_safe(heap, rx, msgh, next) {
			if (msgh->type == type) {
				msgh = msg_heap_linkout(heap, rx, msgh);
				msgh_free(heap, msgh);
			}
		}
	}
	postbox_unlock(address);
}

void post_office_snoop_clear(uint64_t pid)
{
	struct post_office_snoop *snoop;

	lock_mutex_lock(&post_office->lock_snoop);
	msg_heap_foreach(post_office->heap, &post_office->snoop, snoop) {
		if (snoop->pid == pid) {
			snoop = msg_heap_linkout(post_office->heap,
					     &post_office->snoop, snoop);
			msg_heap_free(post_office->heap, snoop);
			break;
		}
	}
	lock_mutex_unlock(&post_office->lock_snoop);
}

void post_office_snoop_create_resolve(struct postbox_address *address,
				      uint32_t tmo)
{
	struct post_office_snoop *snoop;
	struct msg_snoop_postbox *info;

	info = post_office_postbox_info(address);
	if (info) {
		lock_mutex_lock(&post_office->lock_snoop);
		msg_heap_foreach(post_office->heap, &post_office->snoop,
				 snoop) {
			send_msg_snoop_address(snoop, info, tmo);
		}
		lock_mutex_unlock(&post_office->lock_snoop);
		free(info);
	}
}

void post_office_snoop_exit_resolve(struct postbox_address *address,
				    uint32_t tmo)
{
	struct post_office_snoop *snoop;
	struct msg_snoop_postbox *info;
	uint8_t event;

	info = post_office_postbox_info(address);
	if (info) {
		info->type = MSG_POSTBOX_ZOOMBIE;
		lock_mutex_lock(&post_office->lock_snoop);
		msg_heap_foreach(post_office->heap, &post_office->snoop,
				 snoop) {
			event = POST_OFFICE_SNOOP_POSTBOX;
			if (POST_OFFICE_SNOOP_EVENT(event, snoop->event))
				send_msg_snoop_address(snoop, info, tmo);
		}
		lock_mutex_unlock(&post_office->lock_snoop);
		free(info);
	}
}

void post_office_snoop_postbox(uint64_t pid, uint32_t tmo)
{
	pthread_mutex_t *lock = &post_office->lock_snoop;
	struct msg_heap *heap = post_office->heap;
	struct msg_queue *queue = &post_office->snoop;
	struct post_office_snoop *snoop;
	struct postbox_address *address;
	struct msg_snoop_postbox *info;
	uint32_t i;

	lock_mutex_lock(lock);
	msg_heap_foreach(heap, queue, snoop) {
		if (snoop->pid == pid)
			break;
	}
	if (!snoop) {
		snoop = msg_heap_alloc(heap, tmo, sizeof(*snoop), NULL);
		if (!snoop) {
			lock_mutex_unlock(lock);
			error_sig("%s:%d, %s", __FILE__, __LINE__,
				  "heap exhausted");
			return;
		}
		snoop->pid = pid;
		snoop->event = 0;
		msg_heap_append(heap, queue, snoop);
	}
	MSG_BIT_OP(MSG_BIT_SET, POST_OFFICE_SNOOP_POSTBOX, snoop->event);
	for (i = 0; i < post_office->addresses; i++) {
		address = lock_used_address(i);
		if (!address)
			continue;
		if ((address->postbox->box.type == POSTBOX_TYPE_THREAD) &&
		    (address->postbox->thread.state == MSG_STATE_CREATED)) {
			postbox_unlock(address);
			continue;
		}
		info = post_office_postbox_info(address);
		postbox_unlock(address);
		if (info) {
			send_msg_snoop_address(snoop, info, tmo);
			free(info);
		}
	}
	lock_mutex_unlock(lock);
}
