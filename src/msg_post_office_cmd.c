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

#include <msg_post_office_cmd.h>
#include <msg_post_office_hunt.h>
#include <msg_post_office.h>
#include <msg_postbox.h>
#include <msg_tprint.h>
#include <msg_sig.h>
#include <msg.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <limits.h>
#include <pthread.h>
#include <errno.h>

#define RATIO_PERCENT(x, y) ((float)(x * 100) / (float)y)

static struct post_office *post_office;

static char *info_state_str(const struct postbox_thread_info *info)
{
        switch (info->state) {
        case MSG_STATE_CREATED:
                return "created";
        case MSG_STATE_RUNNING:
                return "running";
        case MSG_STATE_RECV:
                return "receive";
        case MSG_STATE_DELAY:
                return "delay";
        default:
                break;
        }
        return "-";
}

static void open_post_office(const char *name)
{
        int res;

        res = post_office_open(name);
        if (res < 0) {
                printf("%s\n", strerror(-res));
                exit(0);
        }
        post_office = post_office_get();
}

static void close_post_office(const char *name)
{
        int res;

        res = post_office_close(post_office);
        if (res < 0)
                printf("%s, %s\n", name, strerror(-res));
}

static int print_postbox_info(const union postbox_info *info, void *user)
{
        struct msg_tprint *tprint = user;
        char *state;

        if (info->type == POSTBOX_TYPE_PHANTOM) {
                msg_tprint_row(tprint, "%zur%zur%zur%%%%%%%%%%%s",
			       info->phantom.pid,
			       info->phantom.ppid,
			       info->phantom.bid,
			       info->phantom.name);
                return 0;
        }
        state = info_state_str(&info->thread);
        switch (info->thread.state) {
        case MSG_STATE_CREATED:
                msg_tprint_row(tprint, "%zur%zur%zur%zur%zur%zur%zur%s%s",
			       info->thread.pid,
			       info->thread.ppid,
			       info->thread.bid,
			       info->thread.rx_count,
			       info->thread.rx_bytes,
			       info->thread.tx_count,
			       info->thread.tx_bytes,
			       state,
			       info->thread.name);
                break;
        case MSG_STATE_RECV:
        case MSG_STATE_DELAY: {
                int len = snprintf(NULL, 0, "%s:%d", info->thread.file,
                                   info->thread.line);
                char location[len + 1];
                snprintf(location, len + 1, "%s:%d", info->thread.file,
                         info->thread.line);
                msg_tprint_row(tprint, "%zur%zur%zur%zur%zur%zur%zur%s%s%s",
			       info->thread.pid,
			       info->thread.ppid,
			       info->thread.bid,
			       info->thread.rx_count,
			       info->thread.rx_bytes,
			       info->thread.tx_count,
			       info->thread.tx_bytes,
			       state,
			       info->thread.name,
			       location);
        }
		break;
        default: /* MSG_STATE_RUNNING */
                msg_tprint_row(tprint, "%zur%zur%zur%zur%zur%zur%zur%s%s",
			       info->thread.pid,
			       info->thread.ppid,
			       info->thread.bid,
			       info->thread.rx_count,
			       info->thread.rx_bytes,
			       info->thread.tx_count,
			       info->thread.tx_bytes,
			       state,
			       info->thread.name);
                break;
        }
        return 0;
}

static int print_hunt_info(const struct post_office_hunt_info *info, void *user)
{
        struct msg_tprint *tprint = user;

        msg_tprint_row(tprint, "%zur%s", info->msgh->addressee, info->name);
        return 0;
}

void post_office_cmd_domain_create(const char *name, uint32_t size,
                                   uint32_t addresses)
{
        int res;

        res = post_office_create(name, size, addresses);
        if (res < 0)
                printf("%s\n", strerror(-res));
        else
                post_office_cmd_domain_info(name);
}

void post_office_cmd_domain_delete(const char *name)
{
        int res;

        open_post_office(name);
        res = post_office_delete(name);
        printf("%s\n", strerror(-res));
        close_post_office(name);
}

void post_office_cmd_domain_info(const char *name)
{
        struct msg_heap_info heap;
        atomic_uint_least32_t *postboxes;

        open_post_office(name);
        msg_heap_get_info(post_office->heap, &heap);
        postboxes = post_office->postboxes;
        printf("domain         : %s\n"
               "addresses      : %u\n"
               "postboxes      : %u (peak %u)\n"
               "heap size      : %u\n"
               "heap used      : %u\n"
               "heap peak      : %u\n"
               "heap alloc     : %zu\n"
               "heap free      : %zu\n"
               "heap alloc tmo : %zu (ratio %0.3f%%)\n",
               post_office->name, post_office->addresses,
               atomic_load_explicit(&postboxes[0], memory_order_relaxed),
               atomic_load_explicit(&postboxes[1], memory_order_relaxed),
               heap.size, heap.used, heap.peak, heap.allocation,
               heap.deallocation,
               heap.tmo_counter,
	       heap.allocation ?
	       RATIO_PERCENT(heap.tmo_counter, heap.allocation) : 0);
        close_post_office(name);
}

void post_office_cmd_postbox_info(const char *name)
{
        struct msg_tprint *tprint;

        open_post_office(name);
        msg_tprint_init(&tprint, '|');
        msg_tprint_sep(tprint, '-', '-');
        msg_tprint_str(tprint, "%sc", name);
        msg_tprint_sep(tprint, '-', '-');
        msg_tprint_row(tprint, "%sc%sc%sc%sc%sc%sc%sc%sc%sc%sc",
		       "pid", "ppid", "bid", "RX packets", "RX bytes",
		       "TX packets", "TX bytes", "state", "name",
		       "file:line");
        msg_tprint_sep(tprint, '-', '+');
        post_office_foreach_postbox(print_postbox_info, tprint);
        close_post_office(name);
        msg_tprint_sep(tprint, '-', '-');
        msg_tprint_do(tprint, stdout);
        msg_tprint_exit(tprint);
}

void post_office_cmd_unresolved_hunt_info(const char *name)
{
        struct msg_tprint *tprint;

        open_post_office(name);
        msg_tprint_init(&tprint, '|');
        msg_tprint_sep(tprint, '-', '-');
        msg_tprint_str(tprint, "%sc", name);
	msg_tprint_sep(tprint, '-', '-');
        msg_tprint_row(tprint, "%sc%sc", "pid", "unresolved hunt");
        msg_tprint_sep(tprint, '-', '+');
        post_office_hunt_foreach(print_hunt_info, tprint);
        close_post_office(name);
        msg_tprint_sep(tprint, '-', '-');
        msg_tprint_do(tprint, stdout);
        msg_tprint_exit(tprint);
}
