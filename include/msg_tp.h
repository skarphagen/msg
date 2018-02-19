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

#ifndef MSG_TRACE_PROVIDER
#error "MSG_TRACE_PROVIDER not defined"
#else
#define MSG_TP_PROVIDER(p) p
#define TRACEPOINT_PROVIDER MSG_TP_PROVIDER(MSG_TRACE_PROVIDER)
#define TRACEPOINT_INCLUDE "msg_tp.h"
#endif

#if !defined(MSG_TP_H) || defined(TRACEPOINT_HEADER_MULTI_READ)
#define MSG_TP_H

#include <lttng/tracepoint.h>

#define MSG_HEADER_FIELDS(msgh) \
	ctf_integer(uint64_t, type, msgh->type) \
	ctf_integer(uint64_t, size, msgh->size) \
	ctf_integer(uint64_t, sender, msgh->sender) \
	ctf_integer(uint64_t, owner, msgh->owner) \
	ctf_integer(uint64_t, addressee, msgh->addressee) \
	ctf_integer(uint64_t, reference, msgh->reference)

#define MSG_TRACE_FIELDS(trace) \
	ctf_string(file, trace->file) \
	ctf_integer(int, line, trace->line) \
	ctf_string(postbox, trace->postbox_name) \
	ctf_integer(uint64_t, pid, trace->pid) \
	ctf_integer(uint64_t, ppid, trace->ppid) \
	ctf_integer(uint64_t, bid, trace->bid) \
	ctf_string(domain, trace->post_office_name)

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_domain_connect,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(ctf_string(file, trace->file)
			   ctf_integer(int, line, trace->line)
			   ctf_string(domain, trace->post_office_name)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_init,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_postbox,
		 TP_ARGS(const char *, name,
			 uint64_t, pid,
			 const uint64_t *, rd,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_string(name, name)
			   ctf_integer(uint64_t, pid, pid)
			   ctf_sequence(uint64_t, rd, rd,
					uint64_t, POSTBOX_RDR_LEN(rd))))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_phantom,
		 TP_ARGS(const char *, name,
			 uint64_t, pid,
			 const uint64_t *, rd,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_string(name, name)
			   ctf_integer(uint64_t, pid, pid)
			   ctf_sequence(uint64_t, rd, rd,
					uint64_t, POSTBOX_RDR_LEN(rd))))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_start,
		 TP_ARGS(int64_t, pid,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, pid, pid)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_kill,
		 TP_ARGS(uint64_t, pid,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, pid, pid)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_alias,
		 TP_ARGS(const char *, name,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_string(name, name)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_alloc,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_free,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_hunt,
		 TP_ARGS(const char *, name,
			 uint64_t, pid,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_string(name, name)
			   ctf_integer(uint64_t, pid, pid)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_hunt_async,
		 TP_ARGS(const struct msgh *, msgh,
			 const char *, name,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_string(name, name)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_cancel,
		 TP_ARGS(uint64_t, reference,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, reference, reference)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_attach,
		 TP_ARGS(const struct msgh *, msgh,
			 uint64_t, pid,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, pid, pid)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_send,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT (MSG_TRACE_PROVIDER,
		  msg_sends,
		  TP_ARGS(const struct msgh *, msgh,
			  const struct msg_trace *, trace),
		  TP_FIELDS(MSG_TRACE_FIELDS(trace)
			    MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_recv,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_recv_tmo,
		 TP_ARGS(const struct msgh *, msgh,
			 long, tmo,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(long, tmo, tmo)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_recv_from,
		 TP_ARGS(const struct msgh *, msgh,
			 long, tmo,
			 uint64_t, from,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(long, tmo, tmo)
			   ctf_integer(uint64_t, from, from)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_redirect,
		 TP_ARGS(uint64_t, pid,
			 const uint64_t *, rd,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, pid, pid)
			   ctf_sequence(uint64_t, rd, rd, uint64_t,
					POSTBOX_RDR_LEN(rd))))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_pid,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_ppid,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_bid,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_sender,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_addressee,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_size,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_reference,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_type,
		 TP_ARGS(const struct msgh *, msgh,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_type_set,
		 TP_ARGS(const struct msgh *, msgh,
			 uint64_t, type,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, type, type)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_pbi,
		 TP_ARGS(uint64_t, pid,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint64_t, pid, pid)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_delay,
		 TP_ARGS(uint32_t, msec,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint32_t, msec, msec)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_open_fd,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_close_fd,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_atmo_set,
		 TP_ARGS(uint32_t, msec,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint32_t, msec, msec)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_tmo,
		 TP_ARGS(const struct msgh *, msgh,
			 long, msec,
			 long, interval_msec,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(long, msec, msec)
			   ctf_integer(long, interval_msec, interval_msec)
			   MSG_HEADER_FIELDS(msgh)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_snoop,
		 TP_ARGS(uint8_t, event,
			 const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)
			   ctf_integer(uint8_t, event, event)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_hook_recv,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_hook_send,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

TRACEPOINT_EVENT(MSG_TRACE_PROVIDER,
		 msg_wait,
		 TP_ARGS(const struct msg_trace *, trace),
		 TP_FIELDS(MSG_TRACE_FIELDS(trace)))

#endif /* MSG_TP_H */

#define TRACEPOINT_INCLUDE "msg_tp.h"

#include <lttng/tracepoint-event.h>
