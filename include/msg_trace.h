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

#ifndef MSG_TRACE_H
#define MSG_TRACE_H

#include <stdint.h>

struct msg_trace {
        const char *post_office_name;
        const char *postbox_name;
        const char *file;
        int line;
        uint64_t ppid;
        uint64_t pid;
        uint64_t bid;
};

#ifdef MSG_LTTNG_ENABLED
#define MSG_TRACE_PROVIDER msg_trace

#include "msg.h"
#include "msgh.h"
#include "msg_postbox.h"
#include "msg_tp.h"

#define msg_trace(name, ...) \
        tracepoint(MSG_TRACE_PROVIDER, name, __VA_ARGS__)

#else

/* Take care of parameters used for logging only */
extern void msg_trace_empty(const char *name, ...);
#define msg_trace(name, ...) \
        msg_trace_empty(NULL, __VA_ARGS__)
#endif

#endif
