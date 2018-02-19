lib_LTLIBRARIES = \
	libmsg.la

libmsg_la_SOURCES = \
	msg.c \
	msgh.c \
	msg_sig.c \
	msg_heap.c \
	msg_time.c \
	msg_lock.c \
	msg_trace.c \
	msg_error.c \
	msg_thread.c \
	msg_postbox.c \
	msg_post_office.c \
	msg_post_office_cmd.c \
	msg_post_office_tmo.c \
	msg_post_office_hunt.c \
	msg_post_office_alias.c \
	msg_post_office_attach.c \
	msg_util.c \
	msg_tprint.c

libmsg_la_CPPFLAGS = \
	-I$(top_srcdir)/include

libmsg_la_CFLAGS = \
	-Wall \
	-Wextra \
	-Wpedantic \
	-pthread \
	-O2

libmsg_la_LIBADD = \
	$(MSG_LTTNG_LIBS) \
	-lrt

libmsg_la_LDFLAGS = \
	-version-info 1:0:0 -Wl,--version-script=$(srcdir)/libmsg.vs
