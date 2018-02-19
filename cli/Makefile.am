bin_PROGRAMS = \
	msg

msg_SOURCES = \
	msg_cmd.c \
	msg_cmd_disp.c

msg_CPPFLAGS = \
	-I$(top_srcdir)/include

msg_CFLAGS = \
	-pthread \
	-Wall \
	-Wextra \
	-Wpedantic \
	-O2

msg_LDFLAGS = \
	-L$(top_srcdir)/src

msg_LDADD = \
	-lmsg
